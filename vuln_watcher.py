#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_watcher.py (modo dry-run y logging CSV)
- --dry-run (por defecto): no envía correos; imprime alertas en consola
- --send: envía correos
- --log-file alerts.csv: además registra cada alerta en un CSV
Entradas:
  - productos.xlsx  (Nombre | Editor | Versiones - Nombre)
  - fuentes.txt     (TSV: NombreFuente<TAB>URL)
Dependencias:
  pip install requests beautifulsoup4 pandas openpyxl rapidfuzz feedparser
"""

import argparse
import csv
import datetime as dt
import requests, sqlite3, hashlib, json, sys, re, unicodedata
from pathlib import Path
from bs4 import BeautifulSoup
import pandas as pd
from email.message import EmailMessage
import smtplib
from rapidfuzz import fuzz
import feedparser
from urllib.parse import urlparse

# ---------------- CONFIG ----------------
DEFAULT_CONFIG = {
    "smtp": {
        "host": "smtp.example.com",
        "port": 587,
        "use_tls": True,
        "username": "alertas@example.com",
        "password": "TU_PASSWORD_APP",
        "from": "alertas@example.com",
        "to": ["tu.email@dominio.com"]
    },
    "threshold_fuzzy": 82,
    "user_agent": "VulnWatcher/1.5 (+https://tuempresa.local)",
    "timeout": 25,
    "min_fuzzy_len": 5,
    "filters": {
        "min_severity": "MEDIUM",
        "require_cve": True
    }
}
CONFIG_PATH = Path("config.json")

def load_config():
    if CONFIG_PATH.exists():
        cfg_disk = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        cfg = {**DEFAULT_CONFIG, **cfg_disk}
        if "filters" in cfg_disk:
            cfg["filters"] = {**DEFAULT_CONFIG["filters"], **cfg_disk["filters"]}
        return cfg
    else:
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        print("Se ha creado config.json. Rellena SMTP y vuelve a ejecutar.")
        sys.exit(1)

cfg = load_config()
DB_PATH = "vuln_watcher.db"

# ---------------- DB ----------------
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY,
        key TEXT UNIQUE,
        product TEXT,
        editor TEXT,
        version TEXT,
        url TEXT,
        source_name TEXT,
        entry_id TEXT,
        title TEXT,
        severity TEXT,
        cvss TEXT,
        cve TEXT,
        found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    con.commit()
    return con

# ---------------- ENTRADAS ----------------
VERS_SPLIT_RE = re.compile(r"(?:<br\s*/?>)|[\n\r;,|]+", re.IGNORECASE)

def parse_versions(cell_value):
    if pd.isna(cell_value): return []
    s = str(cell_value).strip()
    if not s or s.lower() == "nan": return []
    parts = [p.strip() for p in VERS_SPLIT_RE.split(s)]
    seen, result = set(), []
    for p in parts:
        if p and p not in seen:
            seen.add(p); result.append(p)
    return result

def load_products(xlsx_path="productos.xlsx"):
    p = Path(xlsx_path)
    if not p.exists(): raise FileNotFoundError(f"{xlsx_path} no existe.")
    df = pd.read_excel(p)
    if df.empty: raise ValueError("productos.xlsx está vacío.")
    cols = {str(c).strip().lower(): c for c in df.columns}
    nombre_col  = cols.get("nombre")
    editor_col  = cols.get("editor")
    versiones_col = cols.get("versiones - nombre") or next((cols[k] for k in cols if "versiones" in k), None)
    if not nombre_col:
        raise ValueError("Se requiere columna 'Nombre' en productos.xlsx.")
    if not versiones_col:
        df["__Versiones__"] = ""
        versiones_col = "__Versiones__"
    records = []
    for _, r in df.iterrows():
        product = str(r[nombre_col]).strip() if not pd.isna(r[nombre_col]) else ""
        if not product: continue
        editor = ""
        if editor_col and not pd.isna(r[editor_col]): editor = str(r[editor_col]).strip()
        versions = parse_versions(r[versiones_col])
        records.append({"product": product, "editor": editor, "versions": versions})
    if not records:
        raise ValueError("No se han encontrado productos válidos en productos.xlsx.")
    return records

def load_sources(tsv_path="fuentes.txt"):
    p = Path(tsv_path)
    if not p.exists(): raise FileNotFoundError(f"{tsv_path} no existe.")
    sources = []
    with p.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        for idx, row in enumerate(reader, start=1):
            if not row or len(row) < 2: continue
            name, url = row[0].strip(), row[1].strip()
            if not url.startswith(("http://","https://")):
                print(f"[AVISO] Línea {idx}: URL no válida -> '{url}'"); continue
            sources.append((name or "Fuente sin nombre", url))
    if not sources:
        raise ValueError("fuentes.txt no contiene líneas válidas 'Nombre<TAB>URL'.")
    return sources

# ---------------- FETCH ----------------
RSS_EXT = (".xml", ".rss", ".atom", ".rdf")

def is_rss_like(url, headers=None):
    path = urlparse(url).path.lower()
    if path.endswith(RSS_EXT): return True
    if headers:
        ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        if any(t in ctype for t in ["rss","atom","xml"]): return True
    return False

def fetch_html_text(url):
    headers = {"User-Agent": cfg["user_agent"]}
    try:
        r = requests.get(url, headers=headers, timeout=cfg["timeout"])
        r.raise_for_status()
    except Exception as e:
        print(f"[ERROR] fetch HTML {url} -> {e}"); return ""
    soup = BeautifulSoup(r.text, "html.parser")
    for tag in soup(["script","style","noscript"]): tag.decompose()
    return soup.get_text(separator=" ", strip=True)

def fetch_feed(url):
    fp = feedparser.parse(url)
    if fp.bozo and not fp.entries: return [], True
    entries = []
    for e in fp.entries:
        eid = getattr(e, "id", "") or getattr(e, "guid", "") or getattr(e, "link", "")
        link = getattr(e, "link", "")
        title = getattr(e, "title", "") or ""
        summary = getattr(e, "summary", "") or getattr(e, "description", "") or ""
        content_text = ""
        if hasattr(e, "content") and e.content:
            try:
                content_text = " ".join([BeautifulSoup(c.value, "html.parser").get_text(" ", strip=True) for c in e.content if hasattr(c, "value")])
            except Exception: pass
        tags_text = ""
        if hasattr(e, "tags") and e.tags:
            tags_text = " ".join([getattr(t, "term", "") for t in e.tags if hasattr(t, "term")])
        entries.append({
            "id": eid, "link": link, "title": title,
            "summary": BeautifulSoup(summary, "html.parser").get_text(" ", strip=True),
            "content_text": content_text, "tags_text": tags_text
        })
    return entries, True

# ---------------- MATCH ----------------
def make_key(product, version, url, entry_id=""):
    return hashlib.sha256(f"{product}||{version or ''}||{url}||{entry_id}".encode("utf-8")).hexdigest()

def _match_one(product, version, text: str):
    t = text.lower(); pn = product.lower().strip()
    if not pn: return False, ""
    idx = t.find(pn)
    if idx != -1:
        if not version or version.strip() in ("","*"):
            return True, text[max(0, idx-120): idx+len(pn)+120]
        ver = version.strip().lower()
        if ver in t:
            j = t.find(ver)
            return True, text[max(0, j-120): j+len(ver)+120]
    else:
        if len(pn) >= cfg["min_fuzzy_len"] and fuzz.partial_ratio(pn, t[:4000]) >= cfg["threshold_fuzzy"]:
            return True, text[:600]
    return False, ""

def match_product_any_version(product, versions, text):
    if versions:
        for v in versions:
            ok, snip = _match_one(product, v, text)
            if ok: return True, snip, v
        ok, snip = _match_one(product, "", text)
        return (ok, snip, "") if ok else (False, "", "")
    else:
        ok, snip = _match_one(product, "", text)
        return (ok, snip, "") if ok else (False, "", "")

# ---------------- INDICADORES ----------------
CVE_REGEX   = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CVSS_REGEX  = re.compile(r"cvss[^0-9]{0,15}(\d{1,2}\.\d)\b", re.IGNORECASE)
SEV_TOKEN_RE = re.compile(r"\b(critical|critica|critico|high|alta|alto|medium|media|moderada|low|baja|bajo)\b", re.IGNORECASE)
SEV_MAP = {
    "critical": "CRITICAL","critica": "CRITICAL","critico": "CRITICAL",
    "high": "HIGH","alta": "HIGH","alto": "HIGH",
    "medium": "MEDIUM","media": "MEDIUM","moderada": "MEDIUM",
    "low": "LOW","baja": "LOW","bajo": "LOW"
}
SEV_RANK = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}

def infer_severity_from_cvss(score: float):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"

def extract_indicators(*texts):
    combo = " ".join([t for t in texts if t])
    cves = list(dict.fromkeys(CVE_REGEX.findall(combo)))
    cve_str = ", ".join(cves) if cves else ""
    sev = ""
    m = SEV_TOKEN_RE.search(combo)
    if m: sev = SEV_MAP.get(m.group(1).lower(), "")
    cvss_str = ""
    m2 = CVSS_REGEX.search(combo)
    if m2:
        cvss_str = m2.group(1)
        if not sev:
            try: sev = infer_severity_from_cvss(float(cvss_str))
            except: pass
    return cve_str, sev, cvss_str

def pass_filters(cves, sev):
    if cfg["filters"].get("require_cve", False) and not cves:
        return False
    min_sev = cfg["filters"].get("min_severity","MEDIUM").upper()
    if not sev: return False
    return SEV_RANK.get(sev, -1) >= SEV_RANK.get(min_sev, 1)

# ---------------- EMAIL ----------------
def send_email(subject, body_html):
    mailcfg = cfg["smtp"]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mailcfg["from"]
    msg["To"] = ", ".join(mailcfg["to"]) if isinstance(mailcfg["to"], list) else mailcfg["to"]
    msg.set_content(BeautifulSoup(body_html, "html.parser").get_text())
    msg.add_alternative(body_html, subtype="html")
    try:
        if mailcfg.get("use_tls", True):
            s = smtplib.SMTP(mailcfg["host"], mailcfg["port"], timeout=35)
            s.starttls()
        else:
            s = smtplib.SMTP_SSL(mailcfg["host"], mailcfg["port"], timeout=35)
        s.login(mailcfg["username"], mailcfg["password"])
        s.send_message(msg); s.quit()
        print("[OK] Email enviado:", subject)
    except Exception as e:
        print("[ERROR] fallo envio email:", e)

# ---------------- CSV LOG ----------------
CSV_HEADER = [
    "timestamp","source_type","source_name","url","product","editor","version",
    "severity","cvss","cve","title","entry_id","snippet"
]

def append_csv(log_path: Path, row: dict):
    # Crear cabecera si no existe
    new_file = not log_path.exists()
    with log_path.open("a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADER)
        if new_file:
            w.writeheader()
        # normaliza claves faltantes
        safe = {k: row.get(k, "") for k in CSV_HEADER}
        w.writerow(safe)

# ---------------- MAIN ----------------
def main(dry_run=True, log_file: str = None):
    products = load_products("productos.xlsx")
    sources  = load_sources("fuentes.txt")
    con = init_db(); cur = con.cursor()
    log_path = Path(log_file) if log_file else None

    print(f"Cargados {len(products)} productos y {len(sources)} fuentes.")
    for source_name, url in sources:
        print(f"Comprobando: {source_name} -> {url}")
        headers = {}
        try:
            head = requests.head(url, timeout=10, allow_redirects=True)
            headers = head.headers or {}
        except: pass
        is_feed = is_rss_like(url, headers)
        if is_feed:
            entries,_ = fetch_feed(url)
            for e in entries:
                body = " ".join([e["title"], e["summary"], e["content_text"], e["tags_text"]])
                entry_cve, entry_sev, entry_cvss = extract_indicators(body)
                for item in products:
                    ok, snippet, v = match_product_any_version(item["product"], item["versions"], body)
                    if not ok: continue
                    if not pass_filters(entry_cve, entry_sev): continue
                    entry_id = e["id"] or e["link"] or ""
                    link = e["link"] or url
                    key = make_key(item["product"], v or (item["versions"][0] if item["versions"] else ""), url, entry_id)
                    cur.execute("SELECT 1 FROM alerts WHERE key=?",(key,))
                    if cur.fetchone():
                        print(f"Ya alertado (RSS): {item['product']} ({v}) @ {source_name} :: {entry_id}")
                        continue
                    cur.execute("INSERT INTO alerts (key,product,editor,version,url,source_name,entry_id,title,severity,cvss,cve) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                (key,item["product"],item["editor"],v,link,source_name,entry_id,e["title"],entry_sev,entry_cvss,entry_cve))
                    con.commit()
                    # Salida / Email
                    subject=f"[ALERTA VULN][{entry_sev}] {item['product']} {v or ''}"
                    html=f"<p><b>{item['product']}</b> ({v or 'sin versión'}) detectado en <b>{source_name}</b><br><a href='{link}'>{link}</a><br><b>CVE:</b> {entry_cve}<br><b>Severidad:</b> {entry_sev}<br><b>CVSS:</b> {entry_cvss}</p><pre>{snippet}</pre>"
                    if dry_run:
                        print("\n[ALERTA DETECTADA - DRY RUN]")
                        print("Producto:", item["product"])
                        print("Editor:", item["editor"] or "—")
                        print("Versión:", v or "no especificada")
                        print("Fuente:", source_name, "(RSS)")
                        print("URL:", link)
                        print("CVE:", entry_cve or "—")
                        print("Severidad:", entry_sev or "—")
                        print("CVSS:", entry_cvss or "—")
                        print("Extracto:", (snippet or "")[:800].replace("\n"," ") + "...\n")
                    else:
                        send_email(subject, html)
                    # CSV
                    if log_path:
                        append_csv(log_path, {
                            "timestamp": dt.datetime.utcnow().isoformat(timespec="seconds")+"Z",
                            "source_type": "RSS",
                            "source_name": source_name,
                            "url": link,
                            "product": item["product"],
                            "editor": item["editor"],
                            "version": v or "",
                            "severity": entry_sev,
                            "cvss": entry_cvss,
                            "cve": entry_cve,
                            "title": e["title"],
                            "entry_id": entry_id,
                            "snippet": (snippet or "").replace("\n"," ")[:1000]
                        })
        else:
            text = fetch_html_text(url)
            page_cve, page_sev, page_cvss = extract_indicators(text)
            for item in products:
                ok, snippet, v = match_product_any_version(item["product"], item["versions"], text)
                if not ok: continue
                if not pass_filters(page_cve, page_sev): continue
                key = make_key(item["product"], v or (item["versions"][0] if item["versions"] else ""), url)
                cur.execute("SELECT 1 FROM alerts WHERE key=?",(key,))
                if cur.fetchone():
                    print(f"Ya alertado (HTML): {item['product']} ({v}) @ {url}")
                    continue
                cur.execute("INSERT INTO alerts (key,product,editor,version,url,source_name,title,severity,cvss,cve) VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (key,item["product"],item["editor"],v,url,source_name,"",page_sev,page_cvss,page_cve))
                con.commit()
                # Salida / Email
                subject=f"[ALERTA VULN][{page_sev}] {item['product']} {v or ''}"
                html=f"<p><b>{item['product']}</b> ({v or 'sin versión'}) detectado en <b>{source_name}</b><br><a href='{url}'>{url}</a><br><b>CVE:</b> {page_cve}<br><b>Severidad:</b> {page_sev}<br><b>CVSS:</b> {page_cvss}</p><pre>{snippet}</pre>"
                if dry_run:
                    print("\n[ALERTA DETECTADA - DRY RUN]")
                    print("Producto:", item["product"])
                    print("Editor:", item["editor"] or "—")
                    print("Versión:", v or "no especificada")
                    print("Fuente:", source_name, "(HTML)")
                    print("URL:", url)
                    print("CVE:", page_cve or "—")
                    print("Severidad:", page_sev or "—")
                    print("CVSS:", page_cvss or "—")
                    print("Extracto:", (snippet or "")[:800].replace("\n"," ") + "...\n")
                else:
                    send_email(subject, html)
                # CSV
                if log_path:
                    append_csv(log_path, {
                        "timestamp": dt.datetime.utcnow().isoformat(timespec="seconds")+"Z",
                        "source_type": "HTML",
                        "source_name": source_name,
                        "url": url,
                        "product": item["product"],
                        "editor": item["editor"],
                        "version": v or "",
                        "severity": page_sev,
                        "cvss": page_cvss,
                        "cve": page_cve,
                        "title": "",
                        "entry_id": "",
                        "snippet": (snippet or "").replace("\n"," ")[:1000]
                    })
    con.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnWatcher - monitor RSS/HTML for product/version mentions.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", help="No enviar correos; imprimir alertas (por defecto).")
    group.add_argument("--send", action="store_true", help="Enviar correos.")
    parser.add_argument("--log-file", type=str, help="Ruta a CSV para registrar alertas (ej: alerts.csv).")
    args = parser.parse_args()
    dry = not args.send if (args.dry_run or args.send) else True  # por defecto dry-run
    main(dry_run=dry, log_file=args.log_file)