"""Herramienta para cruzar vulnerabilidades entre dos ficheros.

El script recibe dos rutas de archivo.  Cada fichero debe contener las
columnas:

    - ``Activo Afectado``
    - ``Severidad``
    - ``Vulnerabilidad``
    - ``Descripción`` (opcional)

Se comparan línea a línea y se consideran coincidencias únicamente cuando
los valores de las tres primeras columnas son iguales.  La columna
``Descripción`` se muestra solo como referencia.  Para la columna
``Severidad`` se aplica un mapa de equivalencias para aceptar variantes como
``high`` -> ``Alta``.

Si se encuentran coincidencias se muestran los valores de las columnas para
cada fichero.  En caso contrario se imprime ``No se han encontrado
coincidencias``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd


INPUT_DIR = Path("inputs")
OUTPUT_DIR = Path("output")
INPUT_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

FILE1 = INPUT_DIR / "AAVV unificado.xlsx"
FILE2 = INPUT_DIR / "report_AAVV_Unificado.tsv"


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": "Crítica",
    "critica": "Crítica",
    "crítica": "Crítica",
    "alta": "Alta",
    "high": "Alta",
    "media": "Media",
    "medium": "Media",
    "baja": "Baja",
    "low": "Baja",
    "info": "Informativa",
    "informativa": "Informativa",
}


COLUMN_ALIASES = {
    "Descripcion": "Descripción",
    "Description": "Descripción",
}


def _load_file(path: str | Path) -> pd.DataFrame:
    """Carga un fichero TSV o Excel en un ``DataFrame``.

    Parameters
    ----------
    path:
        Ruta del fichero a cargar.  El formato se determina por la extensión.
    """

    ext = os.path.splitext(str(path))[1].lower()
    if ext in {".tsv", ".csv", ".txt"}:
        try:
            return pd.read_csv(path, sep="\t", encoding="utf-8")
        except UnicodeDecodeError:
            return pd.read_csv(path, sep="\t", encoding="latin-1")
    if ext in {".xlsx", ".xls"}:
        return pd.read_excel(path)
    raise ValueError(f"Formato de fichero no soportado: {path}")


def _normalise(df: pd.DataFrame) -> pd.DataFrame:
    """Devuelve una copia del ``DataFrame`` con columnas normalizadas.

    Se crean columnas auxiliares con el sufijo ``_norm`` para utilizar en el
    cruce.  Las cadenas se convierten a minúsculas y se eliminan espacios. La
    columna ``Severidad`` se traduce a su valor canonical en español.

    Se aceptan alias de columnas definidos en ``COLUMN_ALIASES``; por ejemplo,
    ``Description`` o ``Descripcion`` se consideran equivalentes a
    ``Descripción`` si está presente.
    """

    df = df.rename(columns=COLUMN_ALIASES)

    required = ["Activo Afectado", "Severidad", "Vulnerabilidad"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Faltan columnas requeridas: {missing}")

    out = df.copy()
    for col in required:
        out[f"{col}_norm"] = out[col].astype(str).str.strip().str.lower()

    if "Descripción" in df.columns:
        out["Descripción_norm"] = (
            out["Descripción"].astype(str).str.strip().str.lower()
        )

    out["Severidad_norm"] = (
        out["Severidad_norm"].map(SEVERITY_MAP).fillna(out["Severidad_norm"])
    )
    return out


# ---------------------------------------------------------------------------
# Lógica principal
# ---------------------------------------------------------------------------


def main() -> None:
    df1 = _load_file(FILE1)
    df2 = _load_file(FILE2)

    n1 = _normalise(df1)
    n2 = _normalise(df2)

    on_cols = [
        "Activo Afectado_norm",
        "Severidad_norm",
        "Vulnerabilidad_norm",
    ]

    matches = pd.merge(n1, n2, on=on_cols, how="inner", suffixes=("_f1", "_f2"))

    if matches.empty:
        print("No se han encontrado coincidencias")
        return

    rename_map = {
        "Activo Afectado_f1": "Activo Afectado",
        "Activo Afectado_f2": "Activo Afectado",
        "Descripción_f1": "Descripción",
        "Descripción_f2": "Descripción",
    }
    rename_map = {k: v for k, v in rename_map.items() if k in matches.columns}
    out = matches[list(rename_map)].rename(columns=rename_map)
    print(out)


if __name__ == "__main__":
    main()

