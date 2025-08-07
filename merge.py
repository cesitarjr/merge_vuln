"""Herramienta para cruzar vulnerabilidades entre dos ficheros.

El script recibe dos rutas de archivo.  Cada fichero debe contener las
columnas:

    - ``Activo Afectado``
    - ``Severidad``
    - ``Vulnerabilidad``
    - ``Descripción``

Se comparan línea a línea y se consideran coincidencias únicamente cuando
los valores de las cuatro columnas son iguales.  Para la columna
``Severidad`` se aplica un mapa de equivalencias para aceptar variantes como
``high`` -> ``Alta``.

Si se encuentran coincidencias se muestran los valores de las columnas para
cada fichero.  En caso contrario se imprime ``No se han encontrado
coincidencias``.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Callable

import pandas as pd


INPUT_DIR = Path("input")
OUTPUT_DIR = Path("output")
INPUT_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)


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
    """

    required = ["Activo Afectado", "Severidad", "Vulnerabilidad", "Descripción"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Faltan columnas requeridas: {missing}")

    out = df.copy()
    for col in required:
        out[f"{col}_norm"] = out[col].astype(str).str.strip().str.lower()

    out["Severidad_norm"] = (
        out["Severidad_norm"].map(SEVERITY_MAP).fillna(out["Severidad_norm"])
    )
    return out


# ---------------------------------------------------------------------------
# Lógica principal
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Busca vulnerabilidades del segundo fichero en el primero"
    )
    parser.add_argument(
        "file1",
        nargs="?",
        default=INPUT_DIR / "reporte_A.tsv",
        help="Primer fichero de referencia",
    )
    parser.add_argument(
        "file2",
        nargs="?",
        default=INPUT_DIR / "reporte_B.tsv",
        help="Segundo fichero a comparar",
    )
    args = parser.parse_args()

    df1 = _load_file(args.file1)
    df2 = _load_file(args.file2)

    n1 = _normalise(df1)
    n2 = _normalise(df2)

    on_cols = [
        "Activo Afectado_norm",
        "Severidad_norm",
        "Vulnerabilidad_norm",
        "Descripción_norm",
    ]

    matches = pd.merge(n1, n2, on=on_cols, how="inner", suffixes=("_f1", "_f2"))

    if matches.empty:
        print("No se han encontrado coincidencias")
        return

    cols = [
        "Activo Afectado_f1",
        "Severidad_f1",
        "Vulnerabilidad_f1",
        "Descripción_f1",
        "Activo Afectado_f2",
        "Severidad_f2",
        "Vulnerabilidad_f2",
        "Descripción_f2",
    ]
    print(matches[cols])


if __name__ == "__main__":
    main()

