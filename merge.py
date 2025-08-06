import os
import re
import argparse
from collections import defaultdict
from bs4 import BeautifulSoup
import pandas as pd
from docx import Document
import datetime

# Obtener la ruta absoluta del directorio donde está este script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(SCRIPT_DIR, "inputs")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "outputs")
os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Definir rutas absolutas de los archivos de entrada
# Cambia los nombres si tus archivos tienen nombres diferentes
TSV_FILENAME = "report_AAVV_Unificado.tsv"
XLSX_FILENAME = "AAVV unificado.xlsx"
tsv_file = os.path.join(INPUT_DIR, TSV_FILENAME)
xlsx_file = os.path.join(INPUT_DIR, XLSX_FILENAME)

# Mensajes de depuración para saber qué busca y dónde
#print(f"Buscando TSV en: {tsv_file}")
#print(f"Buscando Excel en: {xlsx_file}")
#print(f"Archivos realmente presentes en 'inputs': {os.listdir(INPUT_DIR)}")

# Verificar existencia de archivos antes de cargar
if not os.path.isfile(tsv_file):
    print(f"[ERROR] No se encontró el archivo TSV: {tsv_file}")
    raise FileNotFoundError(f"No se encontró el archivo TSV: {tsv_file}")
if not os.path.isfile(xlsx_file):
    print(f"[ERROR] No se encontró el archivo Excel: {xlsx_file}")
    raise FileNotFoundError(f"No se encontró el archivo Excel: {xlsx_file}")

# Cargar el TSV intentando primero con UTF-8 y
# haciendo un fallback a latin-1 si aparecen errores
try:
    df_tsv = pd.read_csv(tsv_file, sep='\t', encoding="utf-8")
except UnicodeDecodeError:
    df_tsv = pd.read_csv(tsv_file, sep='\t', encoding="latin-1")

# Cargar el Excel
df_xlsx = pd.read_excel(xlsx_file)

# Asegurar que las columnas necesarias existen y tienen el mismo nombre
# Ajustar los nombres de las columnas para que coincidan con los de los ficheros
# Se incluyen columnas adicionales para garantizar un cruce más estricto
required_columns = [
    "HostValue",
    "Activo Afectado",
    "Vulnerabilidad",
    "Severidad",
    "Descripción",
    "Propuesta resolución",
    "Estado",
    "Plugin Output",
]

# Mostrar columnas de ambos archivos para depuración
#print(f"Columnas en el TSV: {list(df_tsv.columns)}")
#print(f"Columnas en el Excel: {list(df_xlsx.columns)}")

# Verificar que todas las columnas necesarias estén presentes en ambos DataFrames
missing_tsv = [col for col in required_columns if col not in df_tsv.columns]
missing_xlsx = [col for col in required_columns if col not in df_xlsx.columns]
if missing_tsv or missing_xlsx:
    raise ValueError(
        f"Faltan columnas en los DataFrames. TSV: {missing_tsv}, Excel: {missing_xlsx}"
    )

# Buscar coincidencias estrictas
coincidencias = pd.merge(df_tsv, df_xlsx, on=required_columns, how="inner")

# Opcional: detectar filas sin coincidencias exactas
outer_merge = pd.merge(
    df_tsv, df_xlsx, on=required_columns, how="outer", indicator=True
)
no_coinciden = outer_merge[outer_merge["_merge"] != "both"]

# Mostrar resultados
print("─" * 80)  # Línea continua separadora
if coincidencias.empty:
    print("No se han encontrado coincidencias")
else:
    print("Se han encontrado coincidencias:")
    columnas = [
        "Activo Afectado",
        "Vulnerabilidad",
        "Severidad",
        "Descripción",
        "Estado",
    ]
    print(coincidencias[columnas])
    if not no_coinciden.empty:
        print("Filas que no coinciden entre los ficheros:")
        print(no_coinciden)
print("─" * 80)  # Línea continua separadora
