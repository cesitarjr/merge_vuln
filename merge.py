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
print(f"Buscando TSV en: {tsv_file}")
print(f"Buscando Excel en: {xlsx_file}")
print(f"Archivos realmente presentes en 'inputs': {os.listdir(INPUT_DIR)}")

# Verificar existencia de archivos antes de cargar
if not os.path.isfile(tsv_file):
    print(f"[ERROR] No se encontró el archivo TSV: {tsv_file}")
    raise FileNotFoundError(f"No se encontró el archivo TSV: {tsv_file}")
if not os.path.isfile(xlsx_file):
    print(f"[ERROR] No se encontró el archivo Excel: {xlsx_file}")
    raise FileNotFoundError(f"No se encontró el archivo Excel: {xlsx_file}")

# Cargar el TSV
df_tsv = pd.read_csv(tsv_file, sep='\t')

# Cargar el Excel
df_xlsx = pd.read_excel(xlsx_file)

# Asegurar que las columnas necesarias existen y tienen el mismo nombre
# Ajustar los nombres de las columnas para que coincidan con los de los ficheros
required_columns = ["HostValue", "Activo Afectado", "Vulnerabilidad", "Severidad"]

# Mostrar columnas de ambos archivos para depuración
print(f"Columnas en el TSV: {list(df_tsv.columns)}")
print(f"Columnas en el Excel: {list(df_xlsx.columns)}")

for col in required_columns:
    if col not in df_tsv.columns or col not in df_xlsx.columns:
        raise ValueError(f"Falta la columna '{col}' en uno de los ficheros")

# Buscar coincidencias
coincidencias = pd.merge(df_tsv, df_xlsx, on=required_columns, how='inner')

# Mostrar resultados
if not coincidencias.empty:
    print("Se encontraron las siguientes coincidencias:")
    print(coincidencias)
else:
    print("No se encontraron coincidencias entre los ficheros.")
