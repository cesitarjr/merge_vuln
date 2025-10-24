Dependencias
pip install requests beautifulsoup4 pandas openpyxl rapidfuzz feedparser

Ejecución
Solo consola (sin emails) y registrar en CSV:
    python vuln_watcher.py --dry-run --log-file alerts.csv
Enviar correos y además registrar en CSV:
    python vuln_watcher.py --send --log-file alerts.csv

Programación
Linux
    0 */6 * * * /usr/bin/python3 /ruta/vuln_watcher.py >> /var/log/vuln_watcher.log 2>&1

Windows
Tarea que ejecute python C:\ruta\vuln_watcher.py cada X horas.
