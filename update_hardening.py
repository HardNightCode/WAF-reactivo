#!/usr/bin/env python3
import subprocess
from datetime import datetime, timedelta, timezone
import re
import sys
import os
import urllib.request
import urllib.parse

# ————— Configuración —————
SSH_KEY            = os.path.expanduser("~/.ssh/id_honeypot")
REMOTE_DB          = "ubuntu@192.168.20.10:/opt/honeypot/db/glastopf.db"
LOCAL_DB           = "/etc/hardening/db/glastopf.db"
MODSEC_RULES_FILE  = "/etc/hardening/modsec_generated.conf"
LOG_FILE           = "/etc/hardening/log/hardening.log"
TIME_WINDOW_MIN    = 6
# Telegram
TELEGRAM_TOKEN     = os.environ.get("TELEGRAM_TOKEN", "7970977614:AAGmGR2nnARAZBYAMJnMVrfhFEeTGkevXKI")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "812751076")

# 0) Copiar la BD remota antes de abrirla
try:
    subprocess.run([
        "scp", "-i", SSH_KEY, "-o", "StrictHostKeyChecking=no",
        REMOTE_DB, LOCAL_DB
    ], check=True)
except subprocess.CalledProcessError as e:
    print(f"ERROR al hacer scp de la BD: {e}", file=sys.stderr)
    sys.exit(1)

# 1) Construir la cláusula time > ?
cutoff = (datetime.now(timezone.utc) - timedelta(minutes=TIME_WINDOW_MIN)) \
         .strftime("%Y-%m-%d %H:%M:%S")

# 2) Leer eventos con sqlite3 CLI
query = f"SELECT source, request_url, pattern FROM events WHERE time > '{cutoff}';"
proc = subprocess.run(
    ["sqlite3", "-separator", "|", LOCAL_DB, query],
    capture_output=True, text=True
)
if proc.returncode != 0:
    print("ERROR al ejecutar sqlite3:", proc.stderr.strip(), file=sys.stderr)
    sys.exit(1)

events = []
for line in proc.stdout.splitlines():
    parts = line.split("|", 2)
    if len(parts) == 3:
        events.append((parts[0], parts[1], parts[2]))

if not events:
    print(f"No hay eventos nuevos en últimos {TIME_WINDOW_MIN} min.")
    sys.exit(0)
    
# 3) Extraer IPs y patrones únicos y asociar IP → solo si el patrón es realmente malicioso
unique_ips      = set()
unique_patterns = set()
GENERIC         = {'lfi', 'rfi', 'sqli', 'xss', 'unknown'}

# Expresión que detecta un payload “de verdad”
MALICIOUS_MARKS = re.compile(
    r'(%[0-9A-Fa-f]{2}|'        # codificación URL
    r'\.\./|'                   # path traversal
    r'<|>|'                     # etiquetas HTML
    r'\.php|\.asp|'             # extensiones de script
    r'\b(select|union|drop|insert|alert|etc)\b)'  # keywords SQL/JS
)

for src_ip, req_url, patt in events:
    # raw: preferimos patt si no es genérico, sino la URL
    raw = patt if patt and patt not in GENERIC else req_url
    raw = raw.strip()[:100].replace('"', '\\"')

    # filtro trivial: descartamos cadenas demasiado cortas o rutas comunes
    alpha = re.sub(r'[^A-Za-z0-9]', '', raw)
    if not raw or raw in {"/", ".", "./", "/favicon.ico"} or len(alpha) < 3:
        continue

    # **solo** si coincide con algo malicioso
    if not MALICIOUS_MARKS.search(raw):
        continue

    # si llegamos hasta aquí, es un payload malo: 
    unique_patterns.add(raw)

    # y entonces sí queremos banear la IP
    ip_only = src_ip.split(":", 1)[0]
    if ip_only and ip_only != "127.0.0.1":
        unique_ips.add(ip_only)


# 4) Generar reglas ModSecurity
rules   = []
rule_id = 100000

# 4.1) Bloqueo por IP
for ip in sorted(unique_ips):
    rule_id += 1
    rules.append(
        f'SecRule REMOTE_ADDR "@ipMatch {ip}" '
        f'"id:{rule_id},phase:1,deny,log,msg:\'Reactivo IP {ip}\'"'
    )

# 4.2) Bloqueo por patrón (@contains sobre substring limpio)
for pat in sorted(unique_patterns):
    rule_id += 1
    rules.append(
        f'SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY '
        f'"@contains {pat}" '
        f'"id:{rule_id},phase:2,deny,log,msg:\'Reactivo payload detectado\'"'
    )

# 5) Escribir el fichero de reglas limpio
header = f"# Generado automáticamente: {datetime.now().isoformat()}\n"
with open(MODSEC_RULES_FILE, "w") as mf:
    mf.write(header)
    for r in rules:
        mf.write(r + "\n")

# 6) Recargar Apache sólo si la config es válida
cfg = subprocess.run(["apachectl", "configtest"], capture_output=True, text=True)
if cfg.returncode == 0:
    subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
else:
    err = cfg.stderr.strip() or cfg.stdout.strip()
    print("ERROR en configuración de Apache, no se recarga:\n", err, file=sys.stderr)
    with open(LOG_FILE, "a") as lf:
        lf.write(f"{datetime.now()}: ERROR recargando Apache: {err}\n")

# 7) Logging de lo procesado
with open(LOG_FILE, "a") as lf:
    lf.write(f"{datetime.now()}: {len(events)} eventos, "
             f"{len(unique_ips)} IPs, {len(unique_patterns)} patrones\n")
  
# 8) Notificación Telegram (si hay algo nuevo)
if (unique_ips or unique_patterns) and TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
    partes = []
    if unique_ips:
        partes.append(f"🔴 IPs bloqueadas: {', '.join(sorted(unique_ips))}")
    if unique_patterns:
        partes.append(f"🛑 Patrones bloqueados: {', '.join(sorted(unique_patterns))}")
    message = "🔔 *Hardening Reactivo activo*\n" + "\n".join(partes)
    # Preparamos URL
    params = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage?" + urllib.parse.urlencode(params)
    try:
        urllib.request.urlopen(url, timeout=10)
    except Exception as e:
        # Si falla Telegram, lo anotamos al log local
        with open(LOG_FILE, "a") as lf:
            lf.write(f"{datetime.now()}: ERROR Telegram: {e}\n")
