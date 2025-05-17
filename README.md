# WAF Reactivo

Automatización reactiva de bloqueos WAF usando Glastopf + ModSecurity.  
Este proyecto sincroniza los eventos de ataque del honeypot Glastopf con reglas dinámicas de ModSecurity en un servidor Apache, para proteger tu aplicación (por ejemplo OWASP Juice Shop) de manera automática.

---

## 📖 Descripción

Cada vez que Glastopf detecta un intento de ataque (SQLi, LFI, RFI, XSS, etc.), este script:

1. **Copia** la base de datos SQLite de Glastopf desde la VM del honeypot (`scp`).
2. **Extrae** las nuevas entradas de la tabla `events`.
3. **Genera** reglas ModSecurity (`modsec_generated.conf`) para bloquear IPs y patrones detectados.
4. **Recarga** Apache si la configuración es válida.
5. **Registra** en un log cada ejecución.
6. (Opcional) Envía notificaciones por Telegram.

---

## 🏗 Arquitectura

Atacante
↓ HTTP/Attack
→ Honeypot Glastopf (VM1) → sqlite DB
└─ copia periódica ──> VM2 (WAF)
├─ update_hardening.py ──> modsec_generated.conf
└─ Apache + ModSecurity ──> Juice Shop (backend HTTP)

---

## ⚙️ Requisitos

- **VM1 (honeypot)** con Glastopf y su `glastopf.db`.
- **VM2 (WAF)** con:
  - Python 3
  - `sqlite3` CLI
  - OpenSSH (para `scp`)
  - Apache 2 + ModSecurity p/ Apache
  - Docker (opcional, si proteges un contenedor)
- Cuenta de Telegram Bot (si usas notificaciones).





