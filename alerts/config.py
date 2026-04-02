# alerts/config.py
#
# ─────────────────────────────────────────────────────────────────────
#  HOW TO SET UP GMAIL SMTP (one-time, takes ~2 minutes)
# ─────────────────────────────────────────────────────────────────────
#  1. Go to  https://myaccount.google.com/security
#  2. Make sure "2-Step Verification" is ON.
#  3. Go to  https://myaccount.google.com/apppasswords
#  4. App: Mail  |  Device: Other  |  Name: "NetFalcon"
#  5. Copy the 16-character password shown (spaces don't matter).
#  6. Open the file  .env  (created next to app.py) and paste:
#
#       GMAIL_ADDRESS=netfalcon02@gmail.com
#       GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx     ← your 16-char password
#       ALERT_RECIPIENTS=you@example.com
#
#  That is all.  The app reads credentials from .env automatically.
#  Never put your real Gmail password here — only the 16-char App Password.
# ─────────────────────────────────────────────────────────────────────

import os
from dotenv import load_dotenv

# Load .env from the project root (one level up from this file)
_env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(dotenv_path=_env_path)

# Recipients can be a comma-separated list in .env, e.g.:
#   ALERT_RECIPIENTS=alice@example.com,bob@example.com
_recipients_raw = os.getenv("ALERT_RECIPIENTS", "")
_recipients = [r.strip() for r in _recipients_raw.split(",") if r.strip()]

ALERT_CONFIG = {
    # ── Email (Gmail SMTP) ──────────────────────────────────────────
    "email": {
        "enabled": bool(_recipients),          # auto-enabled when .env is set
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "sender_email":    os.getenv("GMAIL_ADDRESS", ""),
        "sender_password": os.getenv("GMAIL_APP_PASSWORD", ""),
        "recipients":      _recipients,
        "min_severity":    "medium to high",             # only email on medium to high / critical
    },


    # ── ntfy.sh push (free, no account needed) ────────────────────
    # Add to .env:  NTFY_TOPIC=my-netfalcon-alerts
    "ntfy": {
        "enabled": bool(os.getenv("NTFY_TOPIC")),
        "topic":   os.getenv("NTFY_TOPIC", "netfalcon-alerts"),
        "min_severity": "high",
    },

    # ── Rate limiting ──────────────────────────────────────────────
    "cooldown_seconds":    300,   # 5 min between same-channel alerts
    "max_alerts_per_hour": 12,    # hard cap — prevents spam storms
}
