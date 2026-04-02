# alerts/dispatcher.py

import smtplib
import requests
import threading
import time
from collections import deque
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from .config import ALERT_CONFIG


class AlertDispatcher:
    """
    Multi-channel alert dispatcher.
    Call  dispatcher.dispatch(anomaly_result, raw_metrics)  whenever
    the anomaly engine fires.  Each channel runs in its own daemon
    thread so it never blocks the main loop.
    """

    SEVERITY_RANK  = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    SEVERITY_EMOJI = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🚨"}
    SEVERITY_COLOR = {
        "low": "#f59e0b", "medium": "#f97316",
        "high": "#ef4444", "critical": "#7c3aed",
    }

    def __init__(self):
        self.cfg = ALERT_CONFIG
        self._last_sent: dict  = {}          # channel → epoch
        self._rate_window: deque = deque(maxlen=200)

    # ──────────────────────────────────────────────────────────────
    # Public
    # ──────────────────────────────────────────────────────────────

    def dispatch(self, anomaly_result: dict, raw_metrics: dict):
        """Entry point called by the anomaly engine alert callback."""
        severity = anomaly_result.get("label", "low")

        # Hard hourly rate cap
        now = time.time()
        self._rate_window.append(now)
        hour_count = sum(1 for t in self._rate_window if now - t < 3600)
        if hour_count > self.cfg.get("max_alerts_per_hour", 12):
            print(f"[Alerts] Hourly cap reached — suppressing alert")
            return

        payload = self._build_payload(anomaly_result, raw_metrics)

        channels = [
            ("email",    self._send_email),
            ("telegram", self._send_telegram),
            ("ntfy",     self._send_ntfy),
        ]

        for name, handler in channels:
            ch = self.cfg.get(name, {})
            if not ch.get("enabled"):
                continue

            min_sev = ch.get("min_severity", "high")
            if self.SEVERITY_RANK.get(severity, 0) < self.SEVERITY_RANK.get(min_sev, 3):
                continue

            cooldown = self.cfg.get("cooldown_seconds", 300)
            if now - self._last_sent.get(name, 0) < cooldown:
                print(f"[Alerts] {name} on cooldown")
                continue

            self._last_sent[name] = now
            threading.Thread(
                target=self._safe_send, args=(name, handler, payload), daemon=True
            ).start()

    # ──────────────────────────────────────────────────────────────
    # Channel handlers
    # ──────────────────────────────────────────────────────────────

    def _send_email(self, payload: dict):
        cfg = self.cfg["email"]
        if not cfg["sender_email"] or not cfg["sender_password"]:
            print("[Email] Credentials not set in .env — skipping")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = payload["email_subject"]
        msg["From"]    = cfg["sender_email"]
        msg["To"]      = ", ".join(cfg["recipients"])
        msg.attach(MIMEText(payload["email_html"], "html"))

        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.login(cfg["sender_email"], cfg["sender_password"])
            s.sendmail(cfg["sender_email"], cfg["recipients"], msg.as_string())
        print(f"[Email] Alert sent to {cfg['recipients']}")

    def _send_telegram(self, payload: dict):
        cfg = self.cfg["telegram"]
        if not cfg["bot_token"] or not cfg["chat_id"]:
            print("[Telegram] Credentials not set in .env — skipping")
            return

        url = f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage"
        r = requests.post(url, json={
            "chat_id":    cfg["chat_id"],
            "text":       payload["telegram_text"],
            "parse_mode": "HTML",
        }, timeout=10)
        print(f"[Telegram] {'OK' if r.status_code == 200 else r.text}")

    def _send_ntfy(self, payload: dict):
        cfg      = self.cfg["ntfy"]
        sev      = payload["severity"]
        prio_map = {"low": "low", "medium": "default", "high": "high", "critical": "urgent"}
        r = requests.post(
            f"https://ntfy.sh/{cfg['topic']}",
            data=payload["short_summary"].encode(),
            headers={
                "Title":    payload["ntfy_title"],
                "Priority": prio_map.get(sev, "default"),
                "Tags":     f"warning,{sev}",
            }, timeout=10,
        )
        print(f"[ntfy] {'OK' if r.status_code == 200 else r.text}")

    # ──────────────────────────────────────────────────────────────
    # Payload builder
    # ──────────────────────────────────────────────────────────────

    def _build_payload(self, result: dict, metrics: dict) -> dict:
        sev       = result.get("label", "unknown")
        score     = result.get("score", 0)
        emoji     = self.SEVERITY_EMOJI.get(sev, "⚠️")
        color     = self.SEVERITY_COLOR.get(sev, "#ef4444")
        ts        = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        SEV_UPPER = sev.upper()

        exps       = result.get("explanations", [])
        top_reason = exps[0]["description"] if exps else "Unusual traffic pattern detected"
        actions    = result.get("suggested_actions", [])
        action_txt = actions[0] if actions else "Review the traffic dashboard"

        bw_in  = metrics.get("bandwidth_in",  metrics.get("bandwidth", 0))
        bw_out = metrics.get("bandwidth_out", 0)
        loss   = metrics.get("packet_loss", 0)
        flows  = metrics.get("active_flows", 0)

        short = f"{emoji} {SEV_UPPER} anomaly (Score {score}/100) — {top_reason}"

        return {
            "severity":      sev,
            "short_summary": short,

            "email_subject": f"[{SEV_UPPER}] NetFalcon Network Anomaly — Score {score}/100",
            "email_html":    self._email_html(
                SEV_UPPER, score, emoji, color, ts,
                top_reason, exps, action_txt,
                bw_in, bw_out, loss, flows,
            ),

            "telegram_text": (
                f"{emoji} <b>NetFalcon Network Anomaly</b>\n\n"
                f"<b>Severity:</b> {SEV_UPPER}\n"
                f"<b>Score:</b> {score}/100\n"
                f"<b>Time:</b> {ts}\n\n"
                f"<b>Reason:</b> {top_reason}\n\n"
                f"<b>Action:</b> {action_txt}\n\n"
                f"<b>Metrics:</b>\n"
                f"  BW In: {bw_in:.1f} KB/s | BW Out: {bw_out:.1f} KB/s\n"
                f"  Packet Loss: {loss:.1f}% | Active Flows: {flows}"
            ),

            "ntfy_title": f"NetFalcon {SEV_UPPER} Alert - Score {score}/100",
        }

    # ──────────────────────────────────────────────────────────────
    # HTML email template
    # ──────────────────────────────────────────────────────────────

    def _email_html(self, sev, score, emoji, color, ts,
                    top_reason, exps, action,
                    bw_in, bw_out, loss, flows) -> str:

        exp_rows = "".join(
            f"<tr>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #2a3040'>{e['description']}</td>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #2a3040;color:{color};font-weight:700'>"
            f"+{e['percent_diff']}%</td>"
            f"</tr>"
            for e in exps[:5]
        ) or f"<tr><td colspan='2' style='padding:8px;opacity:0.6'>No specific factors identified</td></tr>"

        return f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background:#0b0e14;color:#e2e8f0">
<div style="max-width:620px;margin:30px auto;border-radius:12px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,0.5)">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,{color},#0b0e14 80%);padding:28px 28px 20px">
    <div style="display:flex;align-items:center;gap:14px">
      <span style="font-size:2.5rem">{emoji}</span>
      <div>
        <h1 style="margin:0;font-size:1.35rem;color:#fff">NetFalcon Network Anomaly Alert</h1>
        <p  style="margin:4px 0 0;font-size:0.85rem;color:rgba(255,255,255,0.65)">{ts}</p>
      </div>
    </div>
  </div>

  <!-- Score badge -->
  <div style="background:#141922;padding:18px 28px;display:flex;gap:24px;border-bottom:1px solid #1e2535">
    <div style="text-align:center">
      <div style="font-size:2rem;font-weight:800;color:{color}">{score}</div>
      <div style="font-size:0.7rem;opacity:0.55;letter-spacing:1px">ANOMALY SCORE /100</div>
    </div>
    <div style="text-align:center">
      <div style="font-size:1.6rem;font-weight:800;color:{color}">{sev}</div>
      <div style="font-size:0.7rem;opacity:0.55;letter-spacing:1px">SEVERITY</div>
    </div>
  </div>

  <!-- Body -->
  <div style="background:#141922;padding:24px 28px">

    <!-- Primary reason -->
    <div style="border-left:4px solid {color};background:rgba(255,255,255,0.04);
                padding:14px 16px;border-radius:0 8px 8px 0;margin-bottom:22px">
      <div style="font-size:0.7rem;opacity:0.5;letter-spacing:1px;margin-bottom:6px">PRIMARY REASON</div>
      <div style="font-size:0.95rem">{top_reason}</div>
    </div>

    <!-- Factors table -->
    <h3 style="font-size:0.8rem;letter-spacing:1px;opacity:0.55;margin-bottom:10px">CONTRIBUTING FACTORS</h3>
    <table width="100%" style="border-collapse:collapse;background:#0f1520;border-radius:8px;overflow:hidden;margin-bottom:22px">
      <thead>
        <tr style="background:#1a2133">
          <th style="padding:10px;text-align:left;font-size:0.8rem;opacity:0.7">Factor</th>
          <th style="padding:10px;text-align:left;font-size:0.8rem;opacity:0.7">Deviation</th>
        </tr>
      </thead>
      <tbody>{exp_rows}</tbody>
    </table>

    <!-- Metrics snapshot -->
    <h3 style="font-size:0.8rem;letter-spacing:1px;opacity:0.55;margin-bottom:10px">LIVE METRICS SNAPSHOT</h3>
    <table width="100%" style="border-collapse:collapse;margin-bottom:22px">
      <tr>
        <td style="padding:6px 0;opacity:0.65">BW Inbound</td>
        <td style="font-weight:700">{bw_in:.1f} KB/s</td>
        <td style="padding:6px 0;opacity:0.65">BW Outbound</td>
        <td style="font-weight:700">{bw_out:.1f} KB/s</td>
      </tr>
      <tr>
        <td style="padding:6px 0;opacity:0.65">Packet Loss</td>
        <td style="font-weight:700">{loss:.1f}%</td>
        <td style="padding:6px 0;opacity:0.65">Active Flows</td>
        <td style="font-weight:700">{flows}</td>
      </tr>
    </table>

    <!-- Recommended action -->
    <div style="border-left:4px solid #10b981;background:rgba(16,185,129,0.08);
                padding:14px 16px;border-radius:0 8px 8px 0">
      <div style="font-size:0.7rem;opacity:0.55;letter-spacing:1px;margin-bottom:6px">RECOMMENDED ACTION</div>
      <div style="font-size:0.9rem">{action}</div>
    </div>

  </div>

  <!-- Footer -->
  <div style="background:#0b0e14;padding:14px 28px;text-align:center;font-size:0.75rem;opacity:0.4">
    NetFalcon Network Traffic Analyzer — Automated Security Alert
  </div>
</div>
</body>
</html>"""

    # ──────────────────────────────────────────────────────────────
    # Safe wrapper
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_send(name, handler, payload):
        try:
            handler(payload)
        except Exception as e:
            print(f"[Alerts] {name} failed: {e}")
