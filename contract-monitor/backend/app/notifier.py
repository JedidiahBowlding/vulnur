from __future__ import annotations

import requests

from .config import Settings
from .models import ScanResult


class Notifier:
    def __init__(self, settings: Settings):
        self.settings = settings

    def notify_scan(self, result: ScanResult) -> None:
        payload = result.to_dict()
        self._send_webhook(payload)
        self._send_telegram(payload)

    def _send_webhook(self, payload: dict) -> None:
        if not self.settings.alert_webhook_url:
            return
        try:
            requests.post(self.settings.alert_webhook_url, json=payload, timeout=10)
        except Exception:
            # Webhook failures should not crash the scanner loop.
            return

    def _send_telegram(self, payload: dict) -> None:
        token = self.settings.telegram_bot_token
        chat_id = self.settings.telegram_chat_id
        if not token or not chat_id:
            return

        vulns = payload.get("vulnerabilities", [])
        vuln_text = ", ".join(vulns) if vulns else "none"
        message = (
            "Smart Contract Scan Completed\n"
            f"Chain: {payload.get('chain', 'ethereum')}\n"
            f"Address: {payload.get('address')}\n"
            f"Block: {payload.get('block_number')}\n"
            f"Status: {payload.get('status')}\n"
            f"Vulnerabilities: {vuln_text}\n"
            f"Summary: {payload.get('summary')}"
        )

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            requests.post(
                url,
                json={"chat_id": chat_id, "text": message},
                timeout=10,
            )
        except Exception:
            return
