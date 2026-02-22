"""Alert notification mechanisms."""

from __future__ import annotations

import json
import logging
import smtplib
import urllib.request
from email.mime.text import MIMEText
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import AlertsConfig
    from .health_monitor import HealthAlert

logger = logging.getLogger(__name__)


class AlertNotificationDispatcher:
    """Dispatches health alerts to various notification channels."""

    def __init__(self, config: AlertsConfig):
        self.config = config

    def notify(self, alert: HealthAlert) -> None:
        """Send alert notifications via enabled channels."""
        status = "RESOLVED" if getattr(alert, "resolved", False) else "ACTIVE"

        if self.config.email.enabled:
            self._send_email(alert, status)

        if self.config.webhook.enabled:
            self._send_webhook(alert, status)

    def _send_email(self, alert: HealthAlert, status: str) -> None:
        """Send alert notification via email."""
        try:
            body = (
                f"Health Alert Status: {status}\n"
                f"Type: {alert.alert_type}\n"
                f"Severity: {alert.severity}\n"
                f"Message: {alert.message}\n"
                f"Timestamp: {alert.timestamp}\n"
            )

            if getattr(alert, "resolved", False) and alert.resolved_at:
                body += f"Resolved At: {alert.resolved_at}\n"

            msg = MIMEText(body)
            msg["Subject"] = f"Argus-V Health Alert [{status}]: {alert.alert_type}"
            msg["From"] = self.config.email.from_address
            msg["To"] = ", ".join(self.config.email.to_addresses)

            logger.debug(f"Connecting to SMTP server {self.config.email.smtp_server}:{self.config.email.smtp_port}")
            with smtplib.SMTP(self.config.email.smtp_server, self.config.email.smtp_port, timeout=10) as server:
                if self.config.email.smtp_user and self.config.email.smtp_password:
                    server.login(self.config.email.smtp_user, self.config.email.smtp_password)
                server.send_message(msg)

            logger.info(f"Alert email sent successfully to {len(self.config.email.to_addresses)} recipients")
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")

    def _send_webhook(self, alert: HealthAlert, status: str) -> None:
        """Send alert notification via webhook."""
        try:
            data = {
                "status": status,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "message": alert.message,
                "timestamp": alert.timestamp,
                "resolved": getattr(alert, "resolved", False),
            }
            if getattr(alert, "resolved", False):
                data["resolved_at"] = getattr(alert, "resolved_at", None)

            payload = json.dumps(data).encode("utf-8")

            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Argus-V-Retina",
            }
            headers.update(self.config.webhook.headers)

            req = urllib.request.Request(
                self.config.webhook.url,
                data=payload,
                headers=headers,
                method=self.config.webhook.method,
            )

            logger.debug(f"Sending alert webhook to {self.config.webhook.url}")
            with urllib.request.urlopen(req, timeout=10) as response:
                if 200 <= response.status < 300:
                    logger.info("Alert webhook sent successfully")
                else:
                    logger.warning(f"Alert webhook returned status: {response.status}")
        except Exception as e:
            logger.error(f"Failed to send alert webhook: {e}")
