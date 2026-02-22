from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

# Mock missing dependencies before importing argus_v
sys.modules["firebase_admin"] = MagicMock()
sys.modules["firebase_admin.credentials"] = MagicMock()
sys.modules["firebase_admin.storage"] = MagicMock()
sys.modules["pandas"] = MagicMock()
sys.modules["numpy"] = MagicMock()
sys.modules["scapy"] = MagicMock()
sys.modules["scapy.all"] = MagicMock()
sys.modules["psutil"] = MagicMock()
sys.modules["sklearn"] = MagicMock()
sys.modules["sklearn.ensemble"] = MagicMock()
sys.modules["joblib"] = MagicMock()
sys.modules["skops"] = MagicMock()
sys.modules["torch"] = MagicMock()

import pytest

from argus_v.retina.config import AlertsConfig, EmailConfig, WebhookConfig
from argus_v.retina.health_monitor import HealthAlert, HealthMetrics
from argus_v.retina.notifications import AlertNotificationDispatcher


@pytest.fixture
def mock_alert():
    metrics = HealthMetrics(
        timestamp=1234567890.0,
        interface_available=True,
        packets_captured=1000,
        packets_processed=900,
        packets_dropped=100,
        flows_in_queue=10,
        current_window_packets=50,
        drop_rate_percent=10.0,
        capture_rate_pps=100.0,
        processing_rate_pps=90.0,
        memory_usage_mb=100.0,
        cpu_usage_percent=10.0,
        disk_usage_percent=5.0,
    )
    return HealthAlert(
        alert_type="high_drop_rate",
        severity="warning",
        message="Drop rate is high",
        timestamp=1234567890.0,
        metrics=metrics,
    )


def test_dispatcher_email_enabled(mock_alert):
    config = AlertsConfig(
        email=EmailConfig(
            enabled=True,
            smtp_server="smtp.example.com",
            smtp_port=587,
            from_address="sender@example.com",
            to_addresses=["receiver@example.com"],
        ),
        webhook=WebhookConfig(enabled=False),
    )

    dispatcher = AlertNotificationDispatcher(config)

    with patch("smtplib.SMTP") as mock_smtp:
        dispatcher.notify(mock_alert)

        mock_smtp.assert_called_once_with("smtp.example.com", 587, timeout=10)
        instance = mock_smtp.return_value.__enter__.return_value
        instance.send_message.assert_called_once()

        # Check message content
        args, _ = instance.send_message.call_args
        msg = args[0]
        assert msg["Subject"] == "Argus-V Health Alert [ACTIVE]: high_drop_rate"
        assert msg["From"] == "sender@example.com"
        assert msg["To"] == "receiver@example.com"
        assert "Drop rate is high" in msg.get_payload()


def test_dispatcher_webhook_enabled(mock_alert):
    config = AlertsConfig(
        email=EmailConfig(enabled=False),
        webhook=WebhookConfig(
            enabled=True,
            url="http://webhook.example.com",
            method="POST",
            headers={"X-Custom-Header": "value"},
        ),
    )

    dispatcher = AlertNotificationDispatcher(config)

    with patch("urllib.request.urlopen") as mock_urlopen, \
         patch("urllib.request.Request") as mock_request:

        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        dispatcher.notify(mock_alert)

        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        assert args[0] == "http://webhook.example.com"
        assert kwargs["method"] == "POST"
        assert kwargs["headers"]["X-Custom-Header"] == "value"
        assert kwargs["headers"]["Content-Type"] == "application/json"

        payload = json.loads(kwargs["data"].decode("utf-8"))
        assert payload["alert_type"] == "high_drop_rate"
        assert payload["status"] == "ACTIVE"


def test_dispatcher_resolved_alert(mock_alert):
    mock_alert.resolved = True
    mock_alert.resolved_at = 1234567895.0

    config = AlertsConfig(
        email=EmailConfig(
            enabled=True,
            to_addresses=["receiver@example.com"],
        ),
        webhook=WebhookConfig(enabled=True, url="http://webhook.example.com"),
    )

    dispatcher = AlertNotificationDispatcher(config)

    with patch("smtplib.SMTP") as mock_smtp, \
         patch("urllib.request.urlopen") as mock_urlopen:

        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        dispatcher.notify(mock_alert)

        # Check email subject
        instance = mock_smtp.return_value.__enter__.return_value
        args, _ = instance.send_message.call_args
        msg = args[0]
        assert "[RESOLVED]" in msg["Subject"]


def test_config_parsing():
    from argus_v.retina.config import RetinaConfig

    data = {
        "retina": {
            "alerts": {
                "email": {
                    "enabled": True,
                    "smtp_server": "myserver",
                    "to_addresses": ["a@b.com", "c@d.com"]
                },
                "webhook": {
                    "enabled": True,
                    "url": "http://example.com"
                }
            }
        }
    }

    config = RetinaConfig.from_mapping(data, path="$", env={})

    assert config.alerts.email.enabled is True
    assert config.alerts.email.smtp_server == "myserver"
    assert config.alerts.email.to_addresses == ["a@b.com", "c@d.com"]
    assert config.alerts.webhook.enabled is True
    assert config.alerts.webhook.url == "http://example.com"

def test_config_parsing_env_vars():
    from argus_v.retina.config import RetinaConfig

    data = {
        "retina": {
            "alerts": {
                "email": {
                    "enabled": True,
                    "smtp_password": "${SMTP_PASS}"
                }
            }
        }
    }

    config = RetinaConfig.from_mapping(data, path="$", env={"SMTP_PASS": "secret123"})
    assert config.alerts.email.smtp_password == "secret123"
