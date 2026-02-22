"""Retina configuration components."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from ..oracle_core.anonymize import AnonymizationConfig
from ..oracle_core.validation import (
    ValidationError,
    ValidationIssue,
    as_bool,
    as_mapping,
    get_optional,
    require_non_empty_str,
    require_positive_int,
)


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    """Packet capture configuration."""
    
    interface: str = "eth0"
    snaplen: int = 65535
    promiscuous: bool = True
    timeout_ms: int = 100
    buffer_size_mb: int = 10
    use_scapy: bool = True
    
    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "CaptureConfig":
        interface = require_non_empty_str(
            get_optional(data, "interface", default="eth0"),
            path=f"{path}.interface",
        )
        snaplen = require_positive_int(
            get_optional(data, "snaplen", default=65535),
            path=f"{path}.snaplen",
        )
        promiscuous = as_bool(
            get_optional(data, "promiscuous", default=True),
            path=f"{path}.promiscuous",
        )
        timeout_ms = require_positive_int(
            get_optional(data, "timeout_ms", default=100),
            path=f"{path}.timeout_ms",
        )
        buffer_size_mb = require_positive_int(
            get_optional(data, "buffer_size_mb", default=10),
            path=f"{path}.buffer_size_mb",
        )
        use_scapy = as_bool(
            get_optional(data, "use_scapy", default=True),
            path=f"{path}.use_scapy",
        )
        
        return CaptureConfig(
            interface=interface,
            snaplen=snaplen,
            promiscuous=promiscuous,
            timeout_ms=timeout_ms,
            buffer_size_mb=buffer_size_mb,
            use_scapy=use_scapy,
        )


@dataclass(frozen=True, slots=True)
class AggregationConfig:
    """Packet aggregation configuration."""
    
    window_seconds: int = 5
    output_dir: Path = field(default_factory=lambda: Path("/var/lib/argus-v/retina"))
    max_rows_per_file: int = 10000
    file_rotation_count: int = 10
    
    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "AggregationConfig":
        window_seconds = require_positive_int(
            get_optional(data, "window_seconds", default=5),
            path=f"{path}.window_seconds",
        )
        
        output_dir_raw = get_optional(data, "output_dir", default="/var/lib/argus-v/retina")
        output_dir = Path(require_non_empty_str(output_dir_raw, path=f"{path}.output_dir"))
        
        max_rows_per_file = require_positive_int(
            get_optional(data, "max_rows_per_file", default=10000),
            path=f"{path}.max_rows_per_file",
        )
        
        file_rotation_count = require_positive_int(
            get_optional(data, "file_rotation_count", default=10),
            path=f"{path}.file_rotation_count",
        )
        
        return AggregationConfig(
            window_seconds=window_seconds,
            output_dir=output_dir,
            max_rows_per_file=max_rows_per_file,
            file_rotation_count=file_rotation_count,
        )


@dataclass(frozen=True, slots=True)
class HealthConfig:
    """Health monitoring configuration."""
    
    max_drop_rate_percent: float = 1.0
    max_flow_queue_size: int = 1000
    alert_cooldown_seconds: int = 300
    enable_drop_monitoring: bool = True
    enable_queue_monitoring: bool = True
    
    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "HealthConfig":
        max_drop_rate_percent = get_optional(data, "max_drop_rate_percent", default=1.0)
        if not isinstance(max_drop_rate_percent, (int, float)):
            raise ValidationError([ValidationIssue(f"{path}.max_drop_rate_percent", "must be a number")])
        
        max_flow_queue_size = require_positive_int(
            get_optional(data, "max_flow_queue_size", default=1000),
            path=f"{path}.max_flow_queue_size",
        )
        
        alert_cooldown_seconds = require_positive_int(
            get_optional(data, "alert_cooldown_seconds", default=300),
            path=f"{path}.alert_cooldown_seconds",
        )
        
        enable_drop_monitoring = as_bool(
            get_optional(data, "enable_drop_monitoring", default=True),
            path=f"{path}.enable_drop_monitoring",
        )
        
        enable_queue_monitoring = as_bool(
            get_optional(data, "enable_queue_monitoring", default=True),
            path=f"{path}.enable_queue_monitoring",
        )
        
        return HealthConfig(
            max_drop_rate_percent=max_drop_rate_percent,
            max_flow_queue_size=max_flow_queue_size,
            alert_cooldown_seconds=alert_cooldown_seconds,
            enable_drop_monitoring=enable_drop_monitoring,
            enable_queue_monitoring=enable_queue_monitoring,
        )


@dataclass(frozen=True, slots=True)
class FirebaseConfig:
    """Firebase configuration."""

    enabled: bool = False
    bucket_name: str = "argus-v-logs"
    credentials_path: Optional[str] = None
    upload_prefix: str = "retina_logs/"

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "FirebaseConfig":
        enabled = as_bool(
            get_optional(data, "enabled", default=False),
            path=f"{path}.enabled",
        )

        bucket_name = require_non_empty_str(
            get_optional(data, "bucket_name", default="argus-v-logs"),
            path=f"{path}.bucket_name",
        )

        credentials_path = get_optional(data, "credentials_path", default=None)
        if credentials_path is not None:
            credentials_path = require_non_empty_str(credentials_path, path=f"{path}.credentials_path")

        upload_prefix = require_non_empty_str(
            get_optional(data, "upload_prefix", default="retina_logs/"),
            path=f"{path}.upload_prefix",
        )

        return FirebaseConfig(
            enabled=enabled,
            bucket_name=bucket_name,
            credentials_path=credentials_path,
            upload_prefix=upload_prefix,
        )


@dataclass(frozen=True, slots=True)
class EmailConfig:
    """Email alert configuration."""

    enabled: bool = False
    smtp_server: str = "localhost"
    smtp_port: int = 25
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    from_address: str = "argus-v@example.com"
    to_addresses: list[str] = field(default_factory=list)

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str, env: Mapping[str, str]) -> "EmailConfig":
        enabled = as_bool(get_optional(data, "enabled", default=False), path=f"{path}.enabled")
        smtp_server = require_non_empty_str(get_optional(data, "smtp_server", default="localhost"), path=f"{path}.smtp_server")
        smtp_port = require_positive_int(get_optional(data, "smtp_port", default=25), path=f"{path}.smtp_port")

        smtp_user = get_optional(data, "smtp_user", default=None)
        if smtp_user is not None:
            smtp_user = require_non_empty_str(smtp_user, path=f"{path}.smtp_user")

        smtp_password_raw = get_optional(data, "smtp_password", default=None)
        smtp_password = None
        if smtp_password_raw is not None:
            if isinstance(smtp_password_raw, str) and smtp_password_raw.startswith("${") and smtp_password_raw.endswith("}"):
                var_name = smtp_password_raw[2:-1]
                smtp_password = env.get(var_name, smtp_password_raw)
            else:
                smtp_password = str(smtp_password_raw)

        from_address = require_non_empty_str(get_optional(data, "from_address", default="argus-v@example.com"), path=f"{path}.from_address")

        to_addresses_raw = get_optional(data, "to_addresses", default=[])
        if not isinstance(to_addresses_raw, list):
            raise ValidationError([ValidationIssue(f"{path}.to_addresses", "must be a list")])
        to_addresses = [require_non_empty_str(addr, path=f"{path}.to_addresses[{i}]") for i, addr in enumerate(to_addresses_raw)]

        return EmailConfig(
            enabled=enabled,
            smtp_server=smtp_server,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            from_address=from_address,
            to_addresses=to_addresses,
        )


@dataclass(frozen=True, slots=True)
class WebhookConfig:
    """Webhook alert configuration."""

    enabled: bool = False
    url: str = ""
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "WebhookConfig":
        enabled = as_bool(get_optional(data, "enabled", default=False), path=f"{path}.enabled")
        url = get_optional(data, "url", default="")
        if enabled and not url:
            raise ValidationError([ValidationIssue(f"{path}.url", "must be provided if webhook is enabled")])

        method = require_non_empty_str(get_optional(data, "method", default="POST"), path=f"{path}.method")
        headers = as_mapping(get_optional(data, "headers", default={}), path=f"{path}.headers")

        return WebhookConfig(
            enabled=enabled,
            url=url,
            method=method,
            headers={str(k): str(v) for k, v in headers.items()},
        )


@dataclass(frozen=True, slots=True)
class AlertsConfig:
    """Alert mechanisms configuration."""

    email: EmailConfig = field(default_factory=EmailConfig)
    webhook: WebhookConfig = field(default_factory=WebhookConfig)

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str, env: Mapping[str, str]) -> "AlertsConfig":
        email_data = as_mapping(get_optional(data, "email", default={}), path=f"{path}.email")
        email = EmailConfig.from_mapping(email_data, path=f"{path}.email", env=env)

        webhook_data = as_mapping(get_optional(data, "webhook", default={}), path=f"{path}.webhook")
        webhook = WebhookConfig.from_mapping(webhook_data, path=f"{path}.webhook")

        return AlertsConfig(email=email, webhook=webhook)


@dataclass(frozen=True, slots=True)
class RetinaConfig:
    """Complete retina configuration."""
    
    capture: CaptureConfig
    aggregation: AggregationConfig
    health: HealthConfig
    anonymization: AnonymizationConfig
    firebase: FirebaseConfig = field(default_factory=FirebaseConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    enabled: bool = True
    
    def ensure_output_dirs(self) -> None:
        """Create output directories if they don't exist."""
        self.aggregation.output_dir.mkdir(parents=True, exist_ok=True)
    
    @staticmethod
    def from_mapping(
        data: Mapping[str, Any], 
        *, 
        path: str,
        env: Mapping[str, str],
    ) -> "RetinaConfig":
        # Check if retina is enabled
        retina_data = as_mapping(get_optional(data, "retina", default={}), path="$.retina")
        enabled = as_bool(get_optional(retina_data, "enabled", default=True), path="$.retina.enabled")
        
        # Load capture config
        capture_data = as_mapping(get_optional(retina_data, "capture", default={}), path="$.retina.capture")
        capture = CaptureConfig.from_mapping(capture_data, path="$.retina.capture")
        
        # Load aggregation config
        aggregation_data = as_mapping(get_optional(retina_data, "aggregation", default={}), path="$.retina.aggregation")
        aggregation = AggregationConfig.from_mapping(aggregation_data, path="$.retina.aggregation")
        
        # Load health config
        health_data = as_mapping(get_optional(retina_data, "health", default={}), path="$.retina.health")
        health = HealthConfig.from_mapping(health_data, path="$.retina.health")
        
        # Load firebase config
        firebase_data = as_mapping(get_optional(retina_data, "firebase", default={}), path="$.retina.firebase")
        firebase = FirebaseConfig.from_mapping(firebase_data, path="$.retina.firebase")

        # Load alerts config
        alerts_data = as_mapping(get_optional(retina_data, "alerts", default={}), path="$.retina.alerts")
        alerts = AlertsConfig.from_mapping(alerts_data, path="$.retina.alerts", env=env)

        # Load anonymization config
        anon_salt_raw = get_optional(retina_data, "ip_salt", default="default_salt_change_in_production")
        if isinstance(anon_salt_raw, str):
            if anon_salt_raw.startswith("${") and anon_salt_raw.endswith("}"):
                var_name = anon_salt_raw[2:-1]
                anon_salt = env.get(var_name, anon_salt_raw)
            else:
                anon_salt = anon_salt_raw
        else:
            anon_salt = str(anon_salt_raw)
        
        anonymization = AnonymizationConfig(ip_salt=anon_salt.encode('utf-8'))
        
        return RetinaConfig(
            capture=capture,
            aggregation=aggregation,
            health=health,
            anonymization=anonymization,
            firebase=firebase,
            alerts=alerts,
            enabled=enabled,
        )
