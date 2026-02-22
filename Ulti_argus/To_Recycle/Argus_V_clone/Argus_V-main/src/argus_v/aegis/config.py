"""Configuration management for Aegis shield runtime service.

This module provides configuration parsing and validation for the Aegis runtime,
including Mnemosyne model settings, Retina polling, prediction thresholds,
blacklist management, and Firebase synchronization.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from ..oracle_core.config import (
    FirebaseConfig,
    GitHubConfig,
    ValidationError,
    ValidationIssue,
    as_bool,
    as_list,
    as_mapping,
    get_optional,
    require_non_empty_str,
    require_positive_int,
)


@dataclass(frozen=True, slots=True)
class ModelConfig:
    """Configuration for Mnemosyne model loading and management."""
    
    # Model paths and loading
    model_local_path: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_MODEL_LOCAL_PATH", "/var/lib/argus/models"))
    model_download_timeout: int = 300  # 5 minutes
    scaler_local_path: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_SCALER_LOCAL_PATH", "/var/lib/argus/scalers"))
    scaler_download_timeout: int = 60
    
    # Model validation
    min_model_age_hours: int = 1  # Don't use models younger than 1 hour
    max_model_age_days: int = 30  # Remove models older than 30 days
    
    # Fallback behavior
    use_fallback_model: bool = True
    fallback_prediction_threshold: float = 0.7
    
    # Foundation Model
    foundation_model_path: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_FOUNDATION_MODEL_PATH", "/var/lib/argus/foundation/model.pkl"))
    foundation_scaler_path: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_FOUNDATION_SCALER_PATH", "/var/lib/argus/foundation/scaler.pkl"))

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "ModelConfig":
        """Create ModelConfig from configuration mapping."""
        model_local_path = require_non_empty_str(
            get_optional(data, "model_local_path", os.environ.get(
                "ARGUS_MODEL_LOCAL_PATH", "/var/lib/argus/models")),
            path=f"{path}.model_local_path"
        )
        
        model_download_timeout = require_positive_int(
            get_optional(data, "model_download_timeout", 300),
            path=f"{path}.model_download_timeout"
        )
        
        scaler_local_path = require_non_empty_str(
            get_optional(data, "scaler_local_path", os.environ.get(
                "ARGUS_SCALER_LOCAL_PATH", "/var/lib/argus/scalers")),
            path=f"{path}.scaler_local_path"
        )
        
        scaler_download_timeout = require_positive_int(
            get_optional(data, "scaler_download_timeout", 60),
            path=f"{path}.scaler_download_timeout"
        )
        
        min_model_age_hours = require_positive_int(
            get_optional(data, "min_model_age_hours", 1),
            path=f"{path}.min_model_age_hours"
        )
        
        max_model_age_days = require_positive_int(
            get_optional(data, "max_model_age_days", 30),
            path=f"{path}.max_model_age_days"
        )
        
        use_fallback_model = as_bool(
            get_optional(data, "use_fallback_model", True),
            path=f"{path}.use_fallback_model"
        )
        
        fallback_prediction_threshold = float(
            get_optional(data, "fallback_prediction_threshold", 0.7)
        )
        if not (0.0 <= fallback_prediction_threshold <= 1.0):
            raise ValidationError([
                ValidationIssue(
                    f"{path}.fallback_prediction_threshold",
                    "must be between 0.0 and 1.0"
                )
            ])

        foundation_model_path = require_non_empty_str(
            get_optional(data, "foundation_model_path", os.environ.get(
                "ARGUS_FOUNDATION_MODEL_PATH", "/var/lib/argus/foundation/model.pkl")),
            path=f"{path}.foundation_model_path"
        )

        foundation_scaler_path = require_non_empty_str(
            get_optional(data, "foundation_scaler_path", os.environ.get(
                "ARGUS_FOUNDATION_SCALER_PATH", "/var/lib/argus/foundation/scaler.pkl")),
            path=f"{path}.foundation_scaler_path"
        )
        
        return ModelConfig(
            model_local_path=model_local_path,
            model_download_timeout=model_download_timeout,
            scaler_local_path=scaler_local_path,
            scaler_download_timeout=scaler_download_timeout,
            min_model_age_hours=min_model_age_hours,
            max_model_age_days=max_model_age_days,
            use_fallback_model=use_fallback_model,
            fallback_prediction_threshold=fallback_prediction_threshold,
            foundation_model_path=foundation_model_path,
            foundation_scaler_path=foundation_scaler_path
        )


@dataclass(frozen=True, slots=True)
class PollingConfig:
    """Configuration for Retina CSV polling."""
    
    poll_interval_seconds: int = 5
    csv_directory: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_CSV_DIRECTORY", "/var/lib/argus/retina/csv"))
    processed_file_suffix: str = ".processed"
    max_poll_errors: int = 5
    poll_retry_delay: int = 30
    batch_size: int = 100
    
    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "PollingConfig":
        """Create PollingConfig from configuration mapping."""
        poll_interval_seconds = require_positive_int(
            get_optional(data, "poll_interval_seconds", 5),
            path=f"{path}.poll_interval_seconds"
        )
        
        csv_directory = require_non_empty_str(
            get_optional(data, "csv_directory", os.environ.get(
                "ARGUS_CSV_DIRECTORY", "/var/lib/argus/retina/csv")),
            path=f"{path}.csv_directory"
        )
        
        processed_file_suffix = require_non_empty_str(
            get_optional(data, "processed_file_suffix", ".processed"),
            path=f"{path}.processed_file_suffix"
        )
        
        max_poll_errors = require_positive_int(
            get_optional(data, "max_poll_errors", 5),
            path=f"{path}.max_poll_errors"
        )
        
        poll_retry_delay = require_positive_int(
            get_optional(data, "poll_retry_delay", 30),
            path=f"{path}.poll_retry_delay"
        )
        
        batch_size = require_positive_int(
            get_optional(data, "batch_size", 100),
            path=f"{path}.batch_size"
        )
        
        return PollingConfig(
            poll_interval_seconds=poll_interval_seconds,
            csv_directory=csv_directory,
            processed_file_suffix=processed_file_suffix,
            max_poll_errors=max_poll_errors,
            poll_retry_delay=poll_retry_delay,
            batch_size=batch_size
        )


@dataclass(frozen=True, slots=True)
class PredictionConfig:
    """Configuration for prediction and scoring."""
    
    # Feature columns to extract from Retina flows
    feature_columns: list[str] = field(default_factory=lambda: [
        'bytes_in', 'bytes_out', 'packets_in', 'packets_out', 'duration',
        'src_port', 'dst_port', 'protocol'
    ])
    
    # Prediction thresholds
    anomaly_threshold: float = 0.7  # Threshold for flagging as anomaly
    high_risk_threshold: float = 0.9  # Threshold for immediate blocking
    
    # Processing limits
    max_flows_per_batch: int = 1000
    prediction_timeout: int = 30
    
    # Performance tuning
    use_gpu: bool = False
    enable_parallel_processing: bool = True
    max_workers: int = 4
    
    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "PredictionConfig":
        """Create PredictionConfig from configuration mapping."""
        feature_columns_raw = get_optional(data, "feature_columns", [
            'bytes_in', 'bytes_out', 'packets_in', 'packets_out', 'duration',
            'src_port', 'dst_port', 'protocol'
        ])
        
        feature_columns_list = as_list(feature_columns_raw, path=f"{path}.feature_columns")
        feature_columns = [
            require_non_empty_str(col, path=f"{path}.feature_columns[{i}]")
            for i, col in enumerate(feature_columns_list)
        ]
        
        anomaly_threshold = float(get_optional(data, "anomaly_threshold", 0.7))
        if not (0.0 <= anomaly_threshold <= 1.0):
            raise ValidationError([
                ValidationIssue(
                    f"{path}.anomaly_threshold",
                    "must be between 0.0 and 1.0"
                )
            ])
        
        high_risk_threshold = float(get_optional(data, "high_risk_threshold", 0.9))
        if not (0.0 <= high_risk_threshold <= 1.0):
            raise ValidationError([
                ValidationIssue(
                    f"{path}.high_risk_threshold",
                    "must be between 0.0 and 1.0"
                )
            ])
        
        if anomaly_threshold >= high_risk_threshold:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.high_risk_threshold",
                    "must be greater than anomaly_threshold"
                )
            ])
        
        max_flows_per_batch = require_positive_int(
            get_optional(data, "max_flows_per_batch", 1000),
            path=f"{path}.max_flows_per_batch"
        )
        
        prediction_timeout = require_positive_int(
            get_optional(data, "prediction_timeout", 30),
            path=f"{path}.prediction_timeout"
        )
        
        use_gpu = as_bool(
            get_optional(data, "use_gpu", False),
            path=f"{path}.use_gpu"
        )
        
        enable_parallel_processing = as_bool(
            get_optional(data, "enable_parallel_processing", True),
            path=f"{path}.enable_parallel_processing"
        )
        
        max_workers = require_positive_int(
            get_optional(data, "max_workers", 4),
            path=f"{path}.max_workers"
        )
        
        return PredictionConfig(
            feature_columns=feature_columns,
            anomaly_threshold=anomaly_threshold,
            high_risk_threshold=high_risk_threshold,
            max_flows_per_batch=max_flows_per_batch,
            prediction_timeout=prediction_timeout,
            use_gpu=use_gpu,
            enable_parallel_processing=enable_parallel_processing,
            max_workers=max_workers
        )


@dataclass(frozen=True, slots=True)
class EnforcementConfig:
    """Configuration for blacklist enforcement and iptables management."""
    
    # Dry run mode
    dry_run_duration_days: int = 7
    enforce_after_dry_run: bool = False
    
    # iptables management
    iptables_chain_name: str = "AEGIS-DROP"
    iptables_table: str = "filter"
    iptables_chain_position: int = 1
    
    # Blacklist management
    blacklist_default_ttl_hours: int = 24
    max_blacklist_entries: int = 10000
    blacklist_cleanup_interval: int = 3600  # 1 hour
    
    # Emergency controls
    emergency_stop_file: str = "/var/run/argus/aegis.emergency"
    allow_manual_overrides: bool = True
    
    # Storage paths
    blacklist_db_path: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_BLACKLIST_DB_PATH", "/var/lib/argus/aegis/blacklist.db"))
    blacklist_json_path: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_BLACKLIST_JSON_PATH", "/var/lib/argus/aegis/blacklist.json"))
    feedback_dir: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_FEEDBACK_DIR", "/var/lib/argus/aegis/feedback"))
    retrain_flag_file: str = field(default_factory=lambda: os.environ.get(
        "ARGUS_RETRAIN_FLAG_FILE", "/var/lib/argus/mnemosyne/trigger_retrain"))

    # Security
    anonymization_salt: str | None = None

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "EnforcementConfig":
        """Create EnforcementConfig from configuration mapping."""
        dry_run_duration_days = require_positive_int(
            get_optional(data, "dry_run_duration_days", 7),
            path=f"{path}.dry_run_duration_days"
        )
        
        enforce_after_dry_run = as_bool(
            get_optional(data, "enforce_after_dry_run", False),
            path=f"{path}.enforce_after_dry_run"
        )
        
        iptables_chain_name = require_non_empty_str(
            get_optional(data, "iptables_chain_name", "AEGIS-DROP"),
            path=f"{path}.iptables_chain_name"
        )
        
        iptables_table = require_non_empty_str(
            get_optional(data, "iptables_table", "filter"),
            path=f"{path}.iptables_table"
        )
        
        iptables_chain_position = require_positive_int(
            get_optional(data, "iptables_chain_position", 1),
            path=f"{path}.iptables_chain_position"
        )
        
        blacklist_default_ttl_hours = require_positive_int(
            get_optional(data, "blacklist_default_ttl_hours", 24),
            path=f"{path}.blacklist_default_ttl_hours"
        )
        
        max_blacklist_entries = require_positive_int(
            get_optional(data, "max_blacklist_entries", 10000),
            path=f"{path}.max_blacklist_entries"
        )
        
        blacklist_cleanup_interval = require_positive_int(
            get_optional(data, "blacklist_cleanup_interval", 3600),
            path=f"{path}.blacklist_cleanup_interval"
        )
        
        emergency_stop_file = require_non_empty_str(
            get_optional(data, "emergency_stop_file", os.environ.get(
                "ARGUS_EMERGENCY_STOP_FILE", "/var/run/argus/aegis.emergency")),
            path=f"{path}.emergency_stop_file"
        )
        
        allow_manual_overrides = as_bool(
            get_optional(data, "allow_manual_overrides", True),
            path=f"{path}.allow_manual_overrides"
        )
        
        blacklist_db_path = require_non_empty_str(
            get_optional(data, "blacklist_db_path", os.environ.get(
                "ARGUS_BLACKLIST_DB_PATH", "/var/lib/argus/aegis/blacklist.db")),
            path=f"{path}.blacklist_db_path"
        )

        blacklist_json_path = require_non_empty_str(
            get_optional(data, "blacklist_json_path", os.environ.get(
                "ARGUS_BLACKLIST_JSON_PATH", "/var/lib/argus/aegis/blacklist.json")),
            path=f"{path}.blacklist_json_path"
        )

        feedback_dir = require_non_empty_str(
            get_optional(data, "feedback_dir", os.environ.get(
                "ARGUS_FEEDBACK_DIR", "/var/lib/argus/aegis/feedback")),
            path=f"{path}.feedback_dir"
        )

        retrain_flag_file = require_non_empty_str(
            get_optional(data, "retrain_flag_file", os.environ.get(
                "ARGUS_RETRAIN_FLAG_FILE", "/var/lib/argus/mnemosyne/trigger_retrain")),
            path=f"{path}.retrain_flag_file"
        )

        # Load anonymization salt
        anonymization_salt = get_optional(data, "anonymization_salt", None)
        if not anonymization_salt:
            anonymization_salt = os.environ.get("ARGUS_ANONYMIZATION_SALT")

        if not anonymization_salt:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.anonymization_salt",
                    "must be provided in config or ARGUS_ANONYMIZATION_SALT environment variable"
                )
            ])

        return EnforcementConfig(
            dry_run_duration_days=dry_run_duration_days,
            enforce_after_dry_run=enforce_after_dry_run,
            iptables_chain_name=iptables_chain_name,
            iptables_table=iptables_table,
            iptables_chain_position=iptables_chain_position,
            blacklist_default_ttl_hours=blacklist_default_ttl_hours,
            max_blacklist_entries=max_blacklist_entries,
            blacklist_cleanup_interval=blacklist_cleanup_interval,
            emergency_stop_file=emergency_stop_file,
            allow_manual_overrides=allow_manual_overrides,
            blacklist_db_path=blacklist_db_path,
            blacklist_json_path=blacklist_json_path,
            feedback_dir=feedback_dir,
            retrain_flag_file=retrain_flag_file,
            anonymization_salt=anonymization_salt
        )


@dataclass(frozen=True, slots=True)
class AegisConfig:
    """Main configuration for Aegis shield runtime service."""
    
    # Core components
    model: ModelConfig
    polling: PollingConfig  
    prediction: PredictionConfig
    enforcement: EnforcementConfig
    
    # Security
    anonymization_salt: str

    # Optional integrations
    firebase: FirebaseConfig | None = None
    github: GitHubConfig | None = None
    
    # Runtime settings
    log_level: str = "INFO"
    state_file: str = "/var/lib/argus/aegis/state.json"
    pid_file: str = "/var/run/argus/aegis.pid"
    stats_file: str = "/var/lib/argus/aegis/stats.json"
    
    # Service management
    health_check_port: int = 8080
    shutdown_timeout: int = 30
    
    def to_safe_dict(self) -> dict[str, Any]:
        """Return a safe dictionary representation (with secrets redacted)."""
        return {
            "model": {
                "model_local_path": self.model.model_local_path,
                "scaler_local_path": self.model.scaler_local_path,
                "min_model_age_hours": self.model.min_model_age_hours,
                "max_model_age_days": self.model.max_model_age_days,
                "use_fallback_model": self.model.use_fallback_model,
                "foundation_model_path": self.model.foundation_model_path,
            },
            "polling": {
                "poll_interval_seconds": self.polling.poll_interval_seconds,
                "csv_directory": self.polling.csv_directory,
                "batch_size": self.polling.batch_size,
            },
            "prediction": {
                "feature_columns": self.prediction.feature_columns,
                "anomaly_threshold": self.prediction.anomaly_threshold,
                "high_risk_threshold": self.prediction.high_risk_threshold,
                "max_flows_per_batch": self.prediction.max_flows_per_batch,
                "enable_parallel_processing": self.prediction.enable_parallel_processing,
                "max_workers": self.prediction.max_workers,
            },
            "enforcement": {
                "dry_run_duration_days": self.enforcement.dry_run_duration_days,
                "enforce_after_dry_run": self.enforcement.enforce_after_dry_run,
                "iptables_chain_name": self.enforcement.iptables_chain_name,
                "blacklist_default_ttl_hours": self.enforcement.blacklist_default_ttl_hours,
                "max_blacklist_entries": self.enforcement.max_blacklist_entries,
            },
            "runtime": {
                "log_level": self.log_level,
                "state_file": self.state_file,
                "stats_file": self.stats_file,
                "health_check_port": self.health_check_port,
                "anonymization_salt": "***",  # Redacted
            },
            "firebase": {
                "enabled": self.firebase is not None,
                "project_id": self.firebase.project_id if self.firebase else None,
            } if self.firebase else None,
            "github": {
                "enabled": self.github is not None,
            } if self.github else None,
        }


def load_aegis_config(
    path: str | os.PathLike[str],
    *,
    env: Mapping[str, str] | None = None,
) -> AegisConfig:
    """Load and validate Aegis configuration from YAML file."""
    
    env_map = dict(os.environ) if env is None else dict(env)
    
    p = Path(path)
    if not p.exists():
        raise ValidationError([
            ValidationIssue(f"config_file:{path}", "Configuration file not found")
        ])
    
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    raw_map = as_mapping(raw, path="$")
    
    # Load model configuration
    model_data = as_mapping(
        get_optional(raw_map, "model", {}),
        path="$.model"
    )
    model = ModelConfig.from_mapping(model_data, path="$.model")
    
    # Load polling configuration
    polling_data = as_mapping(
        get_optional(raw_map, "polling", {}),
        path="$.polling"
    )
    polling = PollingConfig.from_mapping(polling_data, path="$.polling")
    
    # Load prediction configuration
    prediction_data = as_mapping(
        get_optional(raw_map, "prediction", {}),
        path="$.prediction"
    )
    prediction = PredictionConfig.from_mapping(prediction_data, path="$.prediction")
    
    # Load enforcement configuration
    enforcement_data = as_mapping(
        get_optional(raw_map, "enforcement", {}),
        path="$.enforcement"
    )
    enforcement = EnforcementConfig.from_mapping(enforcement_data, path="$.enforcement")
    
    # Load runtime configuration
    runtime_data = as_mapping(
        get_optional(raw_map, "runtime", {}),
        path="$.runtime"
    )
    
    log_level = require_non_empty_str(
        get_optional(runtime_data, "log_level", "INFO"),
        path="$.runtime.log_level"
    )
    
    state_file = require_non_empty_str(
        get_optional(runtime_data, "state_file", os.environ.get(
            "ARGUS_STATE_FILE", "/var/lib/argus/aegis/state.json")),
        path="$.runtime.state_file"
    )
    
    pid_file = require_non_empty_str(
        get_optional(runtime_data, "pid_file", os.environ.get(
            "ARGUS_PID_FILE", "/var/run/argus/aegis.pid")),
        path="$.runtime.pid_file"
    )
    
    stats_file = require_non_empty_str(
        get_optional(runtime_data, "stats_file", os.environ.get(
            "ARGUS_STATS_FILE", "/var/lib/argus/aegis/stats.json")),
        path="$.runtime.stats_file"
    )
    
    health_check_port = require_positive_int(
        get_optional(runtime_data, "health_check_port", 8080),
        path="$.runtime.health_check_port"
    )
    
    shutdown_timeout = require_positive_int(
        get_optional(runtime_data, "shutdown_timeout", 30),
        path="$.runtime.shutdown_timeout"
    )

    anonymization_salt = get_optional(
        runtime_data,
        "anonymization_salt",
        os.environ.get("AEGIS_SALT")
    )

    if not anonymization_salt:
        raise ValidationError([
            ValidationIssue(
                "$.runtime.anonymization_salt",
                "Anonymization salt is required in config or AEGIS_SALT env var"
            )
        ])
    
    # Load optional Firebase configuration
    firebase: FirebaseConfig | None = None
    if get_optional(raw_map, "firebase", None):
        firebase_data = as_mapping(raw_map["firebase"], path="$.firebase")
        firebase = FirebaseConfig.from_mapping(
            firebase_data,
            path="$.firebase",
            env=env_map
        )
    
    # Load optional GitHub configuration
    github: GitHubConfig | None = None
    if get_optional(raw_map, "github", None):
        github_data = as_mapping(raw_map["github"], path="$.github")
        github = GitHubConfig.from_mapping(
            github_data,
            path="$.github",
            env=env_map
        )
    
    return AegisConfig(
        model=model,
        polling=polling,
        prediction=prediction,
        enforcement=enforcement,
        anonymization_salt=anonymization_salt,
        firebase=firebase,
        github=github,
        log_level=log_level,
        state_file=state_file,
        pid_file=pid_file,
        stats_file=stats_file,
        health_check_port=health_check_port,
        shutdown_timeout=shutdown_timeout,
    )