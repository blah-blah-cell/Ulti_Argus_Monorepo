"""Configuration for the Mnemosyne trainer pipeline.

This module defines the configuration schema for the mnemosyne trainer pipeline,
including Firebase connection settings, ML model parameters, and training workflow
configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ..oracle_core.validation import (
    ValidationError,
    ValidationIssue,
    as_bool,
    as_list,
    as_mapping,
    get_optional,
    get_required,
    require_non_empty_str,
    require_positive_int,
    require_range_float,
)


@dataclass(frozen=True, slots=True)
class MnemosyneFirebaseConfig:
    """Firebase configuration for mnemosyne trainer."""
    project_id: str
    storage_bucket: str
    service_account_path: str
    training_data_path: str = "flows/training"
    model_output_path: str = "models"
    cleanup_threshold_hours: int = 24
    request_timeout_seconds: int = 30

    @staticmethod
    def from_mapping(
        data: Mapping[str, Any],
        *,
        path: str,
        env: Mapping[str, str],
    ) -> "MnemosyneFirebaseConfig":
        project_id = require_non_empty_str(
            get_required(data, "project_id", path=path),
            path=f"{path}.project_id",
        )
        storage_bucket = require_non_empty_str(
            get_required(data, "storage_bucket", path=path),
            path=f"{path}.storage_bucket",
        )
        
        service_account_path_raw = require_non_empty_str(
            get_required(data, "service_account_path", path=path),
            path=f"{path}.service_account_path",
        )
        service_account_path = os.path.expanduser(service_account_path_raw)
        
        training_data_path = require_non_empty_str(
            get_optional(data, "training_data_path", "flows/training"),
            path=f"{path}.training_data_path",
        )
        
        model_output_path = require_non_empty_str(
            get_optional(data, "model_output_path", "models"),
            path=f"{path}.model_output_path",
        )
        
        cleanup_threshold_hours = require_positive_int(
            get_optional(data, "cleanup_threshold_hours", 24),
            path=f"{path}.cleanup_threshold_hours",
        )
        
        request_timeout_seconds = require_positive_int(
            get_optional(data, "request_timeout_seconds", 30),
            path=f"{path}.request_timeout_seconds",
        )
        
        return MnemosyneFirebaseConfig(
            project_id=project_id,
            storage_bucket=storage_bucket,
            service_account_path=service_account_path,
            training_data_path=training_data_path,
            model_output_path=model_output_path,
            cleanup_threshold_hours=cleanup_threshold_hours,
            request_timeout_seconds=request_timeout_seconds,
        )


@dataclass(frozen=True, slots=True)
class PreprocessingConfig:
    """Preprocessing configuration for feature scaling and normalization."""
    log_transform_features: list[str] = field(default_factory=lambda: [
        "bytes_in", "bytes_out", "packets_in", "packets_out", "duration"
    ])
    feature_normalization_method: str = "standard"  # "standard" or "robust"
    contamination_auto_tune: bool = True
    contamination_range: tuple[float, float] = (0.01, 0.1)
    min_samples_for_training: int = 1000
    max_model_size_mb: int = 100

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "PreprocessingConfig":
        log_transform_features = get_optional(data, "log_transform_features", [
            "bytes_in", "bytes_out", "packets_in", "packets_out", "duration"
        ])
        features_list = as_list(log_transform_features, path=f"{path}.log_transform_features")
        features = [
            require_non_empty_str(f, path=f"{path}.log_transform_features[{i}]")
            for i, f in enumerate(features_list)
        ]
        
        feature_normalization_method = require_non_empty_str(
            get_optional(data, "feature_normalization_method", "standard"),
            path=f"{path}.feature_normalization_method",
        )
        if feature_normalization_method not in {"standard", "robust"}:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.feature_normalization_method",
                    "must be 'standard' or 'robust'",
                )
            ])
        
        contamination_auto_tune = as_bool(
            get_optional(data, "contamination_auto_tune", True),
            path=f"{path}.contamination_auto_tune",
        )
        
        contamination_range_raw = get_optional(data, "contamination_range", [0.01, 0.1])
        contamination_range_list = as_list(contamination_range_raw, path=f"{path}.contamination_range")
        if len(contamination_range_list) != 2:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.contamination_range",
                    "must contain exactly 2 values [min, max]",
                )
            ])
        
        contamination_min = require_range_float(
            contamination_range_list[0],
            0.001, 0.5,
            path=f"{path}.contamination_range[0]",
        )
        contamination_max = require_range_float(
            contamination_range_list[1],
            0.001, 0.5,
            path=f"{path}.contamination_range[1]",
        )
        if contamination_min >= contamination_max:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.contamination_range",
                    "min value must be less than max value",
                )
            ])
        
        min_samples_for_training = require_positive_int(
            get_optional(data, "min_samples_for_training", 1000),
            path=f"{path}.min_samples_for_training",
        )
        
        max_model_size_mb = require_positive_int(
            get_optional(data, "max_model_size_mb", 100),
            path=f"{path}.max_model_size_mb",
        )
        
        return PreprocessingConfig(
            log_transform_features=features,
            feature_normalization_method=feature_normalization_method,
            contamination_auto_tune=contamination_auto_tune,
            contamination_range=(contamination_min, contamination_max),
            min_samples_for_training=min_samples_for_training,
            max_model_size_mb=max_model_size_mb,
        )


@dataclass(frozen=True, slots=True)
class ModelTrainingConfig:
    """Configuration for IsolationForest model training."""
    random_state: int = 42
    n_estimators_range: tuple[int, int] = (50, 200)
    max_samples_range: tuple[float, float] = (0.5, 1.0)
    bootstrap_options: list[bool] = field(default_factory=lambda: [True, False])
    validation_split: float = 0.2
    cross_validation_folds: int = 3

    @staticmethod
    def from_mapping(data: Mapping[str, Any], *, path: str) -> "ModelTrainingConfig":
        random_state = require_positive_int(
            get_optional(data, "random_state", 42),
            path=f"{path}.random_state",
        )
        
        n_estimators_range_raw = get_optional(data, "n_estimators_range", [50, 200])
        n_estimators_list = as_list(n_estimators_range_raw, path=f"{path}.n_estimators_range")
        if len(n_estimators_list) != 2:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.n_estimators_range",
                    "must contain exactly 2 values [min, max]",
                )
            ])
        
        n_estimators_min = require_positive_int(
            n_estimators_list[0],
            path=f"{path}.n_estimators_range[0]",
        )
        n_estimators_max = require_positive_int(
            n_estimators_list[1],
            path=f"{path}.n_estimators_range[1]",
        )
        if n_estimators_min >= n_estimators_max:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.n_estimators_range",
                    "min value must be less than max value",
                )
            ])
        
        max_samples_range_raw = get_optional(data, "max_samples_range", [0.5, 1.0])
        max_samples_list = as_list(max_samples_range_raw, path=f"{path}.max_samples_range")
        if len(max_samples_list) != 2:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.max_samples_range",
                    "must contain exactly 2 values [min, max]",
                )
            ])
        
        max_samples_min = require_range_float(
            max_samples_list[0],
            0.1, 1.0,
            path=f"{path}.max_samples_range[0]",
        )
        max_samples_max = require_range_float(
            max_samples_list[1],
            0.1, 1.0,
            path=f"{path}.max_samples_range[1]",
        )
        if max_samples_min >= max_samples_max:
            raise ValidationError([
                ValidationIssue(
                    f"{path}.max_samples_range",
                    "min value must be less than max value",
                )
            ])
        
        bootstrap_options_raw = get_optional(data, "bootstrap_options", [True, False])
        bootstrap_list = as_list(bootstrap_options_raw, path=f"{path}.bootstrap_options")
        bootstrap_options = [
            as_bool(b, path=f"{path}.bootstrap_options[{i}]")
            for i, b in enumerate(bootstrap_list)
        ]
        
        validation_split = require_range_float(
            get_optional(data, "validation_split", 0.2),
            0.1, 0.3,
            path=f"{path}.validation_split",
        )
        
        cross_validation_folds = require_positive_int(
            get_optional(data, "cross_validation_folds", 3),
            path=f"{path}.cross_validation_folds",
        )
        
        return ModelTrainingConfig(
            random_state=random_state,
            n_estimators_range=(n_estimators_min, n_estimators_max),
            max_samples_range=(max_samples_min, max_samples_max),
            bootstrap_options=bootstrap_options,
            validation_split=validation_split,
            cross_validation_folds=cross_validation_folds,
        )


@dataclass(frozen=True, slots=True)
class MnemosyneConfig:
    """Main configuration for the Mnemosyne trainer pipeline."""
    firebase: MnemosyneFirebaseConfig
    preprocessing: PreprocessingConfig
    training: ModelTrainingConfig

    def to_safe_dict(self) -> dict[str, Any]:
        """Return a safe dictionary representation for logging."""
        return {
            "firebase": {
                "project_id": self.firebase.project_id,
                "storage_bucket": self.firebase.storage_bucket,
                "service_account_path": "[REDACTED]",
                "training_data_path": self.firebase.training_data_path,
                "model_output_path": self.firebase.model_output_path,
                "cleanup_threshold_hours": self.firebase.cleanup_threshold_hours,
                "request_timeout_seconds": self.firebase.request_timeout_seconds,
            },
            "preprocessing": {
                "log_transform_features": self.preprocessing.log_transform_features,
                "feature_normalization_method": self.preprocessing.feature_normalization_method,
                "contamination_auto_tune": self.preprocessing.contamination_auto_tune,
                "contamination_range": self.preprocessing.contamination_range,
                "min_samples_for_training": self.preprocessing.min_samples_for_training,
                "max_model_size_mb": self.preprocessing.max_model_size_mb,
            },
            "training": {
                "random_state": self.training.random_state,
                "n_estimators_range": self.training.n_estimators_range,
                "max_samples_range": self.training.max_samples_range,
                "bootstrap_options": self.training.bootstrap_options,
                "validation_split": self.training.validation_split,
                "cross_validation_folds": self.training.cross_validation_folds,
            },
        }


def load_mnemosyne_config(
    path: str | os.PathLike[str],
    *,
    env: Mapping[str, str] | None = None,
) -> MnemosyneConfig:
    """Load and validate a Mnemosyne YAML configuration file."""
    
    env_map = dict(os.environ) if env is None else dict(env)
    
    import yaml
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    raw_map = as_mapping(raw, path="$")
    
    firebase = MnemosyneFirebaseConfig.from_mapping(
        as_mapping(get_required(raw_map, "firebase", path="$.firebase"), path="$.firebase"),
        path="$.firebase",
        env=env_map,
    )
    
    preprocessing = PreprocessingConfig.from_mapping(
        as_mapping(get_optional(raw_map, "preprocessing", {}), path="$.preprocessing"),
        path="$.preprocessing",
    )
    
    training = ModelTrainingConfig.from_mapping(
        as_mapping(get_optional(raw_map, "training", {}), path="$.training"),
        path="$.training",
    )
    
    return MnemosyneConfig(
        firebase=firebase,
        preprocessing=preprocessing,
        training=training,
    )