"""Unit tests for mnemosyne configuration module."""

import os
import tempfile

import pytest

from argus_v.mnemosyne.config import (
    MnemosyneConfig,
    MnemosyneFirebaseConfig,
    ModelTrainingConfig,
    PreprocessingConfig,
    load_mnemosyne_config,
)


class TestMnemosyneFirebaseConfig:
    """Test Firebase configuration."""
    
    def test_valid_firebase_config(self):
        """Test valid Firebase configuration."""
        data = {
            "project_id": "test-project",
            "storage_bucket": "test-bucket",
            "service_account_path": "/path/to/service-account.json"
        }
        
        config = MnemosyneFirebaseConfig.from_mapping(
            data, path="test", env={}
        )
        
        assert config.project_id == "test-project"
        assert config.storage_bucket == "test-bucket"
        assert config.service_account_path == "/path/to/service-account.json"
        assert config.training_data_path == "flows/training"
        assert config.cleanup_threshold_hours == 24
    
    def test_firebase_config_with_optional_params(self):
        """Test Firebase configuration with optional parameters."""
        data = {
            "project_id": "test-project",
            "storage_bucket": "test-bucket",
            "service_account_path": "~/service-account.json",
            "training_data_path": "custom/training",
            "model_output_path": "custom/models",
            "cleanup_threshold_hours": 48,
            "request_timeout_seconds": 60
        }
        
        config = MnemosyneFirebaseConfig.from_mapping(
            data, path="test", env={}
        )
        
        assert config.training_data_path == "custom/training"
        assert config.model_output_path == "custom/models"
        assert config.cleanup_threshold_hours == 48
        assert config.request_timeout_seconds == 60
    
    def test_firebase_config_env_expansion(self):
        """Test environment variable expansion in Firebase config."""
        data = {
            "project_id": "test-project",
            "storage_bucket": "test-bucket",
            "service_account_path": "${SERVICE_ACCOUNT_PATH}"
        }
        
        env = {"SERVICE_ACCOUNT_PATH": "/expanded/path.json"}
        
        config = MnemosyneFirebaseConfig.from_mapping(
            data, path="test", env=env
        )
        
        assert config.service_account_path == "/expanded/path.json"
    
    def test_missing_required_firebase_params(self):
        """Test error when required Firebase parameters are missing."""
        data = {
            "project_id": "test-project"
            # Missing storage_bucket and service_account_path
        }
        
        with pytest.raises(Exception):
            MnemosyneFirebaseConfig.from_mapping(
                data, path="test", env={}
            )


class TestPreprocessingConfig:
    """Test preprocessing configuration."""
    
    def test_default_preprocessing_config(self):
        """Test default preprocessing configuration."""
        config = PreprocessingConfig.from_mapping({}, path="test")
        
        assert config.feature_normalization_method == "standard"
        assert config.contamination_auto_tune is True
        assert config.contamination_range == (0.01, 0.1)
        assert config.min_samples_for_training == 1000
        assert "bytes_in" in config.log_transform_features
    
    def test_custom_preprocessing_config(self):
        """Test custom preprocessing configuration."""
        data = {
            "log_transform_features": ["bytes", "duration"],
            "feature_normalization_method": "robust",
            "contamination_auto_tune": False,
            "contamination_range": [0.05, 0.15],
            "min_samples_for_training": 2000,
            "max_model_size_mb": 150
        }
        
        config = PreprocessingConfig.from_mapping(data, path="test")
        
        assert config.log_transform_features == ["bytes", "duration"]
        assert config.feature_normalization_method == "robust"
        assert config.contamination_auto_tune is False
        assert config.contamination_range == (0.05, 0.15)
        assert config.min_samples_for_training == 2000
        assert config.max_model_size_mb == 150
    
    def test_invalid_normalization_method(self):
        """Test error for invalid normalization method."""
        data = {
            "feature_normalization_method": "invalid_method"
        }
        
        with pytest.raises(Exception):
            PreprocessingConfig.from_mapping(data, path="test")
    
    def test_invalid_contamination_range(self):
        """Test error for invalid contamination range."""
        data = {
            "contamination_range": [0.2, 0.1]  # min > max
        }
        
        with pytest.raises(Exception):
            PreprocessingConfig.from_mapping(data, path="test")


class TestModelTrainingConfig:
    """Test model training configuration."""
    
    def test_default_training_config(self):
        """Test default training configuration."""
        config = ModelTrainingConfig.from_mapping({}, path="test")
        
        assert config.random_state == 42
        assert config.n_estimators_range == (50, 200)
        assert config.max_samples_range == (0.5, 1.0)
        assert True in config.bootstrap_options
        assert False in config.bootstrap_options
        assert config.validation_split == 0.2
        assert config.cross_validation_folds == 3
    
    def test_custom_training_config(self):
        """Test custom training configuration."""
        data = {
            "random_state": 123,
            "n_estimators_range": [100, 300],
            "max_samples_range": [0.6, 0.9],
            "bootstrap_options": [True],
            "validation_split": 0.25,
            "cross_validation_folds": 5
        }
        
        config = ModelTrainingConfig.from_mapping(data, path="test")
        
        assert config.random_state == 123
        assert config.n_estimators_range == (100, 300)
        assert config.max_samples_range == (0.6, 0.9)
        assert config.bootstrap_options == [True]
        assert config.validation_split == 0.25
        assert config.cross_validation_folds == 5


class TestMnemosyneConfig:
    """Test main mnemosyne configuration."""
    
    def test_complete_config(self):
        """Test complete mnemosyne configuration."""
        firebase_data = {
            "project_id": "test-project",
            "storage_bucket": "test-bucket",
            "service_account_path": "/path/to/service-account.json"
        }
        
        preprocessing_data = {
            "contamination_range": [0.03, 0.07]
        }
        
        training_data = {
            "random_state": 456
        }
        
        config = MnemosyneConfig(
            firebase=MnemosyneFirebaseConfig.from_mapping(firebase_data, path="firebase", env={}),
            preprocessing=PreprocessingConfig.from_mapping(preprocessing_data, path="preprocessing"),
            training=ModelTrainingConfig.from_mapping(training_data, path="training")
        )
        
        assert config.firebase.project_id == "test-project"
        assert config.preprocessing.contamination_range == (0.03, 0.07)
        assert config.training.random_state == 456
        
        # Test safe dict representation
        safe_dict = config.to_safe_dict()
        assert "service_account_path" not in safe_dict["firebase"]["service_account_path"]
        assert "api_key" not in safe_dict["firebase"]
    
    def test_config_from_yaml(self):
        """Test loading configuration from YAML file."""
        yaml_content = """
firebase:
  project_id: yaml-test-project
  storage_bucket: yaml-test-bucket
  service_account_path: /yaml/path.json
  training_data_path: yaml/training
  model_output_path: yaml/models

preprocessing:
  log_transform_features:
    - bytes_total
    - packets_total
  feature_normalization_method: robust
  contamination_range: [0.02, 0.08]

training:
  random_state: 789
  n_estimators_range: [75, 225]
  validation_split: 0.3
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name
        
        try:
            config = load_mnemosyne_config(temp_path)
            
            assert config.firebase.project_id == "yaml-test-project"
            assert config.firebase.training_data_path == "yaml/training"
            assert config.preprocessing.feature_normalization_method == "robust"
            assert "bytes_total" in config.preprocessing.log_transform_features
            assert config.training.random_state == 789
            assert config.training.n_estimators_range == (75, 225)
            
        finally:
            os.unlink(temp_path)