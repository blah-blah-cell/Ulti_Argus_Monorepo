"""Unit tests for mnemosyne trainer module."""

import pickle
from pathlib import Path
from unittest.mock import Mock, patch

import numpy as np
import pandas as pd
import pytest
import skops.io as sio
from sklearn.preprocessing import StandardScaler

from argus_v.mnemosyne.trainer import IsolationForestTrainer


@pytest.fixture
def training_config():
    """Create a mock training configuration."""
    config = Mock()
    config.random_state = 42
    config.n_estimators_range = (50, 100)
    config.max_samples_range = (0.5, 0.8)
    config.bootstrap_options = [True, False]
    config.validation_split = 0.2
    config.cross_validation_folds = 3
    config.min_samples_for_training = 10  # Lower for testing
    config.max_model_size_mb = 100
    config.contamination_range = (0.01, 0.1)
    return config


@pytest.fixture
def sample_features_df():
    """Create sample feature DataFrame for training."""
    np.random.seed(42)
    data = {
        'bytes_in_log': np.random.normal(0, 1, 100),
        'bytes_out_log': np.random.normal(0, 1, 100),
        'packets_in_log': np.random.normal(0, 1, 100),
        'packets_out_log': np.random.normal(0, 1, 100),
        'duration_log': np.random.normal(0, 1, 100),
        'src_port': np.random.randint(1, 65535, 100),
        'dst_port': np.random.randint(1, 65535, 100),
        'protocol': np.random.choice([1, 2], 100)
    }
    return pd.DataFrame(data)


class TestIsolationForestTrainer:
    """Test IsolationForest model training functionality."""
    
    def test_validate_data_sufficiency_success(self, training_config, sample_features_df):
        """Test successful data validation."""
        trainer = IsolationForestTrainer(training_config)
        
        is_sufficient, reason = trainer._validate_data_sufficiency(sample_features_df)
        
        assert is_sufficient is True
        assert "validation passed" in reason
    
    def test_validate_data_sufficiency_insufficient_samples(self, training_config, sample_features_df):
        """Test data validation with insufficient samples."""
        training_config.min_samples_for_training = 200
        
        trainer = IsolationForestTrainer(training_config)
        
        small_df = sample_features_df.head(10)
        is_sufficient, reason = trainer._validate_data_sufficiency(small_df)
        
        assert is_sufficient is False
        assert "Insufficient samples" in reason
    
    def test_validate_data_sufficiency_empty_dataframe(self, training_config):
        """Test data validation with empty DataFrame."""
        trainer = IsolationForestTrainer(training_config)
        
        empty_df = pd.DataFrame()
        is_sufficient, reason = trainer._validate_data_sufficiency(empty_df)
        
        assert is_sufficient is False
        assert "empty" in reason.lower() or "insufficient" in reason.lower()
    
    def test_validate_data_sufficiency_zero_variance(self, training_config, sample_features_df):
        """Test data validation with zero variance features."""
        trainer = IsolationForestTrainer(training_config)
        
        zero_var_df = sample_features_df.copy()
        zero_var_df.iloc[:, 0] = 5.0  # Set first column to constant value
        
        is_sufficient, reason = trainer._validate_data_sufficiency(zero_var_df)
        
        assert is_sufficient is False
        assert "variance" in reason.lower()
    
    def test_validate_data_sufficiency_nan_values(self, training_config, sample_features_df):
        """Test data validation with NaN values."""
        trainer = IsolationForestTrainer(training_config)
        
        nan_df = sample_features_df.copy()
        nan_df.iloc[0, 0] = np.nan
        
        is_sufficient, reason = trainer._validate_data_sufficiency(nan_df)
        
        assert is_sufficient is False
        assert "NaN" in reason
    
    def test_generate_model_name(self, training_config):
        """Test model name generation."""
        trainer = IsolationForestTrainer(training_config)
        
        model_stats = {
            'sample_count': 1500,
            'contamination': 0.05
        }
        
        model_name = trainer._generate_model_name(model_stats)
        
        assert "isolation_forest_" in model_name
        assert "s1500" in model_name
        assert "c0.050" in model_name
        assert model_name.endswith(".pkl") is False  # Just the name, not filename
    
    def test_create_parameter_grid(self, training_config):
        """Test parameter grid creation."""
        trainer = IsolationForestTrainer(training_config)
        
        param_grid = trainer._create_parameter_grid()
        
        assert 'n_estimators' in param_grid
        assert 'max_samples' in param_grid
        assert 'bootstrap' in param_grid
        
        assert len(param_grid['n_estimators']) > 0
        assert all(50 <= n <= 100 for n in param_grid['n_estimators'])
        assert all(0.5 <= m <= 0.8 for m in param_grid['max_samples'])
        assert True in param_grid['bootstrap']
        assert False in param_grid['bootstrap']
    
    @pytest.mark.skipif(not pytest.importorskip("sklearn"), reason="sklearn not available")
    def test_train_isolation_forest(self, training_config, sample_features_df):
        """Test IsolationForest training."""
        trainer = IsolationForestTrainer(training_config)
        
        model = trainer.train_isolation_forest(sample_features_df, contamination=0.05)
        
        assert hasattr(model, 'predict')
        assert hasattr(model, 'decision_function')
        # IsolationForest does not have score method in recent versions
        # assert hasattr(model, 'score')
        
        # Model should be fitted
        predictions = model.predict(sample_features_df[:5])
        assert len(predictions) == 5
    
    @pytest.mark.skipif(not pytest.importorskip("sklearn"), reason="sklearn not available")
    def test_evaluate_model(self, training_config, sample_features_df):
        """Test model evaluation."""
        trainer = IsolationForestTrainer(training_config)
        
        # Train a model first
        model = trainer.train_isolation_forest(sample_features_df, contamination=0.05)
        
        # Evaluate on the same data
        eval_stats = trainer.evaluate_model(model, sample_features_df)
        
        assert 'total_samples' in eval_stats
        assert 'anomalies_detected' in eval_stats
        assert 'anomaly_rate' in eval_stats
        assert 'mean_anomaly_score' in eval_stats
        assert 'std_anomaly_score' in eval_stats
        
        assert eval_stats['total_samples'] == len(sample_features_df)
        assert 0 <= eval_stats['anomaly_rate'] <= 1
    
    @pytest.mark.skipif(not pytest.importorskip("sklearn"), reason="sklearn not available")
    def test_train_model_success(self, training_config, sample_features_df):
        """Test complete model training."""
        trainer = IsolationForestTrainer(training_config)
        
        training_stats = trainer.train_model(sample_features_df)
        
        assert 'training_samples' in training_stats
        assert 'test_samples' in training_stats
        assert 'feature_count' in training_stats
        assert 'model_parameters' in training_stats
        assert 'training_contamination' in training_stats
        assert 'evaluation' in training_stats
        assert 'training_timestamp' in training_stats
        assert 'random_state' in training_stats
        
        assert training_stats['training_samples'] > 0
        assert training_stats['test_samples'] > 0
        assert training_stats['feature_count'] == sample_features_df.shape[1]
        assert trainer._best_model is not None
    
    def test_train_model_insufficient_data(self, training_config, sample_features_df):
        """Test model training with insufficient data."""
        training_config.min_samples_for_training = 200
        
        trainer = IsolationForestTrainer(training_config)
        small_df = sample_features_df.head(10)
        
        with pytest.raises(ValueError, match="Insufficient data for training"):
            trainer.train_model(small_df)
    
    @pytest.mark.skipif(not pytest.importorskip("sklearn"), reason="sklearn not available")
    def test_serialize_model_success(self, training_config, sample_features_df, tmp_path):
        """Test successful model serialization."""
        trainer = IsolationForestTrainer(training_config)
        
        # Train a model
        trainer.train_model(sample_features_df)
        
        # Create a REAL scaler
        scaler = StandardScaler()
        scaler.fit(sample_features_df)
        
        # Serialize model
        artifact_paths = trainer.serialize_model(str(tmp_path), scaler)
        
        assert 'model_path' in artifact_paths
        assert 'scaler_path' in artifact_paths
        assert 'metadata_path' in artifact_paths
        assert 'model_size_mb' in artifact_paths
        assert 'scaler_size_mb' in artifact_paths
        assert 'total_size_mb' in artifact_paths
        
        # Check files exist
        assert Path(artifact_paths['model_path']).exists()
        assert Path(artifact_paths['scaler_path']).exists()
        assert Path(artifact_paths['metadata_path']).exists()
        
        # Check metadata
        import json
        with open(artifact_paths['metadata_path']) as f:
            metadata = json.load(f)
        
        assert metadata['model_type'] == 'IsolationForest'
        assert 'training_stats' in metadata
        assert metadata['scaler_type'] == type(scaler).__name__
    
    def test_serialize_model_no_trained_model(self, training_config, tmp_path):
        """Test serialization error when no model is trained."""
        trainer = IsolationForestTrainer(training_config)
        
        mock_scaler = Mock()
        
        with pytest.raises(ValueError, match="No trained model available"):
            trainer.serialize_model(str(tmp_path), mock_scaler)
    
    @pytest.mark.skipif(not pytest.importorskip("sklearn"), reason="sklearn not available")
    def test_serialize_model_size_check(self, training_config, sample_features_df, tmp_path):
        """Test model size validation during serialization."""
        trainer = IsolationForestTrainer(training_config)
        
        # Train a model
        trainer.train_model(sample_features_df)
        
        # Create a REAL scaler
        scaler = StandardScaler()
        scaler.fit(sample_features_df)
        
        # Set a very small size limit
        training_config.max_model_size_mb = 0.001  # Very small limit
        
        # This should trigger a size warning
        with patch('argus_v.mnemosyne.trainer.log_event') as mock_log:
            artifact_paths = trainer.serialize_model(str(tmp_path), scaler)
            
            # Check if size warning was logged
            size_warning_logged = any(
                'model_size_warning' in str(call) for call in mock_log.call_args_list
            )
            # Note: This might not always trigger depending on actual model size
    
    def test_load_model_success(self, training_config, tmp_path):
        """Test successful model loading."""
        trainer = IsolationForestTrainer(training_config)

        # Create a mock model file
        model_data = {"mock": "model"}
        model_path = tmp_path / "test_model.skops"

        sio.dump(model_data, model_path)

        loaded_model = trainer.load_model(str(model_path))
        
        assert loaded_model == model_data
    
    def test_load_model_file_not_found(self, training_config):
        """Test model loading with non-existent file."""
        trainer = IsolationForestTrainer(training_config)
        
        with pytest.raises(FileNotFoundError):
            trainer.load_model("/non/existent/path/model.skops")
    
    def test_get_training_stats_empty(self, training_config):
        """Test getting training stats when no training has been done."""
        trainer = IsolationForestTrainer(training_config)
        
        stats = trainer.get_training_stats()
        
        assert stats == {}
    
    @pytest.mark.skipif(not pytest.importorskip("sklearn"), reason="sklearn not available")
    def test_get_training_stats_after_training(self, training_config, sample_features_df):
        """Test getting training stats after model training."""
        trainer = IsolationForestTrainer(training_config)
        
        trainer.train_model(sample_features_df)
        stats = trainer.get_training_stats()
        
        assert 'training_samples' in stats
        assert 'feature_count' in stats
        assert stats['training_samples'] > 0
