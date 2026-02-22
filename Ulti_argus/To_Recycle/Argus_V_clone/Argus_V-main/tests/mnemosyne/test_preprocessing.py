"""Unit tests for mnemosyne preprocessing module."""

from unittest.mock import Mock

import numpy as np
import pandas as pd
import pytest

from argus_v.mnemosyne.preprocessing import FlowPreprocessor


@pytest.fixture
def preprocessing_config():
    """Create a mock preprocessing configuration."""
    config = Mock()
    config.log_transform_features = ["bytes_in", "bytes_out", "packets_in", "packets_out"]
    config.feature_normalization_method = "standard"
    config.contamination_auto_tune = True
    config.contamination_range = (0.01, 0.1)
    config.min_samples_for_training = 1000
    config.max_model_size_mb = 100
    config.random_state = 42
    return config


@pytest.fixture
def sample_flow_df():
    """Create sample flow DataFrame for testing."""
    data = {
        'timestamp': pd.to_datetime(['2024-01-01 10:00:00', '2024-01-01 10:01:00']),
        'src_ip': ['192.168.1.1', '192.168.1.2'],
        'dst_ip': ['192.168.1.2', '192.168.1.3'],
        'src_port': [80, 443],
        'dst_port': [12345, 80],
        'protocol': ['TCP', 'UDP'],
        'bytes_in': [1000, 5000],
        'bytes_out': [500, 2500],
        'packets_in': [10, 50],
        'packets_out': [5, 25],
        'duration': [1.5, 2.3]
    }
    return pd.DataFrame(data)


class TestFlowPreprocessor:
    """Test flow data preprocessing functionality."""
    
    def test_prepare_features_success(self, preprocessing_config, sample_flow_df):
        """Test successful feature preparation."""
        preprocessor = FlowPreprocessor(preprocessing_config)
        features_df = preprocessor.prepare_features(sample_flow_df)
        
        expected_features = ['bytes_in', 'bytes_out', 'packets_in', 'packets_out', 'duration',
                           'src_port', 'dst_port', 'protocol']
        
        assert len(features_df) == 2
        assert list(features_df.columns) == expected_features
        assert 'protocol' in features_df.columns
        
        # Protocol should be numeric
        assert features_df['protocol'].dtype in ['int64', 'float64']
        
        # Ports should be positive
        assert all(features_df['src_port'] > 0)
        assert all(features_df['dst_port'] > 0)
    
    def test_prepare_features_missing_columns(self, preprocessing_config):
        """Test error when required features are missing."""
        incomplete_df = pd.DataFrame({
            'timestamp': ['2024-01-01 10:00:00'],
            'src_ip': ['192.168.1.1'],
            # Missing other required columns
        })
        
        preprocessor = FlowPreprocessor(preprocessing_config)
        
        with pytest.raises(ValueError, match="Missing required features"):
            preprocessor.prepare_features(incomplete_df)
    
    def test_apply_log_transform(self, preprocessing_config, sample_flow_df):
        """Test log transformation of features."""
        preprocessor = FlowPreprocessor(preprocessing_config)
        features_df = preprocessor.prepare_features(sample_flow_df)
        
        log_df = preprocessor.apply_log_transform(features_df)
        
        # Original log transform features should be gone
        for feature in preprocessing_config.log_transform_features:
            assert feature not in log_df.columns
            assert f"{feature}_log" in log_df.columns
        
        # Log-transformed values should be positive (log1p)
        for feature in preprocessing_config.log_transform_features:
            log_col = f"{feature}_log"
            assert all(log_df[log_col] >= 0)
    
    def test_normalize_features_standard(self, preprocessing_config, sample_flow_df):
        """Test feature normalization with StandardScaler."""
        preprocessor = FlowPreprocessor(preprocessing_config)
        features_df = preprocessor.prepare_features(sample_flow_df)
        log_df = preprocessor.apply_log_transform(features_df)
        
        normalized_df, scaler = preprocessor.normalize_features(log_df)
        
        # Features should be normalized (mean ≈ 0, std ≈ 1 for large samples)
        assert len(normalized_df) == len(log_df)
        assert list(normalized_df.columns) == list(log_df.columns)
        assert preprocessor._scaler is not None
        assert type(scaler).__name__ == "StandardScaler"
    
    def test_normalize_features_robust(self, preprocessing_config, sample_flow_df):
        """Test feature normalization with RobustScaler."""
        preprocessing_config.feature_normalization_method = "robust"
        
        preprocessor = FlowPreprocessor(preprocessing_config)
        features_df = preprocessor.prepare_features(sample_flow_df)
        log_df = preprocessor.apply_log_transform(features_df)
        
        normalized_df, scaler = preprocessor.normalize_features(log_df)
        
        assert type(scaler).__name__ == "RobustScaler"
        assert len(normalized_df) == len(log_df)
    
    def test_normalize_features_invalid_method(self, preprocessing_config, sample_flow_df):
        """Test error with invalid normalization method."""
        preprocessing_config.feature_normalization_method = "invalid_method"
        
        preprocessor = FlowPreprocessor(preprocessing_config)
        features_df = preprocessor.prepare_features(sample_flow_df)
        log_df = preprocessor.apply_log_transform(features_df)
        
        with pytest.raises(ValueError, match="Unknown normalization method"):
            preprocessor.normalize_features(log_df)
    
    def test_detect_feature_outliers(self, preprocessing_config, sample_flow_df):
        """Test outlier detection and removal."""
        preprocessor = FlowPreprocessor(preprocessing_config)
        features_df = preprocessor.prepare_features(sample_flow_df)
        
        # Add some outlier data
        outlier_data = sample_flow_df.copy()
        outlier_data.loc[0, 'bytes_in'] = 1000000  # Extreme outlier
        
        outlier_features = preprocessor.prepare_features(outlier_data)
        clean_df, stats = preprocessor.detect_feature_outliers(outlier_features)
        
        assert 'total_outliers' in stats
        assert 'outliers_by_feature' in stats
        assert 'removal_percentage' in stats
        
        # Outlier should have been removed
        assert len(clean_df) < len(outlier_features)
    
    def test_detect_feature_outliers_no_removal(self, preprocessing_config, sample_flow_df):
        """Test outlier detection with high threshold (no removal)."""
        preprocessor = FlowPreprocessor(preprocessing_config)
        features_df = preprocessor.prepare_features(sample_flow_df)
        
        clean_df, stats = preprocessor.detect_feature_outliers(features_df, threshold=10.0)
        
        # With high threshold, no outliers should be removed
        assert len(clean_df) == len(features_df)
        assert stats['total_outliers'] == 0
    
    @pytest.mark.skipif(not pytest.importorskip("sklearn"), reason="sklearn not available")
    def test_tune_contamination_parameter_success(self, preprocessing_config):
        """Test successful contamination parameter tuning."""
        # Create larger dataset for tuning
        np.random.seed(42)
        large_data = {
            'bytes_in': np.random.lognormal(5, 1, 200),
            'bytes_out': np.random.lognormal(4, 1, 200),
            'packets_in': np.random.poisson(20, 200),
            'packets_out': np.random.poisson(15, 200),
            'duration': np.random.exponential(2, 200),
            'src_port': np.random.randint(1, 65535, 200),
            'dst_port': np.random.randint(1, 65535, 200),
            'protocol': np.random.choice([1, 2], 200)
        }
        large_df = pd.DataFrame(large_data)
        
        preprocessor = FlowPreprocessor(preprocessing_config)
        
        contamination, tuning_stats = preprocessor.tune_contamination_parameter(large_df)
        
        assert 0.01 <= contamination <= 0.1
        assert 'contamination_range' in tuning_stats
        assert 'best_contamination' in tuning_stats
        assert 'scores' in tuning_stats
    
    @pytest.mark.skipif(not pytest.importorskip("sklearn"), reason="sklearn not available")
    def test_tune_contamination_parameter_insufficient_samples(self, preprocessing_config, sample_flow_df):
        """Test contamination tuning with insufficient samples."""
        preprocessing_config.min_samples_for_training = 1000
        
        preprocessor = FlowPreprocessor(preprocessing_config)
        
        # Should fall back to default when insufficient samples
        contamination, tuning_stats = preprocessor.tune_contamination_parameter(sample_flow_df)
        
        # Should use middle of range
        expected_contamination = (0.01 + 0.1) / 2
        assert abs(contamination - expected_contamination) < 0.01
        assert 'auto_tune_enabled' in tuning_stats
        assert tuning_stats['auto_tune_enabled'] is False
    
    def test_preprocess_pipeline_success(self, preprocessing_config, sample_flow_df):
        """Test complete preprocessing pipeline."""
        preprocessor = FlowPreprocessor(preprocessing_config)
        
        processed_df, stats = preprocessor.preprocess_pipeline(sample_flow_df)
        
        assert 'initial_rows' in stats
        assert 'feature_preparation' in stats
        assert 'log_transform' in stats
        assert 'outlier_detection' in stats
        assert 'normalization' in stats
        assert 'contamination_tuning' in stats
        assert 'final_rows' in stats
        assert 'optimal_contamination' in stats
        
        assert stats['initial_rows'] == 2
        assert stats['final_features'] > 0
        assert 0.01 <= stats['optimal_contamination'] <= 0.1
        
        # Processed DataFrame should have correct structure
        assert len(processed_df) == stats['final_rows']
        assert processed_df.shape[1] == stats['final_features']
    
    def test_preprocess_pipeline_auto_tune_disabled(self, preprocessing_config, sample_flow_df):
        """Test preprocessing pipeline with auto-tune disabled."""
        preprocessing_config.contamination_auto_tune = False
        
        preprocessor = FlowPreprocessor(preprocessing_config)
        
        processed_df, stats = preprocessor.preprocess_pipeline(sample_flow_df)
        
        # Should use default contamination
        expected_contamination = (0.01 + 0.1) / 2
        assert abs(stats['optimal_contamination'] - expected_contamination) < 0.01
        
        assert 'contamination_tuning' in stats
        assert stats['contamination_tuning']['auto_tune_enabled'] is False