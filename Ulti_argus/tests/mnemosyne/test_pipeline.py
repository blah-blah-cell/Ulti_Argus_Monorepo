"""Unit tests for mnemosyne pipeline orchestration."""

from datetime import datetime
from unittest.mock import Mock, patch

import pandas as pd
import pytest

from argus_v.mnemosyne.pipeline import MnemosynePipeline


@pytest.fixture
def complete_config():
    """Create a complete mnemosyne configuration."""
    # Create mock configs
    firebase_config = Mock()
    firebase_config.project_id = "test-project"
    firebase_config.storage_bucket = "test-bucket"
    firebase_config.service_account_path = "/fake/path/service-account.json"
    firebase_config.training_data_path = "flows/training"
    firebase_config.model_output_path = "models"
    firebase_config.cleanup_threshold_hours = 24
    firebase_config.request_timeout_seconds = 30
    firebase_config.to_safe_dict.return_value = {"project_id": "test-project"}
    
    preprocessing_config = Mock()
    preprocessing_config.log_transform_features = ["bytes_in", "bytes_out"]
    preprocessing_config.feature_normalization_method = "standard"
    preprocessing_config.contamination_auto_tune = True
    preprocessing_config.contamination_range = (0.01, 0.1)
    preprocessing_config.min_samples_for_training = 10
    preprocessing_config.max_model_size_mb = 100
    preprocessing_config.random_state = 42
    
    training_config = Mock()
    training_config.random_state = 42
    training_config.n_estimators_range = (50, 100)
    training_config.max_samples_range = (0.5, 0.8)
    training_config.bootstrap_options = [True, False]
    training_config.validation_split = 0.2
    training_config.cross_validation_folds = 3
    training_config.min_samples_for_training = 10
    training_config.max_model_size_mb = 100
    
    # Create main config
    main_config = Mock()
    main_config.firebase = firebase_config
    main_config.preprocessing = preprocessing_config
    main_config.training = training_config
    main_config.to_safe_dict.return_value = {
        "firebase": {"project_id": "test-project"},
        "preprocessing": {"contamination_range": (0.01, 0.1)},
        "training": {"random_state": 42}
    }
    
    return main_config


@pytest.fixture
def sample_training_data():
    """Create sample training data."""
    return pd.DataFrame({
        'timestamp': pd.to_datetime(['2024-01-01 10:00:00', '2024-01-01 10:01:00', '2024-01-01 10:02:00']),
        'src_ip': ['192.168.1.1', '192.168.1.2', '10.0.0.1'],
        'dst_ip': ['192.168.1.2', '192.168.1.3', '10.0.0.2'],
        'src_port': [80, 443, 22],
        'dst_port': [12345, 80, 443],
        'protocol': ['TCP', 'TCP', 'UDP'],
        'bytes_in': [1000, 2000, 500],
        'bytes_out': [500, 1000, 200],
        'packets_in': [10, 20, 5],
        'packets_out': [5, 15, 3],
        'duration': [1.5, 2.3, 0.8]
    })


class TestMnemosynePipeline:
    """Test pipeline orchestration functionality."""
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.FlowPreprocessor')
    @patch('argus_v.mnemosyne.pipeline.IsolationForestTrainer')
    @patch('argus_v.mnemosyne.pipeline.ArtifactManager')
    def test_pipeline_initialization(self, mock_artifact_manager, mock_trainer, 
                                   mock_preprocessor, mock_data_loader, complete_config):
        """Test successful pipeline initialization."""
        # Mock the initialization calls
        mock_data_loader_instance = Mock()
        mock_preprocessor_instance = Mock()
        mock_trainer_instance = Mock()
        mock_artifact_manager_instance = Mock()
        
        mock_data_loader.return_value = mock_data_loader_instance
        mock_preprocessor.return_value = mock_preprocessor_instance
        mock_trainer.return_value = mock_trainer_instance
        mock_artifact_manager.return_value = mock_artifact_manager_instance
        
        with patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp', return_value='/tmp/mnemosyne_test'):
            pipeline = MnemosynePipeline(complete_config)
            
            # Verify all components were initialized
            mock_data_loader.assert_called_once_with(complete_config.firebase)
            mock_preprocessor.assert_called_once_with(complete_config.preprocessing)
            mock_trainer.assert_called_once_with(complete_config.training)
            mock_artifact_manager.assert_called_once_with(complete_config.firebase)
            
            assert pipeline._data_loader == mock_data_loader_instance
            assert pipeline._preprocessor == mock_preprocessor_instance
            assert pipeline._trainer == mock_trainer_instance
            assert pipeline._artifact_manager == mock_artifact_manager_instance
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.FlowPreprocessor')
    @patch('argus_v.mnemosyne.pipeline.IsolationForestTrainer')
    @patch('argus_v.mnemosyne.pipeline.ArtifactManager')
    def test_pipeline_initialization_failure(self, mock_artifact_manager, mock_trainer,
                                           mock_preprocessor, mock_data_loader, complete_config):
        """Test pipeline initialization failure."""
        # Mock first component to raise exception
        mock_data_loader.side_effect = Exception("Firebase connection failed")
        
        with pytest.raises(Exception, match="Firebase connection failed"):
            MnemosynePipeline(complete_config)
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.FlowPreprocessor')
    @patch('argus_v.mnemosyne.pipeline.IsolationForestTrainer')
    @patch('argus_v.mnemosyne.pipeline.ArtifactManager')
    @patch('argus_v.mnemosyne.data_loader.FirebaseDataLoader.load_csv_flows')
    def test_run_training_pipeline_success(self, mock_load_csv, mock_artifact_manager, mock_trainer,
                                         mock_preprocessor, mock_data_loader, complete_config, sample_training_data):
        """Test successful execution of training pipeline."""
        # Setup mocks
        mock_data_loader_instance = Mock()
        mock_data_loader_instance.list_training_csvs.return_value = ["flows/training/data1.csv"]
        mock_data_loader_instance.combine_flows.return_value = sample_training_data
        mock_data_loader_instance.delete_old_training_data.return_value = {"deleted_count": 2, "remaining_count": 1}
        
        mock_preprocessor_instance = Mock()
        mock_preprocessed_data = sample_training_data.copy()
        mock_preprocessed_data['processed'] = True
        mock_preprocessor_instance.preprocess_pipeline.return_value = (mock_preprocessed_data, {"final_rows": 3})
        mock_preprocessor_instance._scaler = Mock()
        
        mock_trainer_instance = Mock()
        mock_trainer_instance.train_model.return_value = {
            "training_samples": 2,
            "test_samples": 1,
            "feature_count": 8,
            "training_timestamp": datetime.now().isoformat()
        }
        mock_trainer_instance.serialize_model.return_value = {
            "model_path": "/tmp/model.pkl",
            "scaler_path": "/tmp/scaler.pkl",
            "metadata_path": "/tmp/metadata.json"
        }
        
        mock_artifact_manager_instance = Mock()
        mock_artifact_manager_instance.upload_model_artifacts.return_value = {
            "uploaded_files": {"model_path": {}},
            "total_size_mb": 1.5
        }
        
        mock_data_loader.return_value = mock_data_loader_instance
        mock_preprocessor.return_value = mock_preprocessor_instance
        mock_trainer.return_value = mock_trainer_instance
        mock_artifact_manager.return_value = mock_artifact_manager_instance
        
        mock_load_csv.return_value = iter([sample_training_data])
        
        with patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp', return_value='/tmp/mnemosyne_test'):
            pipeline = MnemosynePipeline(complete_config)
            
            # Run training pipeline
            stats = pipeline.run_training_pipeline(max_training_data_age_hours=168)
            
            # Verify execution steps
            mock_data_loader_instance.list_training_csvs.assert_called_once_with(max_age_hours=168)
            mock_data_loader_instance.combine_flows.assert_called_once_with(["flows/training/data1.csv"])
            mock_preprocessor_instance.preprocess_pipeline.assert_called_once_with(sample_training_data)
            mock_trainer_instance.train_model.assert_called_once_with(mock_preprocessed_data)
            mock_trainer_instance.serialize_model.assert_called_once()
            mock_artifact_manager_instance.upload_model_artifacts.assert_called_once()
            mock_data_loader_instance.delete_old_training_data.assert_called_once_with(24)
            
            # Verify stats structure
            assert 'pipeline_start' in stats
            assert 'pipeline_end' in stats
            assert 'data_loading' in stats
            assert 'preprocessing' in stats
            assert 'training' in stats
            assert 'artifact_management' in stats
            assert 'cleanup' in stats
            assert 'execution_time_seconds' in stats
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.FlowPreprocessor')
    @patch('argus_v.mnemosyne.pipeline.IsolationForestTrainer')
    @patch('argus_v.mnemosyne.pipeline.ArtifactManager')
    def test_run_training_pipeline_no_data(self, mock_artifact_manager, mock_trainer,
                                         mock_preprocessor, mock_data_loader, complete_config):
        """Test training pipeline with no training data."""
        # Setup mocks
        mock_data_loader_instance = Mock()
        mock_data_loader_instance.list_training_csvs.return_value = []
        
        mock_data_loader.return_value = mock_data_loader_instance
        
        with patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp', return_value='/tmp/mnemosyne_test'):
            pipeline = MnemosynePipeline(complete_config)
            
            # Should raise ValueError when no training data found
            with pytest.raises(ValueError, match="No training data files found"):
                pipeline.run_training_pipeline()
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.FlowPreprocessor')
    @patch('argus_v.mnemosyne.pipeline.IsolationForestTrainer')
    @patch('argus_v.mnemosyne.pipeline.ArtifactManager')
    def test_validate_setup_success(self, mock_artifact_manager, mock_trainer,
                                  mock_preprocessor, mock_data_loader, complete_config):
        """Test successful setup validation."""
        # Setup mocks
        mock_data_loader_instance = Mock()
        mock_data_loader_instance.list_training_csvs.return_value = ["flows/training/data1.csv"]
        
        mock_artifact_manager_instance = Mock()
        mock_artifact_manager_instance.list_existing_models.return_value = []
        
        mock_data_loader.return_value = mock_data_loader_instance
        mock_artifact_manager.return_value = mock_artifact_manager_instance
        
        with patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp', return_value='/tmp/mnemosyne_test'):
            pipeline = MnemosynePipeline(complete_config)
            
            validation = pipeline.validate_setup()
            
            assert validation['service_account_accessible'] is True
            assert validation['firebase_connection'] is True
            assert validation['storage_permissions'] is True
            assert validation['training_data_accessible'] is True
            assert validation['overall_status'] in ['valid', 'partial']  # Could be either depending on permissions
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp')
    def test_validate_setup_missing_service_account(self, mock_mkdtemp, mock_data_loader, complete_config):
        """Test validation with missing service account file."""
        mock_mkdtemp.return_value = '/tmp/mnemosyne_test'
        
        # Set service account path to non-existent file
        complete_config.firebase.service_account_path = "/nonexistent/path.json"
        
        pipeline = MnemosynePipeline(complete_config)
        validation = pipeline.validate_setup()
        
        assert validation['service_account_accessible'] is False
        assert validation['overall_status'] in ['invalid', 'partial']
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.ArtifactManager')
    def test_get_pipeline_status(self, mock_artifact_manager, mock_data_loader, complete_config):
        """Test getting pipeline status."""
        # Setup mocks
        mock_data_loader_instance = Mock()
        mock_artifact_manager_instance = Mock()
        
        mock_artifact_manager_instance.get_storage_usage.return_value = {
            "training_data": {"file_count": 5, "total_size_mb": 100.0},
            "models": {"file_count": 3, "total_size_mb": 50.0},
            "total_size_mb": 150.0
        }
        
        mock_artifact_manager_instance.list_existing_models.return_value = [
            {"name": "model1", "size_mb": 20.0, "last_modified": "2024-01-01T12:00:00"},
            {"name": "model2", "size_mb": 30.0, "last_modified": "2024-01-02T12:00:00"}
        ]
        
        mock_data_loader.return_value = mock_data_loader_instance
        mock_artifact_manager.return_value = mock_artifact_manager_instance
        
        with patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp', return_value='/tmp/mnemosyne_test'):
            pipeline = MnemosynePipeline(complete_config)
            
            status = pipeline.get_pipeline_status()
            
            assert 'timestamp' in status
            assert 'storage_usage' in status
            assert 'recent_models' in status
            assert 'pipeline_health' in status
            
            assert status['storage_usage']['total_size_mb'] == 150.0
            assert len(status['recent_models']) == 2
            assert status['pipeline_health'] in ['healthy', 'moderate', 'high_usage']
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.ArtifactManager')
    @patch('argus_v.mnemosyne.pipeline.shutil')
    def test_cleanup_success(self, mock_shutil, mock_artifact_manager, mock_data_loader, complete_config):
        """Test successful cleanup."""
        # Setup mocks
        mock_data_loader_instance = Mock()
        mock_artifact_manager_instance = Mock()
        
        mock_data_loader.return_value = mock_data_loader_instance
        mock_artifact_manager.return_value = mock_artifact_manager_instance
        
        with patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp', return_value='/tmp/mnemosyne_test'):
            pipeline = MnemosynePipeline(complete_config)
            
            # Mock temporary directory
            pipeline._temp_dir = Mock()
            pipeline._temp_dir.exists.return_value = True
            pipeline._temp_dir.__str__.return_value = "/tmp/mnemosyne_test"
            
            # Cleanup should not raise exception
            pipeline.cleanup()
            
            # Verify cleanup was called
            mock_shutil.rmtree.assert_called_once_with("/tmp/mnemosyne_test")
    
    def test_context_manager(self, complete_config):
        """Test pipeline as context manager."""
        with patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader'):
            with patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp', return_value='/tmp/mnemosyne_test'):
                with MnemosynePipeline(complete_config) as pipeline:
                    assert isinstance(pipeline, MnemosynePipeline)
                
                # Cleanup should be called automatically
                # (This is implicitly tested by the context manager working)
    
    @patch('argus_v.mnemosyne.pipeline.FirebaseDataLoader')
    @patch('argus_v.mnemosyne.pipeline.tempfile.mkdtemp')
    def test_pipeline_error_handling(self, mock_mkdtemp, mock_data_loader, complete_config):
        """Test error handling in pipeline execution."""
        mock_mkdtemp.return_value = '/tmp/mnemosyne_test'
        
        # Mock data loader to raise exception
        mock_data_loader.side_effect = Exception("Database connection failed")
        
        with pytest.raises(Exception, match="Database connection failed"):
            pipeline = MnemosynePipeline(complete_config)
            pipeline.run_training_pipeline()