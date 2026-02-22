"""Unit tests for mnemosyne artifact manager module."""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from argus_v.mnemosyne.artifact_manager import ArtifactManager


@pytest.fixture
def artifact_config():
    """Create a mock artifact manager configuration."""
    config = Mock()
    config.project_id = "test-project"
    config.storage_bucket = "test-bucket"
    config.service_account_path = "/fake/path/service-account.json"
    config.training_data_path = "flows/training"
    config.model_output_path = "models"
    config.cleanup_threshold_hours = 24
    config.request_timeout_seconds = 30
    
    # Mock to_safe_dict method
    config.to_safe_dict.return_value = {
        "project_id": "test-project",
        "storage_bucket": "test-bucket",
        "service_account_path": "[REDACTED]",
        "training_data_path": "flows/training",
        "model_output_path": "models",
        "cleanup_threshold_hours": 24,
        "request_timeout_seconds": 30
    }
    return config


@pytest.fixture
def temp_artifact_files(tmp_path):
    """Create temporary artifact files for testing."""
    # Create test files
    model_file = tmp_path / "test_model.pkl"
    scaler_file = tmp_path / "test_scaler.pkl"
    metadata_file = tmp_path / "test_metadata.json"
    
    # Write dummy content
    model_file.write_bytes(b"mock model data")
    scaler_file.write_bytes(b"mock scaler data")
    metadata_file.write_text('{"test": "metadata"}')
    
    return {
        'model_path': str(model_file),
        'scaler_path': str(scaler_file),
        'metadata_path': str(metadata_file)
    }


class TestArtifactManager:
    """Test artifact management functionality."""
    
    @patch('argus_v.mnemosyne.artifact_manager.FIREBASE_AVAILABLE', False)
    def test_firebase_not_available(self, artifact_config):
        """Test behavior when Firebase is not available."""
        with pytest.raises(ImportError):
            ArtifactManager(artifact_config)
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_firebase_initialization(self, mock_storage, mock_firebase_admin, artifact_config):
        """Test Firebase initialization."""
        # Mock Firebase Admin SDK
        mock_cred = Mock()
        mock_app = Mock()
        mock_firebase_admin.credentials.Certificate.return_value = mock_cred
        mock_firebase_admin.initialize_app.return_value = mock_app
        
        # Mock storage client
        mock_bucket = Mock()
        mock_storage.bucket.return_value = mock_bucket
        
        manager = ArtifactManager(artifact_config)
        
        # Verify Firebase was initialized correctly
        mock_firebase_admin.credentials.Certificate.assert_called_once_with("/fake/path/service-account.json")
        mock_firebase_admin.initialize_app.assert_called_once()
        mock_storage.bucket.assert_called_once_with(
            name="test-bucket",
            app=mock_app
        )
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_upload_model_artifacts_success(self, mock_storage, mock_firebase_admin, artifact_config, temp_artifact_files):
        """Test successful upload of model artifacts."""
        # Mock Firebase setup
        mock_app = Mock()
        mock_bucket = Mock()
        mock_storage.bucket.return_value = mock_bucket
        
        # Mock blob upload
        mock_blob = Mock()
        mock_blob.upload_from_filename.return_value = None
        mock_bucket.blob.return_value = mock_blob
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                # Upload artifacts
                upload_stats = manager.upload_model_artifacts(temp_artifact_files)
                
                assert 'uploaded_files' in upload_stats
                assert 'total_size_mb' in upload_stats
                assert 'upload_timestamp' in upload_stats
                assert 'summary_remote_path' in upload_stats
                
                # Check that files were uploaded
                assert len(upload_stats['uploaded_files']) == 3  # model, scaler, metadata
                assert upload_stats['total_size_mb'] > 0
                
                # Verify blob upload was called for each file
                assert mock_bucket.blob.call_count >= 3
                assert mock_blob.upload_from_filename.call_count >= 3
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_upload_model_artifacts_missing_file(self, mock_storage, mock_firebase_admin, artifact_config):
        """Test upload with missing local file."""
        mock_app = Mock()
        mock_bucket = Mock()
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                # Try to upload non-existent file
                missing_files = {
                    'model_path': '/nonexistent/path/model.pkl'
                }
                
                with pytest.raises(FileNotFoundError):
                    manager.upload_model_artifacts(missing_files)
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_list_existing_models_success(self, mock_storage, mock_firebase_admin, artifact_config):
        """Test successful listing of existing models."""
        # Mock Firebase setup
        mock_app = Mock()
        mock_bucket = Mock()
        
        # Mock blobs representing different models
        mock_blob1 = Mock()
        mock_blob1.name = "models/20240101_120000/isolation_forest_model.pkl"
        mock_blob1.size = 1024 * 1024  # 1MB
        mock_blob1.updated = datetime.now() - timedelta(days=5)
        mock_blob1.content_type = "application/octet-stream"
        
        mock_blob2 = Mock()
        mock_blob2.name = "models/20240101_120000/model_metadata.json"
        mock_blob2.size = 1024  # 1KB
        mock_blob2.updated = datetime.now() - timedelta(days=5)
        mock_blob2.content_type = "application/json"
        
        mock_bucket.list_blobs.return_value = [mock_blob1, mock_blob2]
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                models = manager.list_existing_models()
                
                assert len(models) == 2
                assert all('name' in model for model in models)
                assert all('size_mb' in model for model in models)
                assert all('last_modified' in model for model in models)
                
                # Check sorting (newest first)
                assert models[0]['timestamp'] == '20240101_120000'
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_list_existing_models_with_age_filter(self, mock_storage, mock_firebase_admin, artifact_config):
        """Test listing models with age filter."""
        mock_app = Mock()
        mock_bucket = Mock()
        
        # Mock blobs with different ages
        old_blob = Mock()
        old_blob.name = "models/20231201_120000/old_model.pkl"
        old_blob.size = 1024 * 1024
        old_blob.updated = datetime.now() - timedelta(days=45)  # Old
        old_blob.content_type = "application/octet-stream"
        
        recent_blob = Mock()
        recent_blob.name = "models/20240101_120000/recent_model.pkl"
        recent_blob.size = 1024 * 1024
        recent_blob.updated = datetime.now() - timedelta(days=5)  # Recent
        recent_blob.content_type = "application/octet-stream"
        
        mock_bucket.list_blobs.return_value = [old_blob, recent_blob]
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                # Only show models from last 30 days
                models = manager.list_existing_models(max_age_days=30)
                
                # Should only include the recent model
                assert len(models) == 1
                assert 'recent_model' in models[0]['name']
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_cleanup_old_models(self, mock_storage, mock_firebase_admin, artifact_config):
        """Test cleanup of old model artifacts."""
        mock_app = Mock()
        mock_bucket = Mock()
        
        # Mock blobs with different ages
        old_model_blob = Mock()
        old_model_blob.name = "models/old_model.pkl"
        old_model_blob.updated = datetime.now() - timedelta(days=40)
        old_model_blob.delete.return_value = None
        
        old_metadata_blob = Mock()
        old_metadata_blob.name = "models/old_metadata.json"
        old_metadata_blob.updated = datetime.now() - timedelta(days=40)
        old_metadata_blob.delete.return_value = None
        
        recent_blob = Mock()
        recent_blob.name = "models/recent_model.pkl"
        recent_blob.updated = datetime.now() - timedelta(days=5)
        recent_blob.delete.return_value = None
        
        mock_bucket.list_blobs.return_value = [old_model_blob, old_metadata_blob, recent_blob]
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                # Clean up models older than 30 days
                cleanup_stats = manager.cleanup_old_models(max_age_days=30)
                
                assert cleanup_stats['deleted_count'] == 2
                assert cleanup_stats['remaining_count'] == 1
                
                # Verify delete was called for old models
                old_model_blob.delete.assert_called_once()
                old_metadata_blob.delete.assert_called_once()
                recent_blob.delete.assert_not_called()
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_download_model_success(self, mock_storage, mock_firebase_admin, artifact_config, tmp_path):
        """Test successful model download."""
        mock_app = Mock()
        mock_bucket = Mock()
        
        # Mock blob
        mock_blob = Mock()
        mock_blob.download_to_filename.return_value = None
        mock_bucket.blob.return_value = mock_blob
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                local_path = str(tmp_path / "downloaded_model.pkl")
                
                success = manager.download_model("models/test_model.pkl", local_path)
                
                assert success is True
                mock_bucket.blob.assert_called_once_with("models/test_model.pkl")
                mock_blob.download_to_filename.assert_called_once_with(local_path)
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_download_model_failure(self, mock_storage, mock_firebase_admin, artifact_config, tmp_path):
        """Test model download failure."""
        mock_app = Mock()
        mock_bucket = Mock()
        
        # Mock blob to raise exception
        mock_blob = Mock()
        mock_blob.download_to_filename.side_effect = Exception("Download failed")
        mock_bucket.blob.return_value = mock_blob
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                local_path = str(tmp_path / "failed_download.pkl")
                
                success = manager.download_model("models/failed_model.pkl", local_path)
                
                assert success is False
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_cleanup_training_data(self, mock_storage, mock_firebase_admin, artifact_config):
        """Test cleanup of old training data."""
        mock_app = Mock()
        mock_bucket = Mock()
        
        # Mock blobs
        old_csv_blob = Mock()
        old_csv_blob.name = "flows/training/old_data.csv"
        old_csv_blob.updated = datetime.now() - timedelta(hours=48)
        old_csv_blob.delete.return_value = None
        
        recent_csv_blob = Mock()
        recent_csv_blob.name = "flows/training/recent_data.csv"
        recent_csv_blob.updated = datetime.now() - timedelta(hours=12)
        recent_csv_blob.delete.return_value = None
        
        non_csv_blob = Mock()
        non_csv_blob.name = "flows/training/readme.txt"
        non_csv_blob.updated = datetime.now() - timedelta(hours=48)
        non_csv_blob.delete.return_value = None
        
        mock_bucket.list_blobs.return_value = [old_csv_blob, recent_csv_blob, non_csv_blob]
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                # Clean up training data older than 24 hours
                cleanup_stats = manager.cleanup_training_data(24)
                
                assert cleanup_stats['deleted_count'] == 1  # Only old CSV
                assert cleanup_stats['remaining_count'] == 2  # Recent CSV + non-CSV
                
                # Verify delete was called for old CSV
                old_csv_blob.delete.assert_called_once()
                recent_csv_blob.delete.assert_not_called()
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    @patch('argus_v.mnemosyne.artifact_manager.storage')
    def test_get_storage_usage(self, mock_storage, mock_firebase_admin, artifact_config):
        """Test storage usage calculation."""
        mock_app = Mock()
        mock_bucket = Mock()
        
        # Mock blobs for training data
        training_blob1 = Mock()
        training_blob1.name = "flows/training/data1.csv"
        training_blob1.size = 1024 * 1024  # 1MB
        
        training_blob2 = Mock()
        training_blob2.name = "flows/training/data2.csv"
        training_blob2.size = 512 * 1024  # 512KB
        
        # Mock blobs for models
        model_blob1 = Mock()
        model_blob1.name = "models/model1.pkl"
        model_blob1.size = 2048 * 1024  # 2MB
        
        model_blob2 = Mock()
        model_blob2.name = "models/metadata1.json"
        model_blob2.size = 1024  # 1KB
        
        mock_bucket.list_blobs.return_value = [training_blob1, training_blob2, model_blob1, model_blob2]
        
        with patch('argus_v.mnemosyne.artifact_manager.storage.bucket', return_value=mock_bucket):
            with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
                manager = ArtifactManager(artifact_config)
                
                usage_stats = manager.get_storage_usage()
                
                assert 'training_data' in usage_stats
                assert 'models' in usage_stats
                assert 'total_size_mb' in usage_stats
                
                # Check training data stats
                assert usage_stats['training_data']['file_count'] == 2
                assert usage_stats['training_data']['total_size_mb'] == 1.5  # 1MB + 512KB
                
                # Check model stats
                assert usage_stats['models']['file_count'] == 2
                assert usage_stats['models']['total_size_mb'] == 2.001  # 2MB + 1KB
                
                # Check total
                assert usage_stats['total_size_mb'] == 3.501  # 1.5 + 2.001
    
    @patch('argus_v.mnemosyne.artifact_manager.firebase_admin')
    def test_cleanup_on_deletion(self, mock_firebase_admin, artifact_config):
        """Test cleanup of Firebase connections on object deletion."""
        mock_app = Mock()
        mock_firebase_admin.delete_app.return_value = None
        
        with patch('argus_v.mnemosyne.artifact_manager.firebase_admin.initialize_app', return_value=mock_app):
            with patch('argus_v.mnemosyne.artifact_manager.storage.bucket'):
                manager = ArtifactManager(artifact_config)
                manager._firebase_app = mock_app
                
                # Delete the manager
                del manager
                
                # Verify Firebase app was deleted
                mock_firebase_admin.delete_app.assert_called_once_with(mock_app)