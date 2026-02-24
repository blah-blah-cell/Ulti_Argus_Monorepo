"""Unit tests for mnemosyne data loading module."""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pandas as pd
import pytest

from argus_v.mnemosyne.data_loader import FirebaseDataLoader


@pytest.fixture
def firebase_config():
    """Create a mock Firebase configuration."""
    config = Mock()
    config.project_id = "test-project"
    config.storage_bucket = "test-bucket"
    config.service_account_path = "/fake/path/service-account.json"
    config.training_data_path = "flows/training"
    config.model_output_path = "models"
    config.cleanup_threshold_hours = 24
    config.request_timeout_seconds = 30
    return config


@pytest.fixture
def sample_flow_data():
    """Create sample flow data for testing."""
    data = {
        'timestamp': [
            datetime(2024, 1, 1, 10, 0, 0),
            datetime(2024, 1, 1, 10, 1, 0),
            datetime(2024, 1, 1, 10, 2, 0)
        ],
        'src_ip': ['192.168.1.1', '192.168.1.2', '10.0.0.1'],
        'dst_ip': ['192.168.1.2', '192.168.1.3', '10.0.0.2'],
        'src_port': [80, 443, 22],
        'dst_port': [12345, 80, 443],
        'protocol': ['TCP', 'TCP', 'UDP'],
        'bytes_in': [1000, 2048, 500],
        'bytes_out': [500, 1024, 200],
        'packets_in': [10, 20, 5],
        'packets_out': [5, 15, 3],
        'duration': [1.5, 2.3, 0.8]
    }
    return pd.DataFrame(data)


class TestFirebaseDataLoader:
    """Test Firebase data loading functionality."""
    
    @patch('argus_v.mnemosyne.data_loader.FIREBASE_AVAILABLE', False)
    def test_firebase_not_available(self, firebase_config):
        """Test behavior when Firebase is not available."""
        with pytest.raises(ImportError):
            FirebaseDataLoader(firebase_config)
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    def test_firebase_initialization(self, mock_storage, mock_credentials, mock_firebase_admin, firebase_config):
        """Test Firebase initialization."""
        # Mock Firebase Admin SDK
        mock_cred = Mock()
        mock_app = Mock()
        mock_credentials.Certificate.return_value = mock_cred
        mock_firebase_admin.initialize_app.return_value = mock_app
        
        # Mock storage client
        mock_bucket = Mock()
        mock_storage.bucket.return_value = mock_bucket
        
        FirebaseDataLoader(firebase_config)
        
        # Verify Firebase was initialized correctly
        mock_credentials.Certificate.assert_called_once_with("/fake/path/service-account.json")
        mock_firebase_admin.initialize_app.assert_called_once()
        mock_storage.bucket.assert_called_once_with(
            name="test-bucket",
            app=mock_app
        )
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    def test_list_training_csvs_no_files(self, mock_storage, mock_credentials, mock_firebase_admin, firebase_config):
        """Test listing training CSV files when none exist."""
        mock_credentials.Certificate.return_value = Mock()
        # Mock storage bucket
        mock_bucket = Mock()
        mock_blob = Mock()
        mock_blob.name = "flows/training/test.csv"
        mock_blob.updated = datetime.now()
        mock_bucket.list_blobs.return_value = [mock_blob]
        
        with patch('argus_v.mnemosyne.data_loader.storage.bucket', return_value=mock_bucket):
            loader = FirebaseDataLoader(firebase_config)
            files = loader.list_training_csvs()
            
            assert len(files) == 1
            assert files[0] == "flows/training/test.csv"
            mock_bucket.list_blobs.assert_called_once_with(prefix="flows/training/")
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    def test_list_training_csvs_with_age_filter(self, mock_storage, mock_credentials, mock_firebase_admin, firebase_config):
        """Test listing training CSV files with age filter."""
        mock_credentials.Certificate.return_value = Mock()
        mock_bucket = Mock()
        
        # Create mock blobs with different ages
        old_blob = Mock()
        old_blob.name = "flows/training/old.csv"
        old_blob.updated = datetime.now() - timedelta(hours=48)
        
        new_blob = Mock()
        new_blob.name = "flows/training/new.csv"
        new_blob.updated = datetime.now() - timedelta(hours=12)
        
        mock_bucket.list_blobs.return_value = [old_blob, new_blob]
        
        with patch('argus_v.mnemosyne.data_loader.storage.bucket', return_value=mock_bucket):
            loader = FirebaseDataLoader(firebase_config)
            files = loader.list_training_csvs(max_age_hours=24)
            
            # Should only include the newer file
            assert len(files) == 1
            assert files[0] == "flows/training/new.csv"
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    @patch('pandas.read_csv')
    def test_load_csv_flows_success(self, mock_read_csv, mock_storage, mock_credentials, mock_firebase_admin, firebase_config, sample_flow_data):
        """Test successful loading of CSV flows."""
        mock_credentials.Certificate.return_value = Mock()
        mock_read_csv.return_value = sample_flow_data
        
        mock_bucket = Mock()
        mock_blob = Mock()
        mock_blob.download_to_filename.return_value = None
        mock_bucket.blob.return_value = mock_blob
        
        with patch('argus_v.mnemosyne.data_loader.storage.bucket', return_value=mock_bucket):
            loader = FirebaseDataLoader(firebase_config)
            dataframes = list(loader.load_csv_flows(["flows/training/test.csv"]))

            assert len(dataframes) == 1
            assert len(dataframes[0]) == 3  # 3 rows
            assert list(dataframes[0].columns) == list(sample_flow_data.columns)
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    @patch('pandas.read_csv')
    def test_load_csv_flows_missing_columns(self, mock_read_csv, mock_storage, mock_credentials, mock_firebase_admin, firebase_config):
        """Test CSV loading with missing columns."""
        mock_credentials.Certificate.return_value = Mock()
        # Create data with missing columns
        incomplete_data = {
            'timestamp': [datetime.now()],
            'src_ip': ['1.1.1.1'],
            'dst_ip': ['2.2.2.2'],
            'src_port': [80],
            'dst_port': [12345],
            'protocol': ['TCP'],
            # 'bytes_in' is missing
            'bytes_out': [500],
            'packets_in': [10],
            'packets_out': [5],
            'duration': [1.5]
        }
        mock_read_csv.return_value = pd.DataFrame(incomplete_data)
        
        mock_bucket = Mock()
        mock_blob = Mock()
        mock_bucket.blob.return_value = mock_blob
        
        with patch('argus_v.mnemosyne.data_loader.storage.bucket', return_value=mock_bucket):
            loader = FirebaseDataLoader(firebase_config)
            dataframes = list(loader.load_csv_flows(["flows/training/test.csv"]))

            # Should return empty list due to missing columns
            assert len(dataframes) == 0
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    @patch('pandas.read_csv')
    def test_load_csv_flows_with_invalid_data(self, mock_read_csv, mock_storage, mock_credentials, mock_firebase_admin, firebase_config):
        """Test CSV loading with invalid data."""
        mock_credentials.Certificate.return_value = Mock()
        # Create data with NaN and negative values
        data = {
            'timestamp': [datetime.now(), datetime.now(), datetime.now()],
            'src_ip': ['1.1.1.1', '1.1.1.2', '1.1.1.3'],
            'dst_ip': ['2.2.2.1', '2.2.2.2', '2.2.2.3'],
            'src_port': [80, 80, 80],
            'dst_port': [12345, 12346, 12347],
            'protocol': ['TCP', 'TCP', 'TCP'],
            'bytes_in': [-100, None, 500], # Negative, NaN, Valid
            'bytes_out': [500, 500, 500],
            'packets_in': [10, 10, 10],
            'packets_out': [5, 5, 5],
            'duration': [1.5, 1.5, 1.5]
        }
        mock_read_csv.return_value = pd.DataFrame(data)
        
        mock_bucket = Mock()
        mock_blob = Mock()
        mock_bucket.blob.return_value = mock_blob
        
        with patch('argus_v.mnemosyne.data_loader.storage.bucket', return_value=mock_bucket):
            loader = FirebaseDataLoader(firebase_config)
            dataframes = list(loader.load_csv_flows(["flows/training/test.csv"]))

            # Should return DataFrame with invalid rows removed
            assert len(dataframes) == 1
            assert len(dataframes[0]) == 1  # Only valid row remains
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    @patch('argus_v.mnemosyne.data_loader.FirebaseDataLoader.load_csv_flows')
    def test_combine_flows_success(self, mock_load_csv, mock_storage, mock_credentials, mock_firebase_admin, firebase_config, sample_flow_data):
        """Test successful combination of flow data."""
        mock_credentials.Certificate.return_value = Mock()
        # Mock two identical DataFrames
        mock_load_csv.return_value = iter([
            sample_flow_data,
            sample_flow_data
        ])
        
        with patch('argus_v.mnemosyne.data_loader.storage.bucket'):
            loader = FirebaseDataLoader(firebase_config)
            combined_df = loader.combine_flows(["file1.csv", "file2.csv"])
            
            assert len(combined_df) == 3  # Duplicates removed
            assert list(combined_df.columns) == list(sample_flow_data.columns)
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    @patch('argus_v.mnemosyne.data_loader.FirebaseDataLoader.load_csv_flows')
    def test_combine_flows_no_valid_data(self, mock_load_csv, mock_storage, mock_credentials, mock_firebase_admin, firebase_config):
        """Test combining flows when no valid data is found."""
        mock_credentials.Certificate.return_value = Mock()
        mock_load_csv.return_value = iter([])  # Empty iterator
        
        with patch('argus_v.mnemosyne.data_loader.storage.bucket'):
            loader = FirebaseDataLoader(firebase_config)
            
            with pytest.raises(ValueError, match="No valid flow data found"):
                loader.combine_flows(["empty.csv"])
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    @patch('argus_v.mnemosyne.data_loader.storage')
    def test_delete_old_training_data(self, mock_storage, mock_credentials, mock_firebase_admin, firebase_config):
        """Test deletion of old training data."""
        mock_credentials.Certificate.return_value = Mock()
        mock_bucket = Mock()
        
        # Create mock blobs
        old_blob = Mock()
        old_blob.name = "flows/training/old.csv"
        old_blob.updated = datetime.now() - timedelta(hours=48)
        old_blob.delete.return_value = None
        
        recent_blob = Mock()
        recent_blob.name = "flows/training/recent.csv"
        recent_blob.updated = datetime.now() - timedelta(hours=12)
        recent_blob.delete.return_value = None
        
        mock_bucket.list_blobs.return_value = [old_blob, recent_blob]
        
        with patch('argus_v.mnemosyne.data_loader.storage.bucket', return_value=mock_bucket):
            loader = FirebaseDataLoader(firebase_config)
            stats = loader.delete_old_training_data(24)
            
            assert stats["deleted_count"] == 1
            assert stats["remaining_count"] == 1
            old_blob.delete.assert_called_once()
            recent_blob.delete.assert_not_called()
    
    @patch('argus_v.mnemosyne.data_loader.firebase_admin')
    @patch('argus_v.mnemosyne.data_loader.credentials')
    def test_cleanup_on_deletion(self, mock_credentials, mock_firebase_admin, firebase_config):
        """Test cleanup of Firebase connections on object deletion."""
        mock_app = Mock()
        mock_firebase_admin.delete_app.return_value = None
        mock_credentials.Certificate.return_value = Mock()
        
        with patch('argus_v.mnemosyne.data_loader.firebase_admin.initialize_app', return_value=mock_app):
            with patch('argus_v.mnemosyne.data_loader.storage.bucket'):
                loader = FirebaseDataLoader(firebase_config)
                loader._firebase_app = mock_app
                
                # Delete the loader
                del loader
                
                # Verify Firebase app was deleted
                mock_firebase_admin.delete_app.assert_called_once_with(mock_app)