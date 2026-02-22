"""Tests for Firebase uploader."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add src to path if needed
root = Path(__file__).resolve().parents[2]
src = root / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))

from argus_v.hermes.uploader import FirebaseUploader


class TestFirebaseUploader:
    """Test cases for FirebaseUploader."""

    @patch("argus_v.hermes.uploader.firebase_admin")
    @patch("argus_v.hermes.uploader.storage")
    def test_initialization_default(self, mock_storage, mock_firebase):
        """Test initialization with default credentials."""
        # Mock bucket
        mock_bucket = MagicMock()
        mock_storage.bucket.return_value = mock_bucket

        # Mock app initialization (not raising ValueError)
        mock_firebase.get_app.side_effect = ValueError

        uploader = FirebaseUploader(bucket_name="test-bucket")

        # Verify app initialized
        mock_firebase.initialize_app.assert_called_once()
        mock_storage.bucket.assert_called_with("test-bucket")
        assert uploader._bucket == mock_bucket

    @patch("argus_v.hermes.uploader.firebase_admin")
    @patch("argus_v.hermes.uploader.storage")
    @patch("argus_v.hermes.uploader.credentials")
    def test_initialization_with_credentials(self, mock_creds, mock_storage, mock_firebase):
        """Test initialization with credentials file."""
        mock_firebase.get_app.side_effect = ValueError

        uploader = FirebaseUploader(
            bucket_name="test-bucket",
            credentials_path="/path/to/creds.json"
        )

        mock_creds.Certificate.assert_called_with("/path/to/creds.json")
        mock_firebase.initialize_app.assert_called_once()

    @patch("argus_v.hermes.uploader.firebase_admin")
    @patch("argus_v.hermes.uploader.storage")
    def test_initialization_already_initialized(self, mock_storage, mock_firebase):
        """Test initialization when app is already initialized."""
        # Mock app already exists (no ValueError)
        mock_firebase.get_app.return_value = MagicMock()

        uploader = FirebaseUploader(bucket_name="test-bucket")

        # Should not call initialize_app
        mock_firebase.initialize_app.assert_not_called()

    @patch("argus_v.hermes.uploader.firebase_admin")
    @patch("argus_v.hermes.uploader.storage")
    def test_upload_success(self, mock_storage, mock_firebase, tmp_path):
        """Test successful file upload."""
        # Setup mocks
        mock_bucket = MagicMock()
        mock_storage.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob

        # Create test file
        test_file = tmp_path / "test_log.csv"
        test_file.write_text("test data")

        uploader = FirebaseUploader(bucket_name="test-bucket", upload_prefix="logs/")
        result = uploader.upload_file(test_file)

        assert result is True
        mock_bucket.blob.assert_called_with("logs/test_log.csv")
        mock_blob.upload_from_filename.assert_called_with(str(test_file))

    @patch("argus_v.hermes.uploader.firebase_admin")
    @patch("argus_v.hermes.uploader.storage")
    def test_upload_file_not_found(self, mock_storage, mock_firebase, tmp_path):
        """Test upload with non-existent file."""
        uploader = FirebaseUploader(bucket_name="test-bucket")

        non_existent = tmp_path / "ghost.csv"
        result = uploader.upload_file(non_existent)

        assert result is False
        mock_storage.bucket.return_value.blob.assert_not_called()

    @patch("argus_v.hermes.uploader.firebase_admin")
    @patch("argus_v.hermes.uploader.storage")
    def test_upload_exception(self, mock_storage, mock_firebase, tmp_path):
        """Test handling of upload exceptions."""
        mock_bucket = MagicMock()
        mock_storage.bucket.return_value = mock_bucket
        mock_blob = MagicMock()
        mock_bucket.blob.return_value = mock_blob
        mock_blob.upload_from_filename.side_effect = Exception("Upload failed")

        test_file = tmp_path / "test_log.csv"
        test_file.write_text("test data")

        uploader = FirebaseUploader(bucket_name="test-bucket")
        result = uploader.upload_file(test_file)

        assert result is False
