"""Tests for daemon Firebase upload integration."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from argus_v.retina.config import (
    AggregationConfig,
    CaptureConfig,
    FirebaseConfig,
    HealthConfig,
    RetinaConfig,
)
from argus_v.retina.daemon import RetinaDaemon
from argus_v.oracle_core.anonymize import AnonymizationConfig


class TestDaemonUpload:
    """Test daemon upload functionality."""

    @pytest.fixture
    def mock_config(self, tmp_path):
        """Create a mock configuration with Firebase enabled."""
        return RetinaConfig(
            capture=CaptureConfig(interface="lo", use_scapy=False),
            aggregation=AggregationConfig(
                output_dir=tmp_path / "output",
                window_seconds=1,
            ),
            health=HealthConfig(),
            anonymization=AnonymizationConfig(ip_salt=b"test"),
            firebase=FirebaseConfig(
                enabled=True,
                bucket_name="test-bucket",
            ),
        )

    @patch("argus_v.retina.daemon.FirebaseUploader")
    @patch("argus_v.retina.daemon.FirebaseCSVStager")
    @patch("argus_v.retina.daemon.CaptureEngine")
    def test_firebase_staging_worker(
        self, mock_capture, mock_stager_cls, mock_uploader_cls, mock_config, tmp_path
    ):
        """Test that the staging worker attempts uploads."""
        # Setup mocks
        mock_uploader = MagicMock()
        mock_uploader_cls.return_value = mock_uploader

        mock_stager = MagicMock()
        mock_stager_cls.return_value = mock_stager

        # Mock files to upload
        file1 = tmp_path / "file1.csv"
        file2 = tmp_path / "file2.csv"
        mock_stager.stage_completed_files.return_value = [file1, file2]

        # Mock upload results
        mock_uploader.upload_file.side_effect = [True, False]

        # Initialize daemon
        daemon = RetinaDaemon(mock_config)

        # Start the daemon
        # We need to speed up the worker loop for testing
        with patch("time.sleep", side_effect=InterruptedError("Stop loop")):
            try:
                # We'll run the worker method directly instead of starting the thread
                # to avoid race conditions and waiting
                daemon._running = True

                # Mock initialization components
                daemon._initialize_components()

                # Inject mocks (init creates new ones)
                daemon._firebase_uploader = mock_uploader
                daemon._csv_stager = mock_stager

                # Call the worker method directly
                daemon._firebase_staging_worker()

            except InterruptedError:
                pass
            finally:
                daemon._running = False

        # Verify interactions
        assert mock_stager.stage_completed_files.called

        # Check upload calls
        assert mock_uploader.upload_file.call_count == 2
        mock_uploader.upload_file.assert_any_call(file1)
        mock_uploader.upload_file.assert_any_call(file2)

        # Check mark_uploaded calls - only for successful upload (file1)
        mock_stager.mark_uploaded.assert_called_once_with(file1)

    @patch("argus_v.retina.daemon.FirebaseUploader")
    def test_daemon_init_firebase_enabled(self, mock_uploader_cls, mock_config):
        """Test that daemon initializes uploader when enabled."""
        daemon = RetinaDaemon(mock_config)
        daemon._initialize_components()

        assert daemon._firebase_uploader is not None
        mock_uploader_cls.assert_called_once_with(
            bucket_name="test-bucket",
            credentials_path=None,
            upload_prefix="retina_logs/",
        )

    def test_daemon_init_firebase_disabled(self, tmp_path):
        """Test that daemon does not initialize uploader when disabled."""
        config = RetinaConfig(
            capture=CaptureConfig(interface="lo"),
            aggregation=AggregationConfig(output_dir=tmp_path),
            health=HealthConfig(),
            anonymization=AnonymizationConfig(ip_salt=b"test"),
            firebase=FirebaseConfig(enabled=False),
        )

        daemon = RetinaDaemon(config)

        # Mock other components to avoid side effects
        with patch("argus_v.retina.daemon.CaptureEngine"), \
             patch("argus_v.retina.daemon.InterfaceMonitor"), \
             patch("argus_v.retina.daemon.WindowAggregator"), \
             patch("argus_v.retina.daemon.PacketBatcher"), \
             patch("argus_v.retina.daemon.MythologicalCSVRotator"), \
             patch("argus_v.retina.daemon.FirebaseCSVStager"):

            daemon._initialize_components()

            assert daemon._firebase_uploader is None
