"""Unit tests for Aegis shield runtime prediction engine.

This module provides comprehensive unit tests for the PredictionEngine class
in Ulti_argus/src/argus_v/aegis/prediction_engine.py.
"""

import threading
import time
from datetime import datetime
from queue import Queue
from unittest.mock import Mock, patch

import pandas as pd
import pytest

from argus_v.aegis.blacklist_manager import BlacklistManager
from argus_v.aegis.config import PollingConfig, PredictionConfig
from argus_v.aegis.model_manager import ModelManager
from argus_v.aegis.prediction_engine import (
    CSVPollingError,
    PredictionEngine,
)
from argus_v.kronos.router import KronosDecision, KronosRouter, RoutingPath


class TestPredictionEngineUnit:
    """Unit tests for PredictionEngine class."""

    @pytest.fixture(autouse=True)
    def setup_method(self, tmp_path):
        """Set up test fixtures."""
        self.tmp_path = tmp_path
        self.csv_dir = self.tmp_path / "csv"
        self.csv_dir.mkdir()

        # Config mocks
        self.polling_config = Mock(spec=PollingConfig)
        self.polling_config.csv_directory = str(self.csv_dir)
        self.polling_config.poll_interval_seconds = 0.1
        self.polling_config.max_poll_errors = 3
        self.polling_config.batch_size = 5
        self.polling_config.poll_retry_delay = 0.1
        self.polling_config.processed_file_suffix = ".processed"

        self.prediction_config = Mock(spec=PredictionConfig)
        self.prediction_config.max_flows_per_batch = 10

        # Manager mocks
        self.model_manager = Mock(spec=ModelManager)
        self.model_manager.is_model_available.return_value = True
        self.model_manager.predict_flows.return_value = pd.DataFrame() # Default empty
        self.model_manager.explain_anomaly.return_value = ["Test Reason"]

        self.blacklist_manager = Mock(spec=BlacklistManager)
        self.blacklist_manager.is_blacklisted.return_value = False
        self.blacklist_manager.add_to_blacklist.return_value = True

        self.anonymizer = Mock()
        self.anonymizer.anonymize_ip.side_effect = lambda x: f"anon_{x}"

        self.feedback_manager = Mock()
        self.feedback_manager.is_trusted.return_value = False

        self.kronos_router = Mock(spec=KronosRouter)
        self.kronos_router.route.return_value = KronosDecision(path=RoutingPath.IF_ONLY, confidence=0.0, if_score=0.0)

        self.ipc_listener = Mock()

        # Instantiate PredictionEngine
        # We need to ensure _KRONOS_AVAILABLE is True for tests that depend on it.
        # Since it's a module level variable in prediction_engine.py, we can patch it.
        with patch('argus_v.aegis.prediction_engine._KRONOS_AVAILABLE', True):
            self.engine = PredictionEngine(
                polling_config=self.polling_config,
                prediction_config=self.prediction_config,
                model_manager=self.model_manager,
                blacklist_manager=self.blacklist_manager,
                anonymizer=self.anonymizer,
                feedback_manager=self.feedback_manager,
                kronos_router=self.kronos_router,
                ipc_listener=self.ipc_listener
            )

    def test_initialization(self):
        """Test PredictionEngine initialization."""
        # Need to patch _KRONOS_AVAILABLE during assertion if we re-instantiate or check logic
        # But self.engine was created with it True (hopefully).

        assert self.engine.polling_config == self.polling_config
        assert self.engine.prediction_config == self.prediction_config
        assert self.engine.model_manager == self.model_manager
        assert self.engine.blacklist_manager == self.blacklist_manager
        assert self.engine.anonymizer == self.anonymizer
        assert self.engine.feedback_manager == self.feedback_manager
        assert self.engine.kronos_router == self.kronos_router
        assert self.engine.ipc_listener == self.ipc_listener

        assert not self.engine._running
        assert self.engine._poll_thread is None
        assert self.engine._prediction_thread is None
        assert self.engine._ipc_thread is None
        assert isinstance(self.engine._csv_queue, Queue)
        assert len(self.engine._processed_files) == 0

        # Verify stats initialized
        stats = self.engine.get_statistics()
        assert stats['total_flows_processed'] == 0
        assert stats['poll_errors'] == 0

    def test_start_stop(self):
        """Test start and stop lifecycle."""
        stop_event = threading.Event()

        # Keep threads alive until stop called
        def run_until_stopped():
            while not stop_event.is_set():
                time.sleep(0.01)

        with patch.object(self.engine, '_poll_csv_files', side_effect=run_until_stopped), \
             patch.object(self.engine, '_process_predictions', side_effect=run_until_stopped), \
             patch.object(self.engine, '_poll_ipc_socket', side_effect=run_until_stopped):

            # Start
            started = self.engine.start()
            assert started
            assert self.engine._running

            # Verify threads started
            assert self.engine._poll_thread.is_alive()
            assert self.engine._prediction_thread.is_alive()
            assert self.engine._ipc_thread.is_alive()

            # Start again (should handle gracefully)
            assert self.engine.start()

            # Stop
            stop_event.set() # Allow threads to exit
            stopped = self.engine.stop(timeout=1)
            assert stopped
            assert not self.engine._running

            # Threads should eventually die
            self.engine._poll_thread.join(timeout=1)
            assert not self.engine._poll_thread.is_alive()

    def test_start_failure(self):
        """Test start failure handling."""
        with patch('threading.Thread', side_effect=RuntimeError("Thread error")):
            started = self.engine.start()
            assert not started
            assert not self.engine._running

    def test_stop_not_running(self):
        """Test stopping when not running."""
        assert self.engine.stop()

    def test_get_statistics(self):
        """Test statistics retrieval."""
        self.engine._stats['total_flows_processed'] = 100
        stats = self.engine.get_statistics()
        assert stats['total_flows_processed'] == 100
        assert 'csv_queue_size' in stats
        assert 'processed_files_count' in stats
        assert 'model_info' in stats
        assert 'blacklist_stats' in stats

        self.model_manager.get_model_info.assert_called_once()
        self.blacklist_manager.get_statistics.assert_called_once()

    def test_reset_stats(self):
        """Test resetting statistics."""
        self.engine._stats['total_flows_processed'] = 100
        self.engine._processing_times.append(1.5)

        self.engine._reset_stats()

        assert self.engine._stats['total_flows_processed'] == 0
        assert len(self.engine._processing_times) == 0

    def test_find_new_csv_files(self):
        """Test finding new CSV files."""
        # Create some files
        file1 = self.csv_dir / "file1.csv"
        file1.touch()
        # file2 is newer
        time.sleep(0.01)
        file2 = self.csv_dir / "file2.csv"
        file2.touch()

        # Create a processed file
        file3 = self.csv_dir / "file3.csv"
        file3.touch()
        self.engine._processed_files.add(file3.name)

        # Test finding
        files = self.engine._find_new_csv_files()

        # Should find file2 and file1, sorted by mtime descending (newest first)
        assert len(files) == 2
        assert files[0].name == "file2.csv"
        assert files[1].name == "file1.csv"

        # file3 should be ignored
        assert file3 not in files

    def test_find_new_csv_files_batch_limit(self):
        """Test finding new CSV files with batch limit."""
        self.polling_config.batch_size = 2

        for i in range(5):
            (self.csv_dir / f"file{i}.csv").touch()
            time.sleep(0.01)

        files = self.engine._find_new_csv_files()
        assert len(files) == 2

    def test_find_new_csv_files_dir_not_exists(self):
        """Test finding files when directory doesn't exist."""
        self.polling_config.csv_directory = str(self.tmp_path / "nonexistent")
        files = self.engine._find_new_csv_files()
        assert len(files) == 0

    def test_poll_csv_files_loop(self):
        """Test the polling loop behavior."""
        # We need to run the loop for one iteration then stop it.
        # We can do this by mocking _find_new_csv_files to return a file,
        # checking the queue, and then setting _running to False.

        file1 = self.csv_dir / "test.csv"

        with patch.object(self.engine, '_find_new_csv_files', return_value=[file1]):
            # Start a thread to run the loop briefly
            self.engine._running = True

            # Use a side effect on sleep to stop the loop after one iteration
            def stop_loop(*args):
                self.engine._running = False

            with patch('time.sleep', side_effect=stop_loop):
                self.engine._poll_csv_files()

            # Check if file was put in queue
            assert not self.engine._csv_queue.empty()
            item = self.engine._csv_queue.get()
            assert item == file1

    def test_poll_csv_files_error_handling(self):
        """Test error handling in polling loop."""
        self.polling_config.max_poll_errors = 2

        # Mock _find_new_csv_files to raise an exception
        with patch.object(self.engine, '_find_new_csv_files', side_effect=Exception("Poll Error")):
            self.engine._running = True

            # We want to verify it retries and eventually sleeps/backs off
            # We'll stop after enough errors

            error_counts = []

            def check_stats(*args):
                error_counts.append(self.engine._stats['poll_errors'])
                if len(error_counts) >= 3:
                    self.engine._running = False

            with patch('time.sleep', side_effect=check_stats):
                self.engine._poll_csv_files()

            # Should have incremented poll errors
            assert self.engine._stats['poll_errors'] >= 2

    def test_load_csv_data_legacy(self):
        """Test loading CSV with legacy schema."""
        file_path = self.csv_dir / "legacy.csv"
        df_content = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["8.8.8.8"],
            "src_port": [12345],
            "dst_port": [80],
            "protocol": ["TCP"],
            "bytes_in": [100],
            "bytes_out": [200],
            "packets_in": [5],
            "packets_out": [3],
            "duration": [10.5],
            "timestamp": [datetime.now()]
        })
        df_content.to_csv(file_path, index=False)

        df = self.engine._load_csv_data(file_path)

        assert len(df) == 1
        assert df.iloc[0]["src_ip"] == "192.168.1.1"
        assert df.iloc[0]["bytes_in"] == 100

    def test_load_csv_data_retina(self):
        """Test loading CSV with Retina schema."""
        file_path = self.csv_dir / "retina.csv"
        df_content = pd.DataFrame({
            "src_ip_anon": ["10.0.0.1"],
            "dst_ip_anon": ["1.1.1.1"],
            "src_flow_bytes": [1000],
            "dst_flow_bytes": [2000],
            "src_flow_packets": [10],
            "dst_flow_packets": [20],
            "duration_seconds": [5.0],
            "timestamp": [datetime.now()]
        })
        df_content.to_csv(file_path, index=False)

        df = self.engine._load_csv_data(file_path)

        assert len(df) == 1
        # Check mapping
        assert df.iloc[0]["src_ip"] == "10.0.0.1"
        assert df.iloc[0]["bytes_in"] == 1000
        assert df.iloc[0]["packets_out"] == 20

    def test_clean_flow_data_missing_columns(self):
        """Test cleaning flow data with missing columns."""
        df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            # Missing dst_ip, bytes_in, etc.
        })

        # The current implementation logs missing columns but does not raise an exception.
        # It proceeds to clean what it can.
        cleaned = self.engine._clean_flow_data(df)
        assert len(cleaned) == 1
        assert "src_ip" in cleaned.columns

    def test_clean_flow_data_normalization(self):
        """Test normalization of flow data."""
        # Test filling missing numeric columns with 0
        df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["8.8.8.8"],
            "bytes_in": [100],
            "bytes_out": [200],
            # Missing packets_in, packets_out
            "timestamp": [datetime.now()]
        })

        cleaned = self.engine._clean_flow_data(df)
        assert len(cleaned) == 1
        assert cleaned.iloc[0]["packets_in"] == 0
        assert cleaned.iloc[0]["packets_out"] == 0

    def test_clean_flow_data_anonymization(self):
        """Test anonymization of IP addresses."""
        df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["8.8.8.8"],
            "bytes_in": [100],
            "bytes_out": [200],
            "timestamp": [datetime.now()]
        })

        cleaned = self.engine._clean_flow_data(df)

        assert "src_ip_hash" in cleaned.columns
        assert cleaned.iloc[0]["src_ip_hash"] == "anon_192.168.1.1"

    def test_load_csv_data_empty(self):
        """Test loading empty CSV file."""
        file_path = self.csv_dir / "empty.csv"
        file_path.touch()

        # The implementation explicitly checks file size and returns empty DataFrame
        df = self.engine._load_csv_data(file_path)
        assert df.empty

    def test_load_csv_data_corrupt(self):
        """Test loading corrupt CSV file."""
        file_path = self.csv_dir / "corrupt.csv"
        file_path.write_text("invalid,csv,content")

        # Depending on how it's parsed, might raise or return empty/malformed df
        # If headers are missing or mismatched

        with pytest.raises(CSVPollingError):
             # Force a pandas error by writing garbage that can't be parsed with expected dtypes potentially?
             # Actually, single line "invalid,csv,content" might be parsed as header.
             # Let's write something that causes type error or parse error if possible.
             # But read_csv is quite lenient.

             # Instead, let's mock pd.read_csv to raise exception
             with patch('pandas.read_csv', side_effect=Exception("Corrupt")):
                 self.engine._load_csv_data(file_path)

    def test_process_predictions_queue(self):
        """Test processing predictions from queue."""
        file1 = self.csv_dir / "test.csv"

        # We need to put file in queue, mock _process_csv_file, and run loop briefly
        self.engine._csv_queue.put(file1)
        self.engine._running = True

        with patch.object(self.engine, '_process_csv_file', return_value=True) as mock_process:
            # Stop loop after queue is empty
            def check_queue(*args):
                if self.engine._csv_queue.empty():
                    self.engine._running = False
                # Call task_done if get was called, but here we are in the loop.
                # The loop calls task_done.

            # Since get blocks with timeout, we just let it run one iteration essentially
            # We can mock get to return item then raise Empty to exit loop?
            # Or use side_effect on queue.get?
            # Or just let the loop run and mock `self.engine._running` to switch off.

            # Better: mock process_csv_file to set running to false
            def process_and_stop(f):
                self.engine._running = False
                return True

            mock_process.side_effect = process_and_stop

            self.engine._process_predictions()

            mock_process.assert_called_with(file1)
            assert self.engine._stats['csv_files_processed'] == 1
            assert file1.name in self.engine._processed_files

    def test_process_batch_predictions_kronos_pass(self):
        """Test batch predictions with Kronos PASS decision."""
        predictions_df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["8.8.8.8"],
            "prediction": [-1], # Anomaly detected by IF
            "anomaly_score": [0.8],
            "risk_level": ["high"],
            "protocol": ["TCP"],
            "dst_port": [80],
            "bytes_in": [100],
            "bytes_out": [100],
            "src_port": [12345]
        })

        # Mock Kronos to PASS
        self.kronos_router.route.return_value = KronosDecision(path=RoutingPath.PASS, confidence=1.0, if_score=0.8)

        self.engine._process_batch_predictions(predictions_df)

        # Should skip enforcement
        self.blacklist_manager.add_to_blacklist.assert_not_called()
        # Anomaly stats should NOT be incremented because we skipped it?
        # Looking at code: "continue" inside loop means we skip everything including stats update.
        assert self.engine._stats['anomalies_detected'] == 0

    def test_process_batch_predictions_kronos_escalate_safe(self):
        """Test batch predictions with Kronos ESCALATE -> CNN Safe."""
        predictions_df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["8.8.8.8"],
            "prediction": [-1], # Anomaly
            "anomaly_score": [0.8],
            "risk_level": ["high"],
            "protocol": ["TCP"],
            "dst_port": [80],
            "bytes_in": [100],
            "bytes_out": [100],
            "src_port": [12345],
            "__raw_payload__": [b"some payload"]
        })

        self.kronos_router.route.return_value = KronosDecision(path=RoutingPath.ESCALATE, confidence=0.5, if_score=0.8)

        # Mock analyze_payload. Use create=True to handle case where it wasn't imported.
        with patch('argus_v.aegis.prediction_engine.analyze_payload', return_value=0.1, create=True) as mock_cnn:
            self.engine._process_batch_predictions(predictions_df)

            mock_cnn.assert_called_once()
            # Should suppress anomaly
            self.blacklist_manager.add_to_blacklist.assert_not_called()
            assert self.engine._stats['anomalies_detected'] == 0

    def test_process_batch_predictions_kronos_escalate_malicious(self):
        """Test batch predictions with Kronos ESCALATE -> CNN Malicious."""
        predictions_df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["8.8.8.8"],
            "prediction": [1], # Normal initially
            "anomaly_score": [0.4],
            "risk_level": ["low"],
            "protocol": ["TCP"],
            "dst_port": [80],
            "bytes_in": [100],
            "bytes_out": [100],
            "src_port": [12345],
            "__raw_payload__": [b"malicious"]
        })

        self.kronos_router.route.return_value = KronosDecision(path=RoutingPath.ESCALATE, confidence=0.5, if_score=0.4)

        # Mock analyze_payload to return high score. Use create=True.
        with patch('argus_v.aegis.prediction_engine.analyze_payload', return_value=0.8, create=True) as mock_cnn:
            self.engine._process_batch_predictions(predictions_df)

            # Should force anomaly (-1) and trigger enforcement
            self.blacklist_manager.add_to_blacklist.assert_called()
            assert self.engine._stats['anomalies_detected'] == 1

    def test_process_batch_predictions_trusted_ip(self):
        """Test batch predictions with Trusted IP."""
        predictions_df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["8.8.8.8"],
            "prediction": [-1],
            "anomaly_score": [0.9],
            "risk_level": ["critical"]
        })

        # Mock Kronos to IF_ONLY
        self.kronos_router.route.return_value = KronosDecision(path=RoutingPath.IF_ONLY, confidence=0.0, if_score=0.9)

        # Mock feedback manager to trust IP
        self.feedback_manager.is_trusted.return_value = True

        self.engine._process_batch_predictions(predictions_df)

        # Should be suppressed
        self.blacklist_manager.add_to_blacklist.assert_not_called()
        assert self.engine._stats['anomalies_detected'] == 0

    def test_process_batch_predictions_blacklist_check(self):
        """Test batch predictions where IP is already blacklisted."""
        predictions_df = pd.DataFrame({
            "src_ip": ["1.2.3.4"],
            "dst_ip": ["8.8.8.8"],
            "prediction": [1], # Normal flow
            "anomaly_score": [0.1],
            "risk_level": ["low"]
        })

        self.kronos_router.route.return_value = KronosDecision(path=RoutingPath.IF_ONLY, confidence=0.0, if_score=0.1)
        self.feedback_manager.is_trusted.return_value = False

        # Mock blacklist manager to say it IS blacklisted
        self.blacklist_manager.is_blacklisted.side_effect = lambda ip: ip == "1.2.3.4"

        self.engine._process_batch_predictions(predictions_df)

        # Should re-add/update blacklist entry because it was detected as blacklisted
        self.blacklist_manager.add_to_blacklist.assert_called()
        # Not an anomaly though
        assert self.engine._stats['anomalies_detected'] == 0

    def test_process_batch_predictions_enforcement(self):
        """Test normal enforcement of anomaly."""
        predictions_df = pd.DataFrame({
            "src_ip": ["10.0.0.5"],
            "dst_ip": ["8.8.8.8"],
            "prediction": [-1],
            "anomaly_score": [0.85],
            "risk_level": ["high"],
            "src_port": [1234],
            "dst_port": [80],
            "protocol": ["TCP"],
            "bytes_in": [500],
            "bytes_out": [500]
        })

        self.kronos_router.route.return_value = KronosDecision(path=RoutingPath.IF_ONLY, confidence=0.0, if_score=0.85)
        self.feedback_manager.is_trusted.return_value = False
        self.blacklist_manager.is_blacklisted.return_value = False

        self.engine._process_batch_predictions(predictions_df)

        self.blacklist_manager.add_to_blacklist.assert_called_once()
        args, kwargs = self.blacklist_manager.add_to_blacklist.call_args
        assert kwargs['ip_address'] == "10.0.0.5"
        assert kwargs['risk_level'] == "high"
        assert kwargs['source'] == "prediction"
        assert self.engine._stats['anomalies_detected'] == 1
        assert self.engine._stats['blacklist_additions'] == 1

    def test_poll_ipc_socket(self):
        """Test IPC socket polling."""
        # Create a mock frame
        mock_frame = Mock()
        mock_frame.src_ip = "192.168.1.1"
        mock_frame.dst_ip = "8.8.8.8"
        mock_frame.src_port = 12345
        mock_frame.dst_port = 80
        mock_frame.protocol = "TCP"
        mock_frame.bytes_in = 100
        mock_frame.bytes_out = 200
        mock_frame.duration = 1.5
        mock_frame.payload = b"payload"

        # Setup ipc_listener mock to return frame once then loop break
        # We need to break the loop.
        # We can use side_effect on ipc_listener.get_frame to return frame then raise Exception to stop loop
        # But loop catches Exception and sleeps.
        # So better to use a side effect that sets running=False.

        def get_frame_side_effect(timeout):
            if self.engine._running:
                self.engine._running = False # Stop after this
                return mock_frame
            return None

        self.ipc_listener.get_frame.side_effect = get_frame_side_effect
        self.engine._running = True

        # Mock model prediction
        self.model_manager.predict_flows.return_value = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "prediction": [1],
            "anomaly_score": [0.0]
        })

        with patch.object(self.engine, '_process_batch_predictions') as mock_process:
            self.engine._poll_ipc_socket()

            mock_process.assert_called_once()
            # Verify payload was passed
            call_args = mock_process.call_args[0][0]
            assert '__raw_payload__' in call_args.columns
            assert call_args.iloc[0]['__raw_payload__'] == b"payload"

    def test_poll_ipc_socket_timeout(self):
        """Test IPC socket polling timeout."""
        # Mock timeout (return None)
        def get_frame_side_effect(timeout):
            self.engine._running = False
            return None

        self.ipc_listener.get_frame.side_effect = get_frame_side_effect
        self.engine._running = True

        with patch.object(self.engine, '_process_batch_predictions') as mock_process:
            self.engine._poll_ipc_socket()

            mock_process.assert_not_called()

    def test_poll_ipc_socket_error(self):
        """Test IPC socket polling error."""
        # Raise exception
        def get_frame_side_effect(timeout):
            self.engine._running = False
            raise RuntimeError("Socket error")

        self.ipc_listener.get_frame.side_effect = get_frame_side_effect
        self.engine._running = True

        with patch('time.sleep') as mock_sleep:
             self.engine._poll_ipc_socket()
             mock_sleep.assert_called()
