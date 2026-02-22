
import pytest
import os
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock, call, ANY

# Ensure src is in path for imports to work
sys.path.append(os.path.join(os.path.dirname(__file__), "../../../src"))

# Mock external dependencies that might be missing in the test environment
# This must be done BEFORE importing modules from argus_v that rely on them
for module in ['yaml', 'scapy', 'pandas', 'numpy', 'sklearn', 'skops', 'firebase_admin']:
    sys.modules[module] = MagicMock()

# Also mock submodules if necessary
sys.modules['scapy.all'] = MagicMock()
sys.modules['sklearn.ensemble'] = MagicMock()
sys.modules['sklearn.preprocessing'] = MagicMock()

from argus_v.aegis.daemon import (
    AegisDaemon,
    ServiceStartError,
    ServiceStopError,
    _KRONOS_AVAILABLE
)
from argus_v.aegis.config import (
    AegisConfig,
    ModelConfig,
    PollingConfig,
    PredictionConfig,
    EnforcementConfig
)

# Mocking external dependencies
@pytest.fixture
def mock_dependencies():
    with patch("argus_v.aegis.daemon.load_aegis_config") as mock_load_config, \
         patch("argus_v.aegis.daemon.configure_logging") as mock_configure_logging, \
         patch("argus_v.aegis.daemon.log_event") as mock_log_event, \
         patch("argus_v.aegis.daemon.ModelManager") as mock_model_manager, \
         patch("argus_v.aegis.daemon.BlacklistManager") as mock_blacklist_manager, \
         patch("argus_v.aegis.daemon.PredictionEngine") as mock_prediction_engine, \
         patch("argus_v.aegis.daemon.FeedbackManager") as mock_feedback_manager, \
         patch("argus_v.oracle_core.anonymize.HashAnonymizer") as mock_anonymizer:

        yield {
            "load_config": mock_load_config,
            "configure_logging": mock_configure_logging,
            "log_event": mock_log_event,
            "model_manager": mock_model_manager,
            "blacklist_manager": mock_blacklist_manager,
            "prediction_engine": mock_prediction_engine,
            "feedback_manager": mock_feedback_manager,
            "anonymizer": mock_anonymizer
        }

@pytest.fixture
def mock_config():
    model_config = ModelConfig(
        model_local_path="/tmp/argus/models",
        scaler_local_path="/tmp/argus/scalers",
        foundation_model_path="/tmp/argus/foundation/model.pkl",
        foundation_scaler_path="/tmp/argus/foundation/scaler.pkl"
    )
    polling_config = PollingConfig(
        csv_directory="/tmp/argus/retina/csv"
    )
    prediction_config = PredictionConfig()
    enforcement_config = EnforcementConfig(
        dry_run_duration_days=7,
        emergency_stop_file="/tmp/argus/emergency",
        blacklist_db_path="/tmp/argus/blacklist.db",
        blacklist_json_path="/tmp/argus/blacklist.json",
        feedback_dir="/tmp/argus/feedback",
        retrain_flag_file="/tmp/argus/retrain",
        anonymization_salt="test_salt"
    )

    config = AegisConfig(
        model=model_config,
        polling=polling_config,
        prediction=prediction_config,
        enforcement=enforcement_config,
        anonymization_salt="test_salt",
        state_file="/tmp/argus/state.json",
        stats_file="/tmp/argus/stats.json",
        pid_file="/tmp/argus/aegis.pid"
    )
    return config

@pytest.fixture
def daemon(mock_dependencies, mock_config):
    mock_dependencies["load_config"].return_value = mock_config
    return AegisDaemon("config.yaml")

class TestAegisDaemonInitialization:
    def test_initialization_success(self, daemon, mock_dependencies, mock_config):
        """Test successful initialization of AegisDaemon."""
        assert daemon.config == mock_config
        assert daemon._running is False
        assert daemon._start_time is None
        assert daemon._components == {
            'anonymizer': None,
            'model_manager': None,
            'blacklist_manager': None,
            'prediction_engine': None
        }

        mock_dependencies["configure_logging"].assert_called_once()
        mock_dependencies["log_event"].assert_any_call(
            ANY,
            "aegis_daemon_initialized",
            level="info",
            config_summary=mock_config.to_safe_dict()
        )

    def test_initialization_config_validation_failure(self, mock_dependencies, mock_config):
        """Test initialization with configuration issues."""
        with patch("pathlib.Path.exists", return_value=False), \
             patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied")):

            mock_dependencies["load_config"].return_value = mock_config

            # Should still initialize but log warnings
            daemon = AegisDaemon("config.yaml")

            assert len(daemon._stats['configuration_issues']) > 0
            mock_dependencies["log_event"].assert_any_call(
                ANY,
                "configuration_issues_detected",
                level="warning",
                issues=ANY
            )

    def test_initialization_failure(self, mock_dependencies, mock_config):
        """Test initialization failure when component init raises exception."""
        mock_dependencies["load_config"].return_value = mock_config

        # We patch a method that is called during initialization to raise an exception.
        # Since _validate_configuration catches exceptions, let's target _validate_configuration itself
        # or anything else inside _initialize_components.
        # But wait, _validate_configuration is called inside _initialize_components inside a try-except block
        # that catches Exception and raises ServiceStartError.

        # Let's mock _validate_configuration to raise an Exception directly.
        # We need to do this on the class before instantiation or on the instance.
        # Since we are testing __init__, we have to patch on the class or use a context manager before creating the instance.

        with patch.object(AegisDaemon, "_validate_configuration", side_effect=Exception("Critical Init Error")):
             with pytest.raises(ServiceStartError) as excinfo:
                AegisDaemon("config.yaml")
             assert "Component initialization failed" in str(excinfo.value)

class TestAegisDaemonStartStop:
    def test_start_success(self, daemon, mock_dependencies):
        """Test successful start of the daemon."""
        # Setup mocks for start
        mock_model_manager_instance = mock_dependencies["model_manager"].return_value
        mock_model_manager_instance.load_latest_model.return_value = True

        mock_prediction_engine_instance = mock_dependencies["prediction_engine"].return_value
        mock_prediction_engine_instance.start.return_value = True

        with patch("threading.Thread") as mock_thread:
            assert daemon.start() is True

        assert daemon._running is True
        assert daemon._start_time is not None
        assert daemon._components['anonymizer'] is not None
        assert daemon._components['model_manager'] is not None
        assert daemon._components['blacklist_manager'] is not None
        assert daemon._components['prediction_engine'] is not None
        assert daemon._components['feedback_manager'] is not None

        mock_thread.assert_called_once()
        mock_thread.return_value.start.assert_called_once()

        mock_dependencies["log_event"].assert_any_call(
            ANY,
            "aegis_daemon_started",
            level="info",
            dry_run_duration_days=ANY,
            dry_run_end_time=ANY,
            components=ANY
        )

    def test_start_already_running(self, daemon, mock_dependencies):
        """Test start when already running."""
        daemon._running = True
        assert daemon.start() is True
        mock_dependencies["log_event"].assert_any_call(
            ANY, "aegis_daemon_already_running", level="warning"
        )

    def test_start_failure_prediction_engine(self, daemon, mock_dependencies):
        """Test start failure when prediction engine fails to start."""
        mock_prediction_engine_instance = mock_dependencies["prediction_engine"].return_value
        mock_prediction_engine_instance.start.return_value = False

        assert daemon.start() is False
        assert daemon._running is False

        mock_dependencies["log_event"].assert_any_call(
            ANY, "aegis_daemon_start_failed", level="error", error="Failed to start prediction engine"
        )

    def test_start_exception(self, daemon, mock_dependencies):
        """Test start failure due to unexpected exception."""
        # Force an exception during component initialization inside start
        mock_dependencies["model_manager"].side_effect = Exception("Model Init Error")

        assert daemon.start() is False
        assert daemon._running is False

        mock_dependencies["log_event"].assert_any_call(
            ANY, "aegis_daemon_start_failed", level="error", error="Model Init Error"
        )

    @patch("argus_v.aegis.daemon.KronosRouter")
    @patch("argus_v.aegis.daemon.IPCListener")
    def test_start_with_kronos(self, mock_ipc_listener, mock_kronos_router, daemon, mock_dependencies):
        """Test start with Kronos components enabled."""

        if not _KRONOS_AVAILABLE:
            pytest.skip("Kronos dependencies not available")

        mock_prediction_engine_instance = mock_dependencies["prediction_engine"].return_value
        mock_prediction_engine_instance.start.return_value = True

        with patch("threading.Thread"):
            daemon.start()

        assert 'kronos_router' in daemon._components
        assert 'ipc_listener' in daemon._components
        mock_kronos_router.assert_called_once()
        mock_ipc_listener.assert_called_once()
        mock_ipc_listener.return_value.start.assert_called_once()

    def test_stop_success(self, daemon, mock_dependencies):
        """Test successful stop."""
        daemon._running = True
        daemon._start_time = datetime.now()

        mock_prediction_engine_instance = Mock()
        mock_prediction_engine_instance.stop.return_value = True
        daemon._components['prediction_engine'] = mock_prediction_engine_instance

        mock_ipc_listener_instance = Mock()
        daemon._components['ipc_listener'] = mock_ipc_listener_instance

        assert daemon.stop() is True
        assert daemon._running is False
        assert daemon._shutdown_event.is_set()

        mock_prediction_engine_instance.stop.assert_called_once()
        mock_ipc_listener_instance.stop.assert_called_once()

        mock_dependencies["log_event"].assert_any_call(
            ANY, "aegis_daemon_stopped", level="info", total_runtime_seconds=ANY
        )

    def test_stop_not_running(self, daemon, mock_dependencies):
        """Test stop when not running."""
        daemon._running = False
        assert daemon.stop() is True
        mock_dependencies["log_event"].assert_any_call(
            ANY, "aegis_daemon_not_running", level="debug"
        )

    def test_stop_exception(self, daemon, mock_dependencies):
        """Test stop with exception."""
        daemon._running = True
        # Inject an object that raises exception on access or stop
        daemon._components['prediction_engine'] = Mock()
        daemon._components['prediction_engine'].stop.side_effect = Exception("Stop Error")

        assert daemon.stop() is False
        mock_dependencies["log_event"].assert_any_call(
            ANY, "aegis_daemon_stop_failed", level="error", error="Stop Error"
        )

class TestAegisDaemonMonitoring:
    def test_monitoring_loop(self, daemon, mock_dependencies):
        """Test monitoring loop execution."""
        daemon._running = True

        mock_blacklist_manager = Mock()
        mock_blacklist_manager.cleanup_expired_entries = Mock()
        mock_blacklist_manager.sync_with_firebase = Mock()
        # Mock _last_sync_time to force sync
        mock_blacklist_manager._last_sync_time = datetime.now() - timedelta(hours=2)

        daemon._components['blacklist_manager'] = mock_blacklist_manager

        # Configure firebase to be enabled
        daemon.config = MagicMock()
        daemon.config.stats_file = "/tmp/argus/stats.json"
        daemon.config.firebase = Mock()
        daemon.config.firebase.project_id = "test_project"

        # We need to break the infinite loop.
        # We can use a side effect on time.sleep to set _running to False after first iteration
        # Also mock open/mkdir to prevent file creation during stats update
        with patch("time.sleep") as mock_sleep, \
             patch("builtins.open"), \
             patch("pathlib.Path.mkdir"):
            def stop_loop(*args):
                daemon._running = False

            mock_sleep.side_effect = stop_loop

            daemon._monitoring_loop()

            mock_blacklist_manager.cleanup_expired_entries.assert_called_once()
            mock_blacklist_manager.sync_with_firebase.assert_called_once()
            mock_sleep.assert_called_once()

    def test_perform_health_check(self, daemon, mock_dependencies):
        """Test health check execution."""
        daemon._components['model_manager'] = Mock()
        daemon._components['model_manager'].is_model_available.return_value = True
        daemon._components['model_manager'].get_model_info.return_value = {}

        daemon._components['blacklist_manager'] = Mock()
        daemon._components['blacklist_manager'].get_statistics.return_value = {}

        daemon._components['prediction_engine'] = Mock()
        daemon._components['prediction_engine']._running = True
        daemon._components['prediction_engine'].get_statistics.return_value = {}

        daemon._perform_health_check()

        assert daemon._stats['health_checks_passed'] == 1
        assert daemon._stats['health_checks_failed'] == 0
        assert daemon._stats['last_health_check'] is not None

    def test_perform_health_check_failure(self, daemon, mock_dependencies):
        """Test health check failure handling."""
        # Force an exception during health check
        daemon._components['model_manager'] = Mock()
        daemon._components['model_manager'].is_model_available.side_effect = Exception("Health Check Error")

        daemon._perform_health_check()

        assert daemon._stats['health_checks_failed'] == 1
        # Since get_health_status catches exceptions and returns error status,
        # _perform_health_check logs 'health_check_completed' with overall_health='error'
        # instead of 'health_check_failed'.
        mock_dependencies["log_event"].assert_any_call(
            ANY, "health_check_completed", level="debug",
            overall_health='error', components_healthy=0, total_components=0
        )

    def test_should_sync_firebase(self, daemon):
        """Test Firebase sync logic."""
        mock_blacklist_manager = Mock()
        daemon._components['blacklist_manager'] = mock_blacklist_manager

        # Replace config with a mock to allow modification
        daemon.config = MagicMock()

        # Case 1: Firebase not configured
        daemon.config.firebase = None
        assert daemon._should_sync_firebase() is False

        # Case 2: Firebase configured, no blacklist manager
        daemon.config.firebase = Mock()
        daemon._components['blacklist_manager'] = None
        assert daemon._should_sync_firebase() is False
        daemon._components['blacklist_manager'] = mock_blacklist_manager

        # Case 3: No last sync time
        mock_blacklist_manager._last_sync_time = None
        assert daemon._should_sync_firebase() is True

        # Case 4: Recent sync
        mock_blacklist_manager._last_sync_time = datetime.now()
        assert daemon._should_sync_firebase() is False

        # Case 5: Old sync
        mock_blacklist_manager._last_sync_time = datetime.now() - timedelta(hours=2)
        assert daemon._should_sync_firebase() is True

class TestAegisDaemonHealthStatus:
    def test_get_health_status_healthy(self, daemon):
        """Test get_health_status returning healthy."""
        daemon._start_time = datetime.now()
        daemon._running = True

        daemon._components['model_manager'] = Mock()
        daemon._components['model_manager'].is_model_available.return_value = True

        daemon._components['blacklist_manager'] = Mock()

        daemon._components['prediction_engine'] = Mock()
        daemon._components['prediction_engine']._running = True

        status = daemon.get_health_status()

        assert status['overall_health'] == 'healthy'
        assert status['components_healthy'] == 3
        assert status['total_components'] == 3
        assert status['service_info']['is_running'] is True

    def test_get_health_status_degraded(self, daemon):
        """Test get_health_status returning degraded."""
        daemon._start_time = datetime.now()

        daemon._components['model_manager'] = Mock()
        daemon._components['model_manager'].is_model_available.return_value = False # Unhealthy

        daemon._components['blacklist_manager'] = Mock() # Healthy

        daemon._components['prediction_engine'] = Mock()
        daemon._components['prediction_engine']._running = True # Healthy

        # 2/3 healthy = 66% -> degraded (>= 0.5 but < 0.8)

        status = daemon.get_health_status()

        assert status['overall_health'] == 'degraded'
        assert status['components_healthy'] == 2

    def test_get_health_status_unhealthy(self, daemon):
        """Test get_health_status returning unhealthy."""
        daemon._start_time = datetime.now()

        daemon._components['model_manager'] = Mock()
        daemon._components['model_manager'].is_model_available.return_value = False

        daemon._components['blacklist_manager'] = Mock()

        daemon._components['prediction_engine'] = Mock()
        daemon._components['prediction_engine']._running = False

        # 1/3 healthy = 33% -> unhealthy (< 0.5)

        status = daemon.get_health_status()

        assert status['overall_health'] == 'unhealthy'

    def test_get_dry_run_remaining_days(self, daemon):
        """Test dry run remaining days calculation."""
        # Not started yet
        assert daemon._get_dry_run_remaining_days() == 7.0

        # Started, end time set
        daemon._start_time = datetime.now()
        end_time = datetime.now() + timedelta(days=3)
        daemon._stats['dry_run_end_time'] = end_time.isoformat()

        remaining = daemon._get_dry_run_remaining_days()
        assert 2.9 < remaining < 3.1

        # Past end time
        end_time = datetime.now() - timedelta(days=1)
        daemon._stats['dry_run_end_time'] = end_time.isoformat()

        remaining = daemon._get_dry_run_remaining_days()
        assert remaining == 0.0

class TestAegisDaemonEmergency:
    def test_emergency_stop(self, daemon, mock_dependencies):
        """Test emergency stop."""
        daemon._components['prediction_engine'] = Mock()
        daemon._components['blacklist_manager'] = Mock()

        assert daemon.emergency_stop("Test Reason") is True

        daemon._components['prediction_engine'].stop.assert_called_once()
        daemon._components['blacklist_manager'].emergency_stop.assert_called_with("Test Reason")
        assert daemon._stats['emergency_stops'] == 1

        mock_dependencies["log_event"].assert_any_call(
            ANY, "emergency_stop_activated", level="critical", reason="Test Reason"
        )

    def test_emergency_stop_failure(self, daemon, mock_dependencies):
        """Test emergency stop failure."""
        daemon._components['prediction_engine'] = Mock()
        daemon._components['prediction_engine'].stop.side_effect = Exception("Stop Error")

        assert daemon.emergency_stop() is False
        mock_dependencies["log_event"].assert_any_call(
            ANY, "emergency_stop_failed", level="error", error="Stop Error"
        )

    def test_emergency_restore(self, daemon, mock_dependencies):
        """Test emergency restore."""
        daemon._components['prediction_engine'] = Mock()
        daemon._components['prediction_engine']._running = False
        daemon._components['blacklist_manager'] = Mock()

        assert daemon.emergency_restore("Restore Reason") is True

        daemon._components['blacklist_manager'].emergency_restore.assert_called_with("Restore Reason")
        daemon._components['prediction_engine'].start.assert_called_once()

        mock_dependencies["log_event"].assert_any_call(
            ANY, "emergency_restored", level="info", reason="Restore Reason"
        )

class TestAegisDaemonConfigValidation:
    def test_validate_configuration(self, daemon):
        """Test configuration validation."""
        # Replace config with a mock to allow modification
        daemon.config = MagicMock()

        # Setup mocks
        mock_model_config = Mock()
        mock_model_config.model_local_path = "/tmp/argus/models"
        mock_model_config.scaler_local_path = "/tmp/argus/scalers"
        mock_model_config.min_model_age_hours = 25
        mock_model_config.max_model_age_days = 1

        mock_prediction_config = Mock()
        mock_prediction_config.anomaly_threshold = 0.9
        mock_prediction_config.high_risk_threshold = 0.8

        mock_enforcement_config = Mock()
        mock_enforcement_config.emergency_stop_file = "/tmp/argus/emergency"
        mock_enforcement_config.dry_run_duration_days = 1

        daemon.config.model = mock_model_config
        daemon.config.prediction = mock_prediction_config
        daemon.config.enforcement = mock_enforcement_config
        daemon.config.state_file = "/tmp/argus/state.json"
        daemon.config.stats_file = "/tmp/argus/stats.json"

        # Valid directories
        with patch("pathlib.Path.exists", return_value=True), \
             patch("os.access", return_value=True):

            issues = daemon._validate_configuration()
            assert any("min_model_age_hours should be less than max_model_age_days" in issue for issue in issues)
            assert any("anomaly_threshold must be less than high_risk_threshold" in issue for issue in issues)

    def test_validate_configuration_directory_issues(self, daemon):
        """Test directory permission issues."""
        with patch("pathlib.Path.exists", return_value=False), \
             patch("pathlib.Path.mkdir", side_effect=Exception("Mkdir Error")):

            issues = daemon._validate_configuration()
            assert any("Cannot create directory" in issue for issue in issues)

        with patch("pathlib.Path.exists", return_value=True), \
             patch("os.access", return_value=False):

            issues = daemon._validate_configuration()
            assert any("No write permission" in issue for issue in issues)
