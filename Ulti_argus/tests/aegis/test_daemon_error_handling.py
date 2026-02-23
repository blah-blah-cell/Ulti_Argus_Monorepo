import json
from unittest.mock import MagicMock, patch

import pytest

from argus_v.aegis.config import AegisConfig
from argus_v.aegis.daemon import AegisDaemon, ServiceStartError


class TestDaemonErrorHandling:

    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration."""
        config = MagicMock(spec=AegisConfig)
        config.log_level = "INFO"
        config.anonymization_salt = "test_salt"

        # Mock sub-configs
        config.model = MagicMock()
        config.model.min_model_age_hours = 1
        config.model.max_model_age_days = 30
        config.model.model_local_path = "/tmp/model"
        config.model.scaler_local_path = "/tmp/scaler"
        config.model.foundation_model_path = "/tmp/foundation_model"

        config.prediction = MagicMock()
        config.prediction.anomaly_threshold = 0.5
        config.prediction.high_risk_threshold = 0.9
        config.prediction.feature_columns = ['col1']

        config.enforcement = MagicMock()
        config.enforcement.dry_run_duration_days = 7
        config.enforcement.emergency_stop_file = "/tmp/emergency"

        config.polling = MagicMock()

        config.stats_file = "/tmp/stats.json"
        config.state_file = "/tmp/state.json"
        config.shutdown_timeout = 5
        config.firebase = None

        config.to_safe_dict.return_value = {}

        return config

    @patch('argus_v.aegis.daemon.load_aegis_config')
    @patch('argus_v.aegis.daemon.configure_logging')
    def test_init_config_load_failure(self, mock_log, mock_load):
        """Test daemon initialization fails when config load fails."""
        mock_load.side_effect = ValueError("Invalid config")

        # Ensure file exists check passes
        with patch('os.path.exists', return_value=True):
            with pytest.raises(ServiceStartError) as excinfo:
                AegisDaemon("dummy_path.yaml")

        assert "Failed to load configuration" in str(excinfo.value)

    @patch('argus_v.aegis.daemon.load_aegis_config')
    @patch('argus_v.aegis.daemon.configure_logging')
    def test_init_invalid_path(self, mock_log, mock_load):
        """Test daemon initialization fails with invalid path."""
        with pytest.raises(ServiceStartError) as excinfo:
            AegisDaemon("/non/existent/path.yaml")

        assert "Configuration file not found" in str(excinfo.value)

    @patch('argus_v.aegis.daemon.load_aegis_config')
    @patch('argus_v.aegis.daemon.configure_logging')
    @patch('argus_v.aegis.daemon.ModelManager')
    def test_start_component_failure(self, mock_model_manager, mock_log, mock_load, mock_config):
        """Test start fails and rolls back if a component fails."""
        mock_load.return_value = mock_config

        # Mock successful anonymizer
        with patch('argus_v.oracle_core.anonymize.HashAnonymizer'):

            # Make ModelManager raise exception
            mock_model_manager.side_effect = Exception("Model failure")

            # Ensure file exists check passes
            with patch('os.path.exists', return_value=True):
                daemon = AegisDaemon("dummy_path.yaml")

                # Daemon should not be running initially
                assert not daemon._running

                # Start should return False due to ModelManager failure
                result = daemon.start()

                assert result is False

                # Verify daemon is stopped (rollback)
                assert not daemon._running

    @patch('argus_v.aegis.daemon.load_aegis_config')
    @patch('argus_v.aegis.daemon.configure_logging')
    def test_monitoring_loop_error_handling(self, mock_log, mock_load, mock_config):
        """Test monitoring loop handles errors without crashing."""
        mock_load.return_value = mock_config

        with patch('os.path.exists', return_value=True):
            daemon = AegisDaemon("dummy_path.yaml")

        daemon._running = True

        # Mock health check to raise exception
        daemon._perform_health_check = MagicMock(side_effect=Exception("Health check error"))
        # Mock other methods to avoid side effects
        daemon._update_statistics = MagicMock()

        # Use a side effect on time.sleep to stop the loop after one iteration
        def stop_loop(*args):
            daemon._running = False

        with patch('time.sleep', side_effect=stop_loop):
             daemon._monitoring_loop()

        # If we reached here, the loop handled the exception and exited gracefully

    @patch('argus_v.aegis.daemon.load_aegis_config')
    @patch('argus_v.aegis.daemon.configure_logging')
    def test_atomic_stats_update(self, mock_log, mock_load, mock_config, tmp_path):
        """Test statistics update uses atomic write."""
        stats_file = tmp_path / "stats.json"
        mock_config.stats_file = str(stats_file)
        mock_load.return_value = mock_config

        with patch('os.path.exists', return_value=True):
            daemon = AegisDaemon("dummy_path.yaml")

        # Call update stats
        daemon._update_statistics()

        # Verify file exists and has content
        assert stats_file.exists()
        with open(stats_file) as f:
            content = json.load(f)
            assert 'daemon_stats' in content

    @patch('argus_v.aegis.daemon.load_aegis_config')
    @patch('argus_v.aegis.daemon.configure_logging')
    def test_health_check_partial_failure(self, mock_log, mock_load, mock_config):
        """Test health check continues even if one component check fails."""
        mock_load.return_value = mock_config

        with patch('os.path.exists', return_value=True):
            daemon = AegisDaemon("dummy_path.yaml")

        # Add a mock component that fails health check
        mock_comp = MagicMock()
        # The check_fn we used in daemon.py expects certain methods.
        # For 'model_manager', it calls is_model_available.
        mock_comp.is_model_available.side_effect = Exception("Component dead")
        daemon._components['model_manager'] = mock_comp

        # Get status
        status = daemon.get_health_status()

        # Check that we got a result, not an exception
        assert status['overall_health'] != 'error'
        assert 'model_manager' in status['component_details']
        assert status['component_details']['model_manager']['healthy'] == False
        assert "Component dead" in str(status['component_details']['model_manager'].get('error', ''))
