
import pytest
from unittest.mock import MagicMock, patch, mock_open
import sys
import os
import signal
import json
from pathlib import Path
from contextlib import contextmanager

# Mock dependencies
mock_yaml = MagicMock()
mock_scapy = MagicMock()
mock_pandas = MagicMock()
mock_numpy = MagicMock()
mock_numpy.float64 = float
mock_numpy.bool_ = bool
mock_sklearn = MagicMock()
mock_skops = MagicMock()
mock_firebase_admin = MagicMock()
mock_daemon = MagicMock()
mock_daemon_pidfile = MagicMock()

sys.modules['yaml'] = mock_yaml
sys.modules['scapy'] = mock_scapy
sys.modules['scapy.all'] = mock_scapy
sys.modules['pandas'] = mock_pandas
sys.modules['numpy'] = mock_numpy
sys.modules['sklearn'] = mock_sklearn
sys.modules['sklearn.ensemble'] = MagicMock()
sys.modules['sklearn.preprocessing'] = MagicMock()
sys.modules['skops'] = mock_skops
sys.modules['skops.io'] = MagicMock()
sys.modules['firebase_admin'] = mock_firebase_admin
sys.modules['daemon'] = mock_daemon
sys.modules['daemon.pidfile'] = mock_daemon_pidfile

# Mock internal dependencies
mock_aegis_daemon = MagicMock()
sys.modules['argus_v.aegis.daemon'] = mock_aegis_daemon
mock_aegis_config = MagicMock()
sys.modules['argus_v.aegis.config'] = mock_aegis_config
mock_oracle_logging = MagicMock()
sys.modules['argus_v.oracle_core.logging'] = mock_oracle_logging

# Now import the module under test
from argus_v.aegis.cli import AegisCLI, main

class TestAegisCLI:

    @pytest.fixture
    def cli(self):
        return AegisCLI()

    @pytest.fixture
    def mock_args(self):
        args = MagicMock()
        args.config = '/etc/aegis/config.yaml'
        args.verbose = False
        return args

    def test_init(self, cli):
        assert cli.daemon is None

    @patch('argus_v.aegis.cli.configure_logging')
    def test_setup_logging(self, mock_configure_logging, cli):
        import logging
        cli.setup_logging(verbose=True)
        mock_configure_logging.assert_called_with(level=logging.DEBUG)

        cli.setup_logging(verbose=False)
        mock_configure_logging.assert_called_with(level=logging.INFO)

    def test_create_parser(self, cli):
        parser = cli._create_parser()
        args = parser.parse_args(['start', '--daemon'])
        assert args.command == 'start'
        assert args.daemon is True

        args = parser.parse_args(['stop', '--force'])
        assert args.command == 'stop'
        assert args.force is True

    @patch('argus_v.aegis.cli.AegisCLI._handle_command')
    @patch('argus_v.aegis.cli.AegisCLI.setup_logging')
    @patch('sys.argv', ['argus-cli', 'start'])
    def test_run(self, mock_setup_logging, mock_handle_command, cli):
        cli.run()
        mock_setup_logging.assert_called()
        mock_handle_command.assert_called()

    @patch('argus_v.aegis.cli.AegisCLI._handle_command')
    def test_run_exception(self, mock_handle_command, cli):
        mock_handle_command.side_effect = Exception("Test error")
        exit_code = cli.run(['start'])
        assert exit_code == 1

    @patch('argus_v.aegis.cli.AegisDaemon')
    @patch('pathlib.Path.exists')
    def test_load_daemon(self, mock_exists, mock_daemon_cls, cli):
        mock_exists.return_value = True
        daemon = cli._load_daemon('config.yaml')
        assert daemon == mock_daemon_cls.return_value
        mock_daemon_cls.assert_called_with('config.yaml')

        mock_exists.return_value = False
        with pytest.raises(Exception):
            cli._load_daemon('config.yaml')

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    @patch('argus_v.aegis.cli.AegisCLI._is_process_running')
    @patch('daemon.DaemonContext')
    @patch('daemon.pidfile.PIDLockFile')
    def test_cmd_start_daemon(self, mock_pidfile, mock_daemon_context, mock_is_running, mock_load_daemon, cli, mock_args):
        mock_args.daemon = True
        mock_args.pid_file = '/var/run/aegis.pid'
        mock_is_running.return_value = False

        daemon_instance = MagicMock()
        daemon_instance._running = False # To exit the loop immediately
        mock_load_daemon.return_value = daemon_instance

        # Setup context manager mock
        context_mock = MagicMock()
        mock_daemon_context.return_value = context_mock
        context_mock.__enter__.return_value = None

        exit_code = cli._cmd_start(mock_args)

        assert exit_code == 0
        mock_daemon_context.assert_called()
        daemon_instance.start.assert_called()

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    def test_cmd_start_foreground(self, mock_load_daemon, cli, mock_args):
        mock_args.daemon = False
        mock_args.pid_file = None

        daemon_instance = MagicMock()
        daemon_instance.start.return_value = True
        daemon_instance._running = False
        mock_load_daemon.return_value = daemon_instance

        exit_code = cli._cmd_start(mock_args)

        assert exit_code == 0
        daemon_instance.start.assert_called()

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    @patch('os.kill')
    @patch('pathlib.Path.exists')
    def test_cmd_stop_graceful(self, mock_exists, mock_kill, mock_load_daemon, cli, mock_args):
        mock_args.force = False
        mock_args.timeout = 1

        daemon_instance = MagicMock()
        daemon_instance.config.pid_file = '/var/run/aegis.pid'
        mock_load_daemon.return_value = daemon_instance

        mock_exists.return_value = True

        with patch('builtins.open', mock_open(read_data='12345')):
            # Mock os.kill(pid, 0) to raise OSError after the first call to simulate process termination
            mock_kill.side_effect = [None, OSError]

            exit_code = cli._cmd_stop(mock_args)

            assert exit_code == 0
            # Ensure SIGTERM was sent
            mock_kill.assert_any_call(12345, signal.SIGTERM)

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    @patch('argus_v.aegis.cli.AegisCLI._force_stop_daemon')
    def test_cmd_stop_force(self, mock_force_stop, mock_load_daemon, cli, mock_args):
        mock_args.force = True

        daemon_instance = MagicMock()
        daemon_instance.config.pid_file = '/var/run/aegis.pid'
        mock_load_daemon.return_value = daemon_instance

        exit_code = cli._cmd_stop(mock_args)

        assert exit_code == 0
        mock_force_stop.assert_called_with('/var/run/aegis.pid')

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    def test_cmd_status(self, mock_load_daemon, cli, mock_args):
        mock_args.json = True
        daemon_instance = MagicMock()
        daemon_instance.get_status.return_value = {'status': 'ok'}
        mock_load_daemon.return_value = daemon_instance

        with patch('sys.stdout') as mock_stdout:
            exit_code = cli._cmd_status(mock_args)
            assert exit_code == 0
            daemon_instance.get_status.assert_called()

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    def test_cmd_health(self, mock_load_daemon, cli, mock_args):
        mock_args.json = True
        daemon_instance = MagicMock()
        daemon_instance.get_health_status.return_value = {'health': 'ok'}
        mock_load_daemon.return_value = daemon_instance

        with patch('sys.stdout') as mock_stdout:
            exit_code = cli._cmd_health(mock_args)
            assert exit_code == 0
            daemon_instance.get_health_status.assert_called()

    @patch('argus_v.aegis.cli.load_aegis_config')
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.is_dir')
    def test_cmd_validate(self, mock_is_dir, mock_exists, mock_load_config, cli, mock_args):
        mock_load_config.return_value = MagicMock()
        mock_exists.return_value = True
        mock_is_dir.return_value = True

        exit_code = cli._cmd_validate(mock_args)
        assert exit_code == 0
        mock_load_config.assert_called_with(mock_args.config)

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    def test_cmd_test_model_load(self, mock_load_daemon, cli, mock_args):
        mock_args.model_load = True
        mock_args.csv = None
        mock_args.blacklist = None

        daemon_instance = MagicMock()
        model_manager = MagicMock()
        model_manager.load_latest_model.return_value = True
        daemon_instance._components = {'model_manager': model_manager}
        mock_load_daemon.return_value = daemon_instance

        exit_code = cli._cmd_test(mock_args)
        assert exit_code == 0
        model_manager.load_latest_model.assert_called()

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    def test_cmd_emergency_stop(self, mock_load_daemon, cli, mock_args):
        mock_args.reason = "Test"
        daemon_instance = MagicMock()
        daemon_instance.emergency_stop.return_value = True
        mock_load_daemon.return_value = daemon_instance

        exit_code = cli._cmd_emergency_stop(mock_args)
        assert exit_code == 0
        daemon_instance.emergency_stop.assert_called_with("Test")

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    def test_cmd_model_load(self, mock_load_daemon, cli, mock_args):
        mock_args.model_command = 'load'
        daemon_instance = MagicMock()
        model_manager = MagicMock()
        model_manager.load_latest_model.return_value = True
        daemon_instance._components = {'model_manager': model_manager}
        mock_load_daemon.return_value = daemon_instance

        exit_code = cli._cmd_model(mock_args)
        assert exit_code == 0
        model_manager.load_latest_model.assert_called()

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    def test_cmd_blacklist_add(self, mock_load_daemon, cli, mock_args):
        mock_args.blacklist_command = 'add'
        mock_args.ip_address = '1.2.3.4'
        mock_args.reason = 'Test'
        mock_args.risk_level = 'high'
        mock_args.ttl_hours = 24
        mock_args.enforce = True

        daemon_instance = MagicMock()
        blacklist_manager = MagicMock()
        blacklist_manager.add_to_blacklist.return_value = True
        daemon_instance._components = {'blacklist_manager': blacklist_manager}
        mock_load_daemon.return_value = daemon_instance

        exit_code = cli._cmd_blacklist(mock_args)
        assert exit_code == 0
        blacklist_manager.add_to_blacklist.assert_called()

    @patch('argus_v.aegis.cli.AegisCLI._load_daemon')
    def test_cmd_feedback(self, mock_load_daemon, cli, mock_args):
        mock_args.false_positive = '1.2.3.4'
        mock_args.reason = 'FP'

        daemon_instance = MagicMock()
        feedback_manager = MagicMock()
        feedback_manager.report_false_positive.return_value = True
        feedback_manager.trigger_retrain.return_value = True

        blacklist_manager = MagicMock()
        blacklist_manager.is_blacklisted.return_value = True
        blacklist_manager.remove_from_blacklist.return_value = True

        daemon_instance._components = {
            'feedback_manager': feedback_manager,
            'blacklist_manager': blacklist_manager
        }
        mock_load_daemon.return_value = daemon_instance

        exit_code = cli._cmd_feedback(mock_args)
        assert exit_code == 0
        feedback_manager.report_false_positive.assert_called_with(ip_address='1.2.3.4', reason='FP')
        blacklist_manager.remove_from_blacklist.assert_called()
        feedback_manager.trigger_retrain.assert_called()

    def test_is_process_running(self, cli):
        with patch('pathlib.Path.exists', return_value=False):
            assert cli._is_process_running('pidfile') is False

        with patch('pathlib.Path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data='12345')):
                with patch('os.kill') as mock_kill:
                    assert cli._is_process_running('pidfile') is True
                    mock_kill.assert_called_with(12345, 0)

                    mock_kill.side_effect = OSError
                    assert cli._is_process_running('pidfile') is False

    def test_force_stop_daemon(self, cli):
        with patch('pathlib.Path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data='12345')):
                with patch('os.kill') as mock_kill:
                    with patch('pathlib.Path.unlink') as mock_unlink:
                        cli._force_stop_daemon('pidfile')
                        mock_kill.assert_called_with(12345, signal.SIGKILL)
                        mock_unlink.assert_called()
