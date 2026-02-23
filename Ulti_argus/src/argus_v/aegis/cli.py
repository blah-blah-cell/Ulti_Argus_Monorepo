"""Command-line interface for Aegis shield runtime service.

This module provides a comprehensive CLI for managing the Aegis daemon,
including start/stop operations, status monitoring, configuration validation,
and emergency controls.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Optional

from ..oracle_core.logging import configure_logging
from .config import load_aegis_config

if TYPE_CHECKING:
    from .daemon import AegisDaemon

logger = logging.getLogger(__name__)


class AegisCLI:
    """Command-line interface for Aegis shield runtime."""
    
    def __init__(self):
        """Initialize CLI interface."""
        self.daemon: Optional["AegisDaemon"] = None
    
    def setup_logging(self, verbose: bool = False) -> None:
        """Set up logging for CLI operations.
        
        Args:
            verbose: Enable verbose logging
        """
        log_level = logging.DEBUG if verbose else logging.INFO
        configure_logging(level=log_level)
    
    def run(self, args: Optional[list[str]] = None) -> int:
        """Run the CLI with given arguments.
        
        Args:
            args: Command line arguments (uses sys.argv if None)
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        parser = self._create_parser()
        
        if args is None:
            args = sys.argv[1:]
        
        parsed_args = parser.parse_args(args)
        
        try:
            if parsed_args.verbose:
                self.setup_logging(verbose=True)
            else:
                self.setup_logging(verbose=False)
            
            return self._handle_command(parsed_args)
            
        except Exception as e:
            logger.error(f"Error: {e}")
            return 1
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser for CLI.
        
        Returns:
            Configured argument parser
        """
        parser = argparse.ArgumentParser(
            description="Aegis Shield Runtime Service",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s start --config /etc/aegis/config.yaml
  %(prog)s status --config /etc/aegis/config.yaml
  %(prog)s stop --config /etc/aegis/config.yaml
  %(prog)s validate --config /etc/aegis/config.yaml
  %(prog)s health --config /etc/aegis/config.yaml
  %(prog)s emergency-stop --config /etc/aegis/config.yaml
  %(prog)s test --config /etc/aegis/config.yaml --csv /path/to/test.csv
            """
        )
        
        # Global arguments
        parser.add_argument(
            '--config', '-c',
            type=str,
            default='/etc/aegis/config.yaml',
            help='Path to configuration file (default: /etc/aegis/config.yaml)'
        )
        
        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Enable verbose output'
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(
            dest='command',
            help='Available commands',
            metavar='COMMAND'
        )
        
        # Start command
        start_parser = subparsers.add_parser(
            'start',
            help='Start Aegis daemon service'
        )
        start_parser.add_argument(
            '--daemon', '-d',
            action='store_true',
            help='Run as daemon (background process)'
        )
        start_parser.add_argument(
            '--pid-file',
            type=str,
            help='PID file path (default: from config)'
        )
        
        # Stop command
        stop_parser = subparsers.add_parser(
            'stop',
            help='Stop Aegis daemon service'
        )
        stop_parser.add_argument(
            '--timeout',
            type=int,
            default=30,
            help='Shutdown timeout in seconds (default: 30)'
        )
        stop_parser.add_argument(
            '--force',
            action='store_true',
            help='Force stop (kill process)'
        )
        
        # Status command
        status_parser = subparsers.add_parser(
            'status',
            help='Show daemon status'
        )
        status_parser.add_argument(
            '--json',
            action='store_true',
            help='Output status as JSON'
        )
        
        # Health command
        health_parser = subparsers.add_parser(
            'health',
            help='Show health status'
        )
        health_parser.add_argument(
            '--json',
            action='store_true',
            help='Output health as JSON'
        )
        
        # Validate command
        validate_parser = subparsers.add_parser(
            'validate',
            help='Validate configuration'
        )
        
        # Test command
        test_parser = subparsers.add_parser(
            'test',
            help='Test configuration and components'
        )
        test_parser.add_argument(
            '--csv',
            type=str,
            help='Test CSV file for prediction'
        )
        test_parser.add_argument(
            '--model-load',
            action='store_true',
            help='Test model loading'
        )
        test_parser.add_argument(
            '--blacklist',
            action='store_true',
            help='Test blacklist operations'
        )
        
        # Emergency commands
        emergency_parser = subparsers.add_parser(
            'emergency-stop',
            help='Emergency stop all enforcement'
        )
        emergency_parser.add_argument(
            '--reason',
            type=str,
            default='Manual emergency stop',
            help='Reason for emergency stop'
        )
        
        emergency_restore_parser = subparsers.add_parser(
            'emergency-restore',
            help='Restore normal operations'
        )
        emergency_restore_parser.add_argument(
            '--reason',
            type=str,
            default='Manual emergency restore',
            help='Reason for restoration'
        )
        
        # Statistics command
        stats_parser = subparsers.add_parser(
            'stats',
            help='Show detailed statistics'
        )
        stats_parser.add_argument(
            '--json',
            action='store_true',
            help='Output stats as JSON'
        )
        
        # Model command
        model_parser = subparsers.add_parser(
            'model',
            help='Model management'
        )
        model_subparsers = model_parser.add_subparsers(dest='model_command')
        
        model_load_parser = model_subparsers.add_parser(
            'load',
            help='Load latest model'
        )
        model_load_parser.add_argument(
            '--force',
            action='store_true',
            help='Force reload even if model exists'
        )
        
        model_info_parser = model_subparsers.add_parser(
            'info',
            help='Show model information'
        )
        
        # Blacklist command
        blacklist_parser = subparsers.add_parser(
            'blacklist',
            help='Blacklist management'
        )
        blacklist_subparsers = blacklist_parser.add_subparsers(dest='blacklist_command')
        
        blacklist_list_parser = blacklist_subparsers.add_parser(
            'list',
            help='List blacklist entries'
        )
        blacklist_list_parser.add_argument(
            '--active-only',
            action='store_true',
            help='Show only active entries'
        )
        blacklist_list_parser.add_argument(
            '--risk-level',
            type=str,
            choices=['low', 'medium', 'high', 'critical'],
            help='Filter by risk level'
        )
        blacklist_list_parser.add_argument(
            '--json',
            action='store_true',
            help='Output as JSON'
        )
        
        blacklist_add_parser = blacklist_subparsers.add_parser(
            'add',
            help='Add IP to blacklist'
        )
        blacklist_add_parser.add_argument(
            'ip_address',
            type=str,
            help='IP address to blacklist'
        )
        blacklist_add_parser.add_argument(
            '--reason',
            type=str,
            default='Manual blacklist',
            help='Reason for blacklisting'
        )
        blacklist_add_parser.add_argument(
            '--risk-level',
            type=str,
            choices=['low', 'medium', 'high', 'critical'],
            default='medium',
            help='Risk level'
        )
        blacklist_add_parser.add_argument(
            '--ttl-hours',
            type=int,
            help='Time to live in hours'
        )
        blacklist_add_parser.add_argument(
            '--enforce',
            action='store_true',
            help='Enforce immediately'
        )
        
        blacklist_remove_parser = blacklist_subparsers.add_parser(
            'remove',
            help='Remove IP from blacklist'
        )
        blacklist_remove_parser.add_argument(
            'ip_address',
            type=str,
            help='IP address to remove'
        )
        blacklist_remove_parser.add_argument(
            '--source',
            type=str,
            default='manual',
            help='Source of entry to remove'
        )

        # Feedback command (Active Learning)
        feedback_parser = subparsers.add_parser(
            'feedback',
            help='Provide feedback on model predictions and trigger retraining'
        )
        feedback_parser.add_argument(
            '--false-positive',
            type=str,
            metavar='IP',
            help='Report an IP as a false positive (trusted)'
        )
        feedback_parser.add_argument(
            '--reason',
            type=str,
            default='User reported false positive',
            help='Reason for feedback'
        )
        
        return parser
    
    def _handle_command(self, args) -> int:
        """Handle the parsed command.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            Exit code
        """
        if not args.command:
            logger.error("No command specified. Use --help for usage information.")
            return 1
        
        try:
            if args.command == 'start':
                return self._cmd_start(args)
            elif args.command == 'stop':
                return self._cmd_stop(args)
            elif args.command == 'status':
                return self._cmd_status(args)
            elif args.command == 'health':
                return self._cmd_health(args)
            elif args.command == 'validate':
                return self._cmd_validate(args)
            elif args.command == 'test':
                return self._cmd_test(args)
            elif args.command == 'emergency-stop':
                return self._cmd_emergency_stop(args)
            elif args.command == 'emergency-restore':
                return self._cmd_emergency_restore(args)
            elif args.command == 'stats':
                return self._cmd_stats(args)
            elif args.command == 'model':
                return self._cmd_model(args)
            elif args.command == 'blacklist':
                return self._cmd_blacklist(args)
            elif args.command == 'feedback':
                return self._cmd_feedback(args)
            else:
                logger.error(f"Unknown command: {args.command}")
                return 1
                
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            return 1
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return 1
    
    def _load_daemon(self, config_path: str) -> "AegisDaemon":
        """Load and initialize daemon.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Initialized AegisDaemon instance
        """
        try:
            # Validate config file exists
            if not Path(config_path).exists():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            
            # Import daemon locally to avoid heavy dependencies on CLI load
            from .daemon import AegisDaemon

            # Load daemon (but don't start it yet)
            daemon = AegisDaemon(config_path)
            return daemon
            
        except Exception as e:
            raise Exception(f"Failed to load daemon: {e}")
    
    def _cmd_start(self, args) -> int:
        """Start daemon command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        logger.info(f"Starting Aegis daemon with config: {args.config}")
        
        try:
            daemon = self._load_daemon(args.config)
            
            # Set PID file from config or command line
            pid_file = args.pid_file or daemon.config.pid_file
            
            if args.daemon:
                # Daemon mode - check if already running
                if self._is_process_running(pid_file):
                    logger.info("Daemon is already running")
                    return 0
                
                # Start as daemon
                import daemon as python_daemon
                import daemon.pidfile as python_daemon_pidfile
                
                with python_daemon.DaemonContext(
                    pidfile=python_daemon_pidfile.PIDLockFile(pid_file),
                    signal_map={
                        signal.SIGTERM: daemon.shutdown_requested,
                        signal.SIGINT: daemon.shutdown_requested,
                    }
                ):
                    daemon.start()
                    
                    # Keep daemon running
                    while daemon._running:
                        time.sleep(1)
            else:
                # Foreground mode
                if not daemon.start():
                    logger.error("Failed to start daemon")
                    return 1
                
                logger.info("Daemon started successfully")
                logger.info("Press Ctrl+C to stop...")
                
                try:
                    while daemon._running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    logger.info("Shutting down...")
                    daemon.stop()
                finally:
                    logger.info("Daemon stopped")
            
            return 0
            
        except Exception as e:
            logger.error(f"Failed to start daemon: {e}")
            return 1
    
    def _cmd_stop(self, args) -> int:
        """Stop daemon command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        logger.info("Stopping Aegis daemon...")
        
        try:
            # Load config directly to get PID file
            config = load_aegis_config(args.config)
            pid_file = config.pid_file
            
            # Try graceful stop first
            if not args.force:
                # Check if PID file exists and try to stop gracefully
                if Path(pid_file).exists():
                    try:
                        with open(pid_file, 'r') as f:
                            pid = int(f.read().strip())
                        
                        # Send SIGTERM
                        os.kill(pid, signal.SIGTERM)
                        logger.info(f"Sent stop signal to process {pid}")
                        
                        # Wait for graceful shutdown
                        for i in range(args.timeout):
                            try:
                                os.kill(pid, 0)  # Check if process exists
                                time.sleep(1)
                            except OSError:
                                logger.info("Daemon stopped successfully")
                                return 0
                        
                        logger.warning("Graceful shutdown timeout, forcing stop...")
                        
                    except (ValueError, OSError, FileNotFoundError):
                        pass
            
            # Force stop
            if args.force:
                self._force_stop_daemon(pid_file)
            
            return 0
            
        except Exception as e:
            logger.error(f"Failed to stop daemon: {e}")
            return 1
    
    def _cmd_status(self, args) -> int:
        """Status daemon command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        try:
            config = load_aegis_config(args.config)
            status = self._get_daemon_status(config)
            
            if args.json:
                logger.info("Daemon status", extra={'status': status})
            else:
                self._print_status(status)
            
            return 0
            
        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            return 1
    
    def _cmd_health(self, args) -> int:
        """Health check command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        try:
            config = load_aegis_config(args.config)
            status = self._get_daemon_status(config)
            health = status.get('health', {})
            
            if args.json:
                logger.info("Daemon health", extra={'health': health})
            else:
                self._print_health(health)
            
            return 0
            
        except Exception as e:
            logger.error(f"Failed to get health status: {e}")
            return 1
    
    def _cmd_validate(self, args) -> int:
        """Validate configuration command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        try:
            # Load configuration
            config = load_aegis_config(args.config)
            
            logger.info("Configuration validation:")
            logger.info("  ✓ Configuration loaded successfully")
            logger.info(f"  ✓ Model path: {config.model.model_local_path}")
            logger.info(f"  ✓ Scaler path: {config.model.scaler_local_path}")
            logger.info(f"  ✓ CSV directory: {config.polling.csv_directory}")
            logger.info(f"  ✓ Poll interval: {config.polling.poll_interval_seconds}s")
            logger.info(f"  ✓ Anomaly threshold: {config.prediction.anomaly_threshold}")
            logger.info(f"  ✓ High-risk threshold: {config.prediction.high_risk_threshold}")
            logger.info(f"  ✓ Dry run duration: {config.enforcement.dry_run_duration_days} days")
            logger.info(f"  ✓ Emergency stop file: {config.enforcement.emergency_stop_file}")
            
            if config.firebase:
                logger.info(f"  ✓ Firebase: {config.firebase.project_id}")
            
            if config.github:
                logger.info(f"  ✓ GitHub: {config.github.base_url}")
            
            # Check directories
            required_dirs = [
                Path(config.model.model_local_path).parent,
                Path(config.model.scaler_local_path).parent,
                Path(config.polling.csv_directory),
                Path(config.state_file).parent,
                Path(config.stats_file).parent
            ]
            
            for dir_path in required_dirs:
                if dir_path.exists() and dir_path.is_dir():
                    logger.info(f"  ✓ Directory exists: {dir_path}")
                else:
                    logger.warning(f"  ⚠ Directory missing: {dir_path}")
            
            logger.info("Configuration validation completed successfully")
            return 0
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return 1
    
    def _cmd_test(self, args) -> int:
        """Test command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        logger.info("Testing Aegis components...")
        
        try:
            daemon = self._load_daemon(args.config)
            
            # Test model loading
            if args.model_load or not any([args.csv, args.blacklist]):
                logger.info("=== Model Loading Test ===")
                if daemon._components.get('model_manager'):
                    model_manager = daemon._components['model_manager']
                    success = model_manager.load_latest_model()
                    if success:
                        logger.info("✓ Model loaded successfully")
                        info = model_manager.get_model_info()
                        logger.info(f"  Model type: {info.get('model_type')}")
                        logger.info(f"  Scaler type: {info.get('scaler_type')}")
                    else:
                        logger.error("✗ Model loading failed")
                else:
                    logger.error("✗ Model manager not initialized")
            
            # Test blacklist operations
            if args.blacklist or not any([args.csv, args.model_load]):
                logger.info("=== Blacklist Test ===")
                if daemon._components.get('blacklist_manager'):
                    blacklist_manager = daemon._components['blacklist_manager']
                    
                    # Test add
                    test_ip = "192.168.1.100"
                    success = blacklist_manager.add_to_blacklist(
                        test_ip, 
                        "Test entry", 
                        risk_level="low"
                    )
                    if success:
                        logger.info(f"✓ Added {test_ip} to blacklist")
                        
                        # Test lookup
                        is_blacklisted = blacklist_manager.is_blacklisted(test_ip)
                        if is_blacklisted:
                            logger.info(f"✓ Found {test_ip} in blacklist")
                        else:
                            logger.error(f"✗ Could not find {test_ip} in blacklist")
                        
                        # Test remove
                        success = blacklist_manager.remove_from_blacklist(test_ip)
                        if success:
                            logger.info(f"✓ Removed {test_ip} from blacklist")
                        else:
                            logger.error(f"✗ Could not remove {test_ip} from blacklist")
                    else:
                        logger.error("✗ Failed to add test entry to blacklist")
                else:
                    logger.error("✗ Blacklist manager not initialized")
            
            # Test CSV prediction
            if args.csv:
                logger.info("=== CSV Prediction Test ===")
                csv_path = Path(args.csv)
                if csv_path.exists():
                    logger.info(f"Testing with CSV: {csv_path}")
                    
                    if daemon._components.get('prediction_engine'):
                        prediction_engine = daemon._components['prediction_engine']
                        success = prediction_engine.force_process_file(csv_path)
                        if success:
                            logger.info("✓ CSV processing completed")
                            stats = prediction_engine.get_statistics()
                            logger.info(f"  Flows processed: {stats.get('total_flows_processed', 0)}")
                            logger.info(f"  Predictions made: {stats.get('total_predictions_made', 0)}")
                            logger.info(f"  Anomalies detected: {stats.get('anomalies_detected', 0)}")
                        else:
                            logger.error("✗ CSV processing failed")
                    else:
                        logger.error("✗ Prediction engine not initialized")
                else:
                    logger.error(f"✗ CSV file not found: {csv_path}")
            
            logger.info("=== Test Summary ===")
            logger.info("All requested tests completed")
            
            return 0
            
        except Exception as e:
            logger.error(f"Test failed: {e}")
            return 1
    
    def _cmd_emergency_stop(self, args) -> int:
        """Emergency stop command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        logger.info(f"Emergency stop activated: {args.reason}")
        
        try:
            daemon = self._load_daemon(args.config)
            success = daemon.emergency_stop(args.reason)
            
            if success:
                logger.info("Emergency stop activated successfully")
                return 0
            else:
                logger.error("Failed to activate emergency stop")
                return 1
                
        except Exception as e:
            logger.error(f"Emergency stop failed: {e}")
            return 1
    
    def _cmd_emergency_restore(self, args) -> int:
        """Emergency restore command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        logger.info(f"Emergency restore: {args.reason}")
        
        try:
            daemon = self._load_daemon(args.config)
            success = daemon.emergency_restore(args.reason)
            
            if success:
                logger.info("Emergency restore completed successfully")
                return 0
            else:
                logger.error("Failed to restore emergency state")
                return 1
                
        except Exception as e:
            logger.error(f"Emergency restore failed: {e}")
            return 1
    
    def _cmd_stats(self, args) -> int:
        """Statistics command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        try:
            config = load_aegis_config(args.config)
            status = self._get_daemon_status(config)
            
            if args.json:
                logger.info("Daemon statistics", extra={'stats': status})
            else:
                self._print_detailed_stats(status)
            
            return 0
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return 1
    
    def _cmd_model(self, args) -> int:
        """Model management command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        try:
            daemon = self._load_daemon(args.config)
            
            if not args.model_command:
                logger.error("Model subcommand required")
                return 1
            
            if args.model_command == 'load':
                logger.info("Loading latest model...")
                if daemon._components.get('model_manager'):
                    model_manager = daemon._components['model_manager']
                    success = model_manager.load_latest_model()
                    if success:
                        logger.info("✓ Model loaded successfully")
                    else:
                        logger.error("✗ Model loading failed")
                        return 1
                else:
                    logger.error("✗ Model manager not initialized")
                    return 1
            
            elif args.model_command == 'info':
                logger.info("Model information:")
                if daemon._components.get('model_manager'):
                    model_manager = daemon._components['model_manager']
                    info = model_manager.get_model_info()
                    
                    logger.info(f"  Model available: {info.get('model_available', False)}")
                    logger.info(f"  Model type: {info.get('model_type', 'None')}")
                    logger.info(f"  Scaler type: {info.get('scaler_type', 'None')}")
                    logger.info(f"  Last load: {info.get('last_load_time', 'Never')}")
                    logger.info(f"  Load failures: {info.get('load_failures', 0)}")
                    logger.info(f"  Fallback in use: {info.get('fallback_in_use', False)}")
                else:
                    logger.error("✗ Model manager not initialized")
                    return 1
            
            return 0
            
        except Exception as e:
            logger.error(f"Model command failed: {e}")
            return 1
    
    def _cmd_blacklist(self, args) -> int:
        """Blacklist management command.
        
        Args:
            args: Command arguments
            
        Returns:
            Exit code
        """
        try:
            daemon = self._load_daemon(args.config)
            
            if not args.blacklist_command:
                logger.error("Blacklist subcommand required")
                return 1
            
            if args.blacklist_command == 'list':
                if daemon._components.get('blacklist_manager'):
                    blacklist_manager = daemon._components['blacklist_manager']
                    # Consume generator
                    entries = list(blacklist_manager.get_blacklist_entries(
                        active_only=args.active_only,
                        risk_level=args.risk_level
                    ))
                    
                    if args.json:
                        logger.info("Blacklist entries", extra={'entries': entries})
                    else:
                        logger.info(f"Blacklist entries ({len(entries)} total):")
                        for entry in entries:
                            status = "ACTIVE" if entry['is_active'] else "INACTIVE"
                            expires = f" (expires: {entry['expires_at']})" if entry['expires_at'] else ""
                            logger.info(f"  {entry['ip_address']} - {entry['reason']} [{entry['risk_level']}] {status}{expires}")
                else:
                    logger.error("✗ Blacklist manager not initialized")
                    return 1
            
            elif args.blacklist_command == 'add':
                if daemon._components.get('blacklist_manager'):
                    blacklist_manager = daemon._components['blacklist_manager']
                    success = blacklist_manager.add_to_blacklist(
                        ip_address=args.ip_address,
                        reason=args.reason,
                        risk_level=args.risk_level,
                        ttl_hours=args.ttl_hours,
                        enforce=args.enforce
                    )
                    
                    if success:
                        logger.info(f"✓ Added {args.ip_address} to blacklist")
                    else:
                        logger.error(f"✗ Failed to add {args.ip_address} to blacklist")
                        return 1
                else:
                    logger.error("✗ Blacklist manager not initialized")
                    return 1
            
            elif args.blacklist_command == 'remove':
                if daemon._components.get('blacklist_manager'):
                    blacklist_manager = daemon._components['blacklist_manager']
                    success = blacklist_manager.remove_from_blacklist(
                        ip_address=args.ip_address,
                        source=args.source
                    )
                    
                    if success:
                        logger.info(f"✓ Removed {args.ip_address} from blacklist")
                    else:
                        logger.error(f"✗ Failed to remove {args.ip_address} from blacklist")
                        return 1
                else:
                    logger.error("✗ Blacklist manager not initialized")
                    return 1
            
            return 0
            
        except Exception as e:
            logger.error(f"Blacklist command failed: {e}")
            return 1

    def _cmd_feedback(self, args) -> int:
        """Handle feedback command.

        Args:
            args: Command arguments

        Returns:
            Exit code
        """
        if not args.false_positive:
            logger.error("Error: --false-positive <IP> is required")
            return 1

        try:
            daemon = self._load_daemon(args.config)

            if daemon._components.get('feedback_manager'):
                feedback_manager = daemon._components['feedback_manager']

                # 1. Report false positive (add to trusted list)
                success = feedback_manager.report_false_positive(
                    ip_address=args.false_positive,
                    reason=args.reason
                )

                if success:
                    logger.info(f"✓ Reported {args.false_positive} as false positive (trusted)")

                    # 2. Remove from blacklist if present
                    if daemon._components.get('blacklist_manager'):
                        blacklist_manager = daemon._components['blacklist_manager']
                        if blacklist_manager.is_blacklisted(args.false_positive):
                            rm_success = blacklist_manager.remove_from_blacklist(
                                args.false_positive,
                                source="feedback_correction"
                            )
                            if rm_success:
                                logger.info(f"✓ Removed {args.false_positive} from blacklist")
                            else:
                                logger.warning(f"⚠ Could not remove {args.false_positive} from blacklist")

                    # 3. Trigger incremental retrain
                    trigger_success = feedback_manager.trigger_retrain()
                    if trigger_success:
                        logger.info("✓ Triggered incremental model retraining")
                    else:
                        logger.error("✗ Failed to trigger retraining")

                    return 0
                else:
                    logger.error("✗ Failed to report false positive")
                    return 1
            else:
                logger.error("✗ Feedback manager not initialized")
                return 1

        except Exception as e:
            logger.error(f"Feedback command failed: {e}")
            return 1
    
    def _get_daemon_status(self, config) -> Dict[str, Any]:
        """Get daemon status without loading heavy components.

        Args:
            config: Aegis configuration object

        Returns:
            Status dictionary
        """
        # Check if running
        is_running = self._is_process_running(config.pid_file)

        status = {
            'health': {
                'overall_health': 'unknown',
                'service_info': {
                    'is_running': is_running
                },
                'component_details': {}
            },
            'statistics': {},
            'component_stats': {},  # Added for detailed stats
            'config_summary': {}
        }

        if not is_running:
            status['health']['overall_health'] = 'stopped'
            return status

        # Try to read stats file
        stats_file = Path(config.stats_file)
        if stats_file.exists():
            try:
                with open(stats_file, 'r') as f:
                    file_stats = json.load(f)

                daemon_stats = file_stats.get('daemon_stats', {})
                component_stats = file_stats.get('component_stats', {})

                status['statistics'] = daemon_stats
                status['component_stats'] = component_stats
                status['config_summary'] = file_stats.get('config_summary', {})

                # Reconstruct health info
                start_time = daemon_stats.get('service_start_time')
                if start_time:
                    status['health']['service_info']['start_time'] = start_time
                    try:
                        start_dt = datetime.fromisoformat(start_time)
                        uptime = (datetime.now() - start_dt).total_seconds()
                        status['health']['service_info']['uptime_seconds'] = uptime
                    except Exception:
                        pass

                # Dry run
                dry_run_end = daemon_stats.get('dry_run_end_time')
                if dry_run_end:
                    try:
                        end_dt = datetime.fromisoformat(dry_run_end)
                        remaining = (end_dt - datetime.now()).total_seconds() / (24 * 3600)
                        status['health']['service_info']['dry_run_remaining_days'] = max(0, remaining)
                    except Exception:
                        pass

                # Calculate healthy components approximation
                components_healthy = 0
                total_components = 0

                if 'model_manager' in component_stats:
                    total_components += 1
                    info = component_stats['model_manager']
                    is_available = info.get('model_available', False)
                    if is_available:
                        components_healthy += 1
                    status['health']['component_details']['model_manager'] = {
                        'healthy': is_available,
                        'model_info': info
                    }

                if 'blacklist_manager' in component_stats:
                    total_components += 1
                    components_healthy += 1  # Assume healthy if stats exist
                    status['health']['component_details']['blacklist_manager'] = {
                        'healthy': True,
                        'stats': component_stats['blacklist_manager']
                    }

                if 'prediction_engine' in component_stats:
                    total_components += 1
                    components_healthy += 1  # Assume healthy if stats exist
                    status['health']['component_details']['prediction_engine'] = {
                        'healthy': True,
                        'stats': component_stats['prediction_engine']
                    }

                status['health']['components_healthy'] = components_healthy
                status['health']['total_components'] = total_components

                if total_components > 0:
                    health_ratio = components_healthy / total_components
                    if health_ratio >= 0.8:
                        status['health']['overall_health'] = 'healthy'
                    elif health_ratio >= 0.5:
                        status['health']['overall_health'] = 'degraded'
                    else:
                        status['health']['overall_health'] = 'unhealthy'

            except Exception as e:
                logger.warning(f"Failed to read stats file: {e}")

        return status

    def _is_process_running(self, pid_file: str) -> bool:
        """Check if process is running based on PID file.
        
        Args:
            pid_file: Path to PID file
            
        Returns:
            True if process is running, False otherwise
        """
        try:
            if not Path(pid_file).exists():
                return False
            
            with open(pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process exists
            os.kill(pid, 0)
            return True
            
        except (ValueError, OSError, FileNotFoundError):
            return False
    
    def _force_stop_daemon(self, pid_file: str) -> None:
        """Force stop daemon by killing the process.
        
        Args:
            pid_file: Path to PID file
        """
        try:
            if Path(pid_file).exists():
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                
                os.kill(pid, signal.SIGKILL)
                logger.warning(f"Force killed process {pid}")
                
                # Remove PID file
                Path(pid_file).unlink()
                
        except (ValueError, OSError, FileNotFoundError):
            pass
    
    def _print_status(self, status: Dict[str, Any]) -> None:
        """Print formatted status information.
        
        Args:
            status: Status dictionary
        """
        health = status.get('health', {})
        daemon_stats = status.get('statistics', {})
        
        logger.info("Aegis Daemon Status")
        logger.info("==================")
        
        overall_health = health.get('overall_health', 'unknown')
        health_icons = {
            'healthy': '✓',
            'degraded': '⚠',
            'unhealthy': '✗',
            'error': '✗'
        }
        icon = health_icons.get(overall_health, '?')
        
        logger.info(f"Overall Health: {icon} {overall_health.upper()}")
        
        service_info = health.get('service_info', {})
        is_running = service_info.get('is_running', False)
        running_icon = '✓' if is_running else '✗'
        
        logger.info(f"Service Status: {running_icon} {'RUNNING' if is_running else 'STOPPED'}")
        
        if service_info.get('start_time'):
            logger.info(f"Start Time: {service_info['start_time']}")
        
        if service_info.get('uptime_seconds'):
            uptime = service_info['uptime_seconds']
            hours = int(uptime // 3600)
            minutes = int((uptime % 3600) // 60)
            logger.info(f"Uptime: {hours}h {minutes}m")
        
        if service_info.get('dry_run_remaining_days') is not None:
            remaining = service_info['dry_run_remaining_days']
            if remaining > 0:
                logger.info(f"Dry Run: {remaining:.1f} days remaining")
            else:
                logger.info("Dry Run: EXPIRED (enforcement active)")
        
        components = health.get('component_details', {})
        logger.info(f"\\nComponents ({health.get('components_healthy', 0)}/{health.get('total_components', 0)} healthy):")
        
        for name, details in components.items():
            healthy = details.get('healthy', False)
            icon = '✓' if healthy else '✗'
            logger.info(f"  {icon} {name}")
    
    def _print_health(self, health: Dict[str, Any]) -> None:
        """Print formatted health information.
        
        Args:
            health: Health dictionary
        """
        logger.info("Aegis Health Report")
        logger.info("===================")
        
        overall = health.get('overall_health', 'unknown')
        logger.info(f"Overall Health: {overall.upper()}")
        
        service_info = health.get('service_info', {})
        if service_info:
            logger.info("\\nService Information:")
            for key, value in service_info.items():
                logger.info(f"  {key}: {value}")
        
        components = health.get('component_details', {})
        if components:
            logger.info("\\nComponent Details:")
            for name, details in components.items():
                logger.info(f"  {name}:")
                for key, value in details.items():
                    logger.info(f"    {key}: {value}")
        
        if health.get('error'):
            logger.info(f"\\nError: {health['error']}")
    
    def _print_detailed_stats(self, status: Dict[str, Any]) -> None:
        """Print detailed statistics.
        
        Args:
            status: Status dictionary
        """
        logger.info("Aegis Detailed Statistics")
        logger.info("=========================")
        
        daemon_stats = status.get('statistics', {})
        component_stats = status.get('component_stats', {})
        
        if daemon_stats:
            logger.info("\\nDaemon Statistics:")
            for key, value in daemon_stats.items():
                logger.info(f"  {key}: {value}")
        
        if component_stats:
            logger.info("\\nComponent Statistics:")
            for component, stats in component_stats.items():
                logger.info(f"  {component}:")
                for key, value in stats.items():
                    logger.info(f"    {key}: {value}")


def main() -> int:
    """Main entry point for CLI.
    
    Returns:
        Exit code
    """
    cli = AegisCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())