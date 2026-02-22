"""Aegis shield runtime daemon for Raspberry Pi.

This module provides the main daemon service that orchestrates the Aegis shield
runtime, including model management, prediction processing, and blacklist enforcement
with proper dry-run mode handling and service lifecycle management.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from ..oracle_core.logging import configure_logging, log_event
from .blacklist_manager import BlacklistManager
from .config import load_aegis_config
from .feedback_manager import FeedbackManager
from .model_manager import ModelManager
from .prediction_engine import PredictionEngine

logger = logging.getLogger(__name__)


class AegisDaemonError(Exception):
    """Base exception for Aegis daemon operations."""
    pass


class ServiceStartError(AegisDaemonError):
    """Exception raised when service fails to start."""
    pass


class ServiceStopError(AegisDaemonError):
    """Exception raised when service fails to stop."""
    pass


class HealthCheckError(AegisDaemonError):
    """Exception raised when health check fails."""
    pass


class AegisDaemon:
    """Main daemon service for Aegis shield runtime."""
    
    def __init__(self, config_path: str):
        """Initialize Aegis daemon.
        
        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_aegis_config(config_path)
        
        # Configure logging
        self._setup_logging()
        
        # Service state
        self._running = False
        self._shutdown_event = threading.Event()
        self._start_time = None
        self._components = {}
        
        # Statistics and monitoring
        self._stats = {
            'service_start_time': None,
            'total_runtime_seconds': 0,
            'components_started': [],
            'components_failed': [],
            'health_checks_passed': 0,
            'health_checks_failed': 0,
            'last_health_check': None,
            'dry_run_end_time': None,
            'emergency_stops': 0,
            'configuration_issues': []
        }
        
        # Initialize components
        self._initialize_components()
        
        log_event(
            logger,
            "aegis_daemon_initialized",
            level="info",
            config_summary=self.config.to_safe_dict()
        )
    
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        
        # Configure logging with structured output
        configure_logging(
            level=log_level
        )
    
    def _initialize_components(self) -> None:
        """Initialize all Aegis components."""
        try:
            log_event(
                logger,
                "components_initialization_started",
                level="info"
            )
            
            # Initialize core components
            self._components['anonymizer'] = None  # Will be initialized in start()
            self._components['model_manager'] = None
            self._components['blacklist_manager'] = None  
            self._components['prediction_engine'] = None
            
            # Validate configuration
            config_issues = self._validate_configuration()
            if config_issues:
                self._stats['configuration_issues'] = config_issues
                log_event(
                    logger,
                    "configuration_issues_detected",
                    level="warning",
                    issues=config_issues
                )
            
            log_event(
                logger,
                "components_initialization_completed",
                level="info"
            )
            
        except Exception as e:
            log_event(
                logger,
                "components_initialization_failed",
                level="error",
                error=str(e)
            )
            raise ServiceStartError(f"Component initialization failed: {e}")
    
    def _validate_configuration(self) -> list[str]:
        """Validate daemon configuration.
        
        Returns:
            List of configuration issues found
        """
        issues = []
        
        try:
            # Check directory permissions
            required_dirs = [
                Path(self.config.model.model_local_path).parent,
                Path(self.config.model.scaler_local_path).parent,
                Path(self.config.state_file).parent,
                Path(self.config.stats_file).parent
            ]
            
            for dir_path in required_dirs:
                if not dir_path.exists():
                    try:
                        dir_path.mkdir(parents=True, exist_ok=True)
                    except Exception as e:
                        issues.append(f"Cannot create directory {dir_path}: {e}")
                elif not os.access(dir_path, os.W_OK):
                    issues.append(f"No write permission for directory {dir_path}")
            
            # Check file paths
            if Path(self.config.enforcement.emergency_stop_file).parent != Path('/'):
                emergency_dir = Path(self.config.enforcement.emergency_stop_file).parent
                if not emergency_dir.exists():
                    try:
                        emergency_dir.mkdir(parents=True, exist_ok=True)
                    except Exception as e:
                        issues.append(f"Cannot create emergency stop directory: {e}")
            
            # Validate configuration values
            if self.config.model.min_model_age_hours >= self.config.model.max_model_age_days * 24:
                issues.append("min_model_age_hours should be less than max_model_age_days")
            
            if self.config.prediction.anomaly_threshold >= self.config.prediction.high_risk_threshold:
                issues.append("anomaly_threshold must be less than high_risk_threshold")
            
            if self.config.enforcement.dry_run_duration_days < 1:
                issues.append("dry_run_duration_days must be at least 1")
            
            # Check Firebase configuration if specified
            if self.config.firebase:
                if not self.config.firebase.project_id:
                    issues.append("Firebase project_id is required")
                if not self.config.firebase.api_key:
                    issues.append("Firebase api_key is required")
            
        except Exception as e:
            issues.append(f"Configuration validation error: {e}")
        
        return issues
    
    def start(self) -> bool:
        """Start the Aegis daemon service.
        
        Returns:
            True if started successfully, False otherwise
        """
        try:
            if self._running:
                log_event(
                    logger,
                    "aegis_daemon_already_running",
                    level="warning"
                )
                return True
            
            log_event(
                logger,
                "aegis_daemon_starting",
                level="info"
            )
            
            # Set up signal handlers
            self._setup_signal_handlers()
            
            # Initialize anonymizer
            from ..oracle_core.anonymize import HashAnonymizer
            anonymizer = HashAnonymizer(salt=self.config.anonymization_salt)
            self._components['anonymizer'] = anonymizer
            
            # Initialize model manager
            model_manager = ModelManager(
                config=self.config.model,
                anonymizer=anonymizer,
                feature_columns=self.config.prediction.feature_columns,
            )
            model_manager.anomaly_threshold = self.config.prediction.anomaly_threshold
            model_manager.high_risk_threshold = self.config.prediction.high_risk_threshold
            self._components['model_manager'] = model_manager
            
            # Initialize blacklist manager
            blacklist_manager = BlacklistManager(
                config=self.config.enforcement,
                anonymizer=anonymizer
            )
            self._components['blacklist_manager'] = blacklist_manager
            
            # Initialize feedback manager (Active Learning)
            feedback_manager = FeedbackManager(self.config)
            self._components['feedback_manager'] = feedback_manager

            # Initialize prediction engine
            prediction_engine = PredictionEngine(
                polling_config=self.config.polling,
                prediction_config=self.config.prediction,
                model_manager=model_manager,
                blacklist_manager=blacklist_manager,
                anonymizer=anonymizer,
                feedback_manager=feedback_manager
            )
            self._components['prediction_engine'] = prediction_engine
            
            # Load initial model
            if not model_manager.load_latest_model():
                log_event(
                    logger,
                    "initial_model_load_failed",
                    level="warning"
                )
            
            # Start prediction engine
            if not prediction_engine.start():
                raise ServiceStartError("Failed to start prediction engine")
            
            # Calculate dry run end time
            self._stats['dry_run_end_time'] = (
                datetime.now() + timedelta(days=self.config.enforcement.dry_run_duration_days)
            ).isoformat()
            
            # Set running state
            self._running = True
            self._start_time = datetime.now()
            self._stats['service_start_time'] = self._start_time.isoformat()
            
            # Start background monitoring thread
            monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                name="Aegis-Monitor",
                daemon=True
            )
            monitor_thread.start()
            
            log_event(
                logger,
                "aegis_daemon_started",
                level="info",
                dry_run_duration_days=self.config.enforcement.dry_run_duration_days,
                dry_run_end_time=self._stats['dry_run_end_time'],
                components=list(self._components.keys())
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "aegis_daemon_start_failed",
                level="error",
                error=str(e)
            )
            self._running = False
            return False
    
    def stop(self, timeout: Optional[int] = None) -> bool:
        """Stop the Aegis daemon service.
        
        Args:
            timeout: Timeout in seconds for graceful shutdown
            
        Returns:
            True if stopped successfully, False otherwise
        """
        try:
            if not self._running:
                log_event(
                    logger,
                    "aegis_daemon_not_running",
                    level="debug"
                )
                return True
            
            timeout = timeout or self.config.shutdown_timeout
            
            log_event(
                logger,
                "aegis_daemon_stopping",
                level="info",
                timeout=timeout
            )
            
            # Signal shutdown
            self._running = False
            self._shutdown_event.set()
            
            # Stop prediction engine
            prediction_engine = self._components.get('prediction_engine')
            if prediction_engine:
                if not prediction_engine.stop(timeout // 2):
                    log_event(
                        logger,
                        "prediction_engine_stop_failed",
                        level="warning"
                    )
            
            # Wait for monitoring thread
            time.sleep(1)
            
            # Update statistics
            if self._start_time:
                runtime = datetime.now() - self._start_time
                self._stats['total_runtime_seconds'] = runtime.total_seconds()
            
            log_event(
                logger,
                "aegis_daemon_stopped",
                level="info",
                total_runtime_seconds=self._stats['total_runtime_seconds']
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "aegis_daemon_stop_failed",
                level="error",
                error=str(e)
            )
            return False
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            log_event(
                logger,
                "signal_received",
                level="info",
                signal=signum
            )
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
    
    def _monitoring_loop(self) -> None:
        """Background monitoring and maintenance loop."""
        while self._running:
            try:
                # Health check
                self._perform_health_check()
                
                # Update statistics
                self._update_statistics()
                
                # Cleanup expired blacklist entries
                blacklist_manager = self._components.get('blacklist_manager')
                if blacklist_manager:
                    blacklist_manager.cleanup_expired_entries()
                
                # Sync with Firebase if enabled
                if (blacklist_manager and 
                    self._should_sync_firebase()):
                    blacklist_manager.sync_with_firebase()
                
                # Sleep for monitoring interval
                time.sleep(60)  # Monitor every minute
                
            except Exception as e:
                log_event(
                    logger,
                    "monitoring_loop_error",
                    level="error",
                    error=str(e)
                )
                time.sleep(30)  # Shorter sleep on error
    
    def _perform_health_check(self) -> None:
        """Perform health check on all components."""
        try:
            health_status = self.get_health_status()
            
            if health_status['overall_health'] == 'healthy':
                self._stats['health_checks_passed'] += 1
            else:
                self._stats['health_checks_failed'] += 1
            
            self._stats['last_health_check'] = datetime.now().isoformat()
            
            log_event(
                logger,
                "health_check_completed",
                level="debug",
                overall_health=health_status['overall_health'],
                components_healthy=health_status['components_healthy'],
                total_components=health_status['total_components']
            )
            
        except Exception as e:
            self._stats['health_checks_failed'] += 1
            log_event(
                logger,
                "health_check_failed",
                level="error",
                error=str(e)
            )
    
    def _should_sync_firebase(self) -> bool:
        """Check if Firebase sync should be performed.
        
        Returns:
            True if sync should be performed, False otherwise
        """
        # Check if Firebase is configured
        if not self.config.firebase:
            return False
        
        # Check if enough time has passed since last sync
        # For now, sync every hour
        blacklist_manager = self._components.get('blacklist_manager')
        if not blacklist_manager:
            return False
        
        last_sync = blacklist_manager._last_sync_time
        if not last_sync:
            return True
        
        time_since_sync = datetime.now() - last_sync
        return time_since_sync.total_seconds() >= 3600  # 1 hour
    
    def _update_statistics(self) -> None:
        """Update daemon statistics."""
        try:
            # Gather component statistics
            component_stats = {}
            
            for name, component in self._components.items():
                if component:
                    if hasattr(component, 'get_statistics'):
                        component_stats[name] = component.get_statistics()
                    elif hasattr(component, 'get_model_info'):
                        component_stats[name] = component.get_model_info()
            
            # Combine all statistics
            all_stats = {
                'daemon_stats': self._stats,
                'component_stats': component_stats,
                'config_summary': self.config.to_safe_dict(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Write to statistics file
            stats_file = Path(self.config.stats_file)
            stats_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(stats_file, 'w') as f:
                json.dump(all_stats, f, indent=2, default=str)
            
        except Exception as e:
            log_event(
                logger,
                "statistics_update_failed",
                level="error",
                error=str(e)
            )
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status of the daemon.
        
        Returns:
            Dictionary containing health status information
        """
        try:
            status = {
                'overall_health': 'healthy',
                'components_healthy': 0,
                'total_components': 0,
                'component_details': {},
                'service_info': {
                    'is_running': self._running,
                    'start_time': self._start_time.isoformat() if self._start_time else None,
                    'uptime_seconds': (
                        (datetime.now() - self._start_time).total_seconds() 
                        if self._start_time else 0
                    ),
                    'dry_run_remaining_days': self._get_dry_run_remaining_days()
                }
            }
            
            # Check model manager
            model_manager = self._components.get('model_manager')
            if model_manager:
                status['total_components'] += 1
                model_healthy = model_manager.is_model_available()
                if model_healthy:
                    status['components_healthy'] += 1
                
                status['component_details']['model_manager'] = {
                    'healthy': model_healthy,
                    'model_info': model_manager.get_model_info()
                }
            
            # Check blacklist manager
            blacklist_manager = self._components.get('blacklist_manager')
            if blacklist_manager:
                status['total_components'] += 1
                blacklist_healthy = True  # Blacklist manager is generally healthy
                if blacklist_healthy:
                    status['components_healthy'] += 1
                
                status['component_details']['blacklist_manager'] = {
                    'healthy': blacklist_healthy,
                    'stats': blacklist_manager.get_statistics()
                }
            
            # Check prediction engine
            prediction_engine = self._components.get('prediction_engine')
            if prediction_engine:
                status['total_components'] += 1
                pred_healthy = prediction_engine._running
                if pred_healthy:
                    status['components_healthy'] += 1
                
                status['component_details']['prediction_engine'] = {
                    'healthy': pred_healthy,
                    'stats': prediction_engine.get_statistics()
                }
            
            # Determine overall health
            if status['total_components'] > 0:
                health_ratio = status['components_healthy'] / status['total_components']
                if health_ratio >= 0.8:
                    status['overall_health'] = 'healthy'
                elif health_ratio >= 0.5:
                    status['overall_health'] = 'degraded'
                else:
                    status['overall_health'] = 'unhealthy'
            
            return status
            
        except Exception as e:
            return {
                'overall_health': 'error',
                'error': str(e),
                'service_info': {
                    'is_running': self._running
                }
            }
    
    def _get_dry_run_remaining_days(self) -> float:
        """Get remaining days in dry run mode.
        
        Returns:
            Number of remaining days in dry run mode (negative if enforced)
        """
        if not self._start_time or not self._stats.get('dry_run_end_time'):
            return self.config.enforcement.dry_run_duration_days
        
        try:
            end_time = datetime.fromisoformat(self._stats['dry_run_end_time'])
            remaining = (end_time - datetime.now()).total_seconds() / (24 * 3600)
            return max(0, remaining)
        except Exception:
            return 0.0
    
    def get_status(self) -> Dict[str, Any]:
        """Get detailed status of the daemon.
        
        Returns:
            Dictionary containing status information
        """
        return {
            'health': self.get_health_status(),
            'statistics': self._stats,
            'configuration': self.config.to_safe_dict(),
            'components': {
                name: (type(component).__name__ if component else None)
                for name, component in self._components.items()
            }
        }
    
    def emergency_stop(self, reason: str = "Manual emergency stop") -> bool:
        """Emergency stop all enforcement actions.
        
        Args:
            reason: Reason for emergency stop
            
        Returns:
            True if emergency stop activated successfully
        """
        try:
            # Stop prediction engine to stop processing
            prediction_engine = self._components.get('prediction_engine')
            if prediction_engine:
                prediction_engine.stop()
            
            # Activate emergency stop in blacklist manager
            blacklist_manager = self._components.get('blacklist_manager')
            if blacklist_manager:
                blacklist_manager.emergency_stop(reason)
            
            self._stats['emergency_stops'] += 1
            
            log_event(
                logger,
                "emergency_stop_activated",
                level="critical",
                reason=reason
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "emergency_stop_failed",
                level="error",
                error=str(e)
            )
            return False
    
    def emergency_restore(self, reason: str = "Manual emergency restore") -> bool:
        """Restore normal operations after emergency stop.
        
        Args:
            reason: Reason for restoration
            
        Returns:
            True if emergency restored successfully
        """
        try:
            # Restore blacklist manager
            blacklist_manager = self._components.get('blacklist_manager')
            if blacklist_manager:
                blacklist_manager.emergency_restore(reason)
            
            # Restart prediction engine if still running
            prediction_engine = self._components.get('prediction_engine')
            if prediction_engine and not prediction_engine._running:
                prediction_engine.start()
            
            log_event(
                logger,
                "emergency_restored",
                level="info",
                reason=reason
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "emergency_restore_failed",
                level="error",
                error=str(e)
            )
            return False