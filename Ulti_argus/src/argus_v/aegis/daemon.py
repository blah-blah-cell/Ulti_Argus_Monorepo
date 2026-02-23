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
import sqlite3
import sys
import threading
import time
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import yaml
from prometheus_client import Counter, Gauge, Histogram, start_http_server
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel

from ..oracle_core.config import ValidationError
from ..oracle_core.logging import configure_logging, log_event
from .blacklist_manager import BlacklistManager
from .config import load_aegis_config
from .feedback_manager import FeedbackManager
from .model_manager import ModelManager
from .prediction_engine import PredictionEngine

try:
    from ..kronos.ipc_listener import IPCListener
    from ..kronos.router import KronosRouter
    _KRONOS_AVAILABLE = True
except ImportError:
    _KRONOS_AVAILABLE = False

logger = logging.getLogger(__name__)

# Prometheus Metrics
AEGIS_FLOWS_ANALYZED = Counter('aegis_flows_analyzed_total', 'Total number of flows analyzed')
AEGIS_ANOMALIES_DETECTED = Counter('aegis_anomalies_detected_total', 'Total number of anomalies detected')
AEGIS_ACTIVE_BLOCKS = Gauge('aegis_active_blocks_gauge', 'Number of currently active IP blocks')
AEGIS_INFERENCE_LATENCY = Histogram('aegis_inference_latency_seconds', 'Inference latency in seconds')
AEGIS_MODEL_ACCURACY = Gauge('aegis_model_accuracy', 'Current model accuracy score')


# API Models
class BlockRequest(BaseModel):
    reason: str = "Manual blacklist"
    risk_level: str = "medium"
    ttl_hours: Optional[int] = None


app = FastAPI(title="Aegis Daemon API")


@app.post("/api/whitelist/{ip}")
async def whitelist_ip(ip: str):
    """Manually whitelist an IP address."""
    daemon = getattr(app.state, "daemon", None)
    if not daemon or not daemon._components.get('blacklist_manager'):
        raise HTTPException(status_code=503, detail="Daemon or BlacklistManager not available")

    success = daemon._components['blacklist_manager'].remove_from_blacklist(ip, source="manual")
    if not success:
        raise HTTPException(status_code=400, detail="Failed to whitelist IP")
    return {"message": f"IP {ip} whitelisted"}


@app.post("/api/blacklist/{ip}")
async def blacklist_ip(ip: str, request: BlockRequest):
    """Manually blacklist an IP address."""
    daemon = getattr(app.state, "daemon", None)
    if not daemon or not daemon._components.get('blacklist_manager'):
        raise HTTPException(status_code=503, detail="Daemon or BlacklistManager not available")

    success = daemon._components['blacklist_manager'].add_to_blacklist(
        ip_address=ip,
        reason=request.reason,
        risk_level=request.risk_level,
        ttl_hours=request.ttl_hours,
        source="manual",
        enforce=True
    )
    if not success:
        raise HTTPException(status_code=400, detail="Failed to blacklist IP")
    return {"message": f"IP {ip} blacklisted"}


@app.post("/api/retrain")
async def trigger_retrain():
    """Trigger emergency model retraining."""
    daemon = getattr(app.state, "daemon", None)
    if not daemon or not daemon._components.get('feedback_manager'):
        raise HTTPException(status_code=503, detail="Daemon or FeedbackManager not available")

    success = daemon._components['feedback_manager'].trigger_retrain()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to trigger retraining")
    return {"message": "Retraining triggered"}


@app.get("/api/status")
async def get_status():
    """Get daemon health status."""
    daemon = getattr(app.state, "daemon", None)
    if not daemon:
        raise HTTPException(status_code=503, detail="Daemon not available")
    return daemon.get_health_status()


@app.get("/api/metrics")
async def get_metrics():
    """Get live telemetry data."""
    daemon = getattr(app.state, "daemon", None)
    if not daemon:
        raise HTTPException(status_code=503, detail="Daemon not available")

    # Combine daemon stats and component stats
    stats = daemon._stats.copy()

    # Add prediction stats if available
    prediction_engine = daemon._components.get('prediction_engine')
    if prediction_engine:
        stats['prediction_engine'] = prediction_engine.get_statistics()

    return stats


@app.get("/api/blacklist")
async def get_blacklist(active_only: bool = True, limit: int = 15):
    """Get list of blacklisted IPs."""
    daemon = getattr(app.state, "daemon", None)
    if not daemon or not daemon._components.get('blacklist_manager'):
        raise HTTPException(status_code=503, detail="Daemon or BlacklistManager not available")

    entries = daemon._components['blacklist_manager'].get_blacklist_entries(
        active_only=active_only,
        limit=limit
    )
    return list(entries)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for live updates."""
    await websocket.accept()
    daemon = getattr(app.state, "daemon", None)
    try:
        while True:
            if daemon:
                # Gather data
                prediction_engine = daemon._components.get('prediction_engine')
                pe_stats = prediction_engine.get_statistics() if prediction_engine else {}

                # Try to get active blocks count
                blacklist_manager = daemon._components.get('blacklist_manager')
                active_blocks = blacklist_manager._stats.get('active_entries', 0) if blacklist_manager else 0

                data = {
                    "health": daemon.get_health_status(),
                    "stats": daemon._stats,
                    "prediction_stats": pe_stats,
                    "active_blocks": active_blocks,
                    "timestamp": datetime.now().isoformat()
                }
                await websocket.send_json(data)
            else:
                await websocket.send_json({"error": "Daemon not ready"})

            await asyncio.sleep(1)  # Update every second
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")


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


class OnlineLearningThread(threading.Thread):
    """Background thread for continuous online learning."""

    def __init__(self, prediction_engine: PredictionEngine, db_path: Path):
        """Initialize online learning thread.

        Args:
            prediction_engine: Reference to the prediction engine.
            db_path: Path to the SQLite database for buffering.
        """
        super().__init__(name="Aegis-OnlineLearning", daemon=True)
        self.prediction_engine = prediction_engine
        self.db_path = db_path
        self._stop_event = threading.Event()
        self.batch_size_trigger = 1000

    def run(self) -> None:
        """Run the online learning loop."""
        log_event(logger, "online_learning_thread_started", db_path=str(self.db_path))

        # Ensure DB directory exists
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            log_event(logger, "online_learning_db_dir_error", error=str(e))
            return

        while not self._stop_event.is_set():
            try:
                # Sleep for 5 minutes (interruptible)
                if self._stop_event.wait(300):
                    break

                self._process_buffer()

            except Exception as e:
                log_event(logger, "online_learning_loop_error", error=str(e))
                # Prevent tight loop on error
                time.sleep(60)

    def _process_buffer(self) -> None:
        """Process buffered events and trigger training if ready."""
        # 1. Drain queue
        events = []
        try:
            while not self.prediction_engine.borderline_events_queue.empty():
                events.append(self.prediction_engine.borderline_events_queue.get_nowait())
        except Exception:
            pass

        if not events and not self.db_path.exists():
            return

        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Create table if needed
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learning_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    features TEXT,
                    score REAL,
                    timestamp TEXT
                )
            """)

            # Insert new events
            if events:
                data_to_insert = [
                    (json.dumps(e['features']), e['score'], e['timestamp'])
                    for e in events
                ]
                cursor.executemany(
                    "INSERT INTO learning_buffer (features, score, timestamp) VALUES (?, ?, ?)",
                    data_to_insert
                )
                conn.commit()
                log_event(logger, "online_learning_buffer_updated", new_events=len(events))

            # Check buffer size
            cursor.execute("SELECT COUNT(*) FROM learning_buffer")
            count = cursor.fetchone()[0]

            if count >= self.batch_size_trigger:
                self._trigger_partial_fit(conn, count)

        except Exception as e:
            log_event(logger, "online_learning_db_error", error=str(e))
        finally:
            if conn:
                conn.close()

    def _trigger_partial_fit(self, conn: sqlite3.Connection, count: int) -> None:
        """Trigger partial fit on the model using buffered data."""
        try:
            # Fetch data
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, features FROM learning_buffer ORDER BY id ASC LIMIT ?",
                (self.batch_size_trigger,)
            )
            rows = cursor.fetchall()

            if not rows:
                return

            ids = [r[0] for r in rows]
            feature_list = [json.loads(r[1]) for r in rows]

            # Convert to DataFrame/Array
            # We need to ensure correct column order matching the model
            feature_columns = self.prediction_engine.model_manager.feature_columns

            X = []
            for f_dict in feature_list:
                row_vector = [f_dict.get(col, 0) for col in feature_columns]
                X.append(row_vector)

            X_arr = np.array(X)

            # Access the model (thread-safe access would be ideal, but partial_fit handles internal state)
            # We acquire the lock to prevent swapping during update
            with self.prediction_engine._model_lock:
                model = self.prediction_engine.model_manager._model

                if model is None:
                    log_event(logger, "online_learning_skipped_no_model")
                    return

                updated = False
                if hasattr(model, "partial_fit"):
                    model.partial_fit(X_arr)
                    updated = True
                    log_event(logger, "online_learning_partial_fit_applied", sample_count=len(X_arr))
                elif hasattr(model, "warm_start") and getattr(model, "warm_start", False):
                    # For IsolationForest with warm_start=True, fit adds more trees
                    model.fit(X_arr)
                    updated = True
                    log_event(logger, "online_learning_warm_start_fit_applied", sample_count=len(X_arr))
                else:
                    log_event(logger, "online_learning_model_not_supported")

            # Clean up buffer regardless of success to prevent stuck queue?
            # Or only on success? If model doesn't support it, we should probably clear to avoid infinite growth.
            # If update failed due to error, we might want to retry, but for "not supported", we clear.
            # Let's clear the processed rows.

            placeholders = ','.join(['?'] * len(ids))
            cursor.execute(f"DELETE FROM learning_buffer WHERE id IN ({placeholders})", ids)
            conn.commit()

            log_event(logger, "online_learning_buffer_cleared", count=len(ids))

        except Exception as e:
            log_event(logger, "online_learning_update_failed", error=str(e))

    def stop(self) -> None:
        """Stop the online learning thread."""
        self._stop_event.set()


class AegisDaemon:
    """Main daemon service for Aegis shield runtime."""
    
    def __init__(self, config_path: str):
        """Initialize Aegis daemon.
        
        Args:
            config_path: Path to configuration file

        Raises:
            ServiceStartError: If configuration loading fails
        """
        if not config_path:
            raise ServiceStartError("Configuration path cannot be empty")

        if not os.path.exists(config_path):
            raise ServiceStartError(f"Configuration file not found: {config_path}")

        try:
            # Load configuration
            self.config = load_aegis_config(config_path)
        except (OSError, ValueError, yaml.YAMLError, ValidationError) as e:
            raise ServiceStartError(f"Failed to load configuration: {e}")
        except Exception as e:
            raise ServiceStartError(f"Unexpected error loading configuration: {e}")
        
        # Configure logging
        try:
            self._setup_logging()
        except Exception as e:
            # Fallback basic logging if setup fails
            logging.basicConfig(level=logging.INFO)
            logger.error(f"Failed to setup logging: {e}")
        
        # Service state
        self._running = False
        self._shutdown_event = threading.Event()
        self._start_time = None
        self._api_server = None  # Uvicorn server instance
        self._components = {
            'anonymizer': None,
            'model_manager': None,
            'blacklist_manager': None,
            'feedback_manager': None,
            'kronos_router': None,
            'ipc_listener': None,
            'prediction_engine': None,
            'online_learning_thread': None
        }
        
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
        
        # Initialize components structure
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
        """Initialize Aegis components structure and validate config."""
        try:
            log_event(
                logger,
                "components_initialization_started",
                level="info"
            )
            
            # Components are already pre-filled with None in __init__
            # This method now primarily focuses on validation before heavy lifting in start()
            
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
                "components_structure_initialized",
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
            try:
                self._setup_signal_handlers()
            except Exception as e:
                # Critical failure: cannot handle signals
                raise ServiceStartError(f"Failed to setup signal handlers: {e}")
            
            # Initialize components step-by-step
            try:
                # Initialize anonymizer
                try:
                    from ..oracle_core.anonymize import HashAnonymizer
                    anonymizer = HashAnonymizer(salt=self.config.anonymization_salt)
                    self._components['anonymizer'] = anonymizer
                except Exception as e:
                    raise ServiceStartError(f"Failed to initialize anonymizer: {e}")

                # Initialize model manager
                try:
                    model_manager = ModelManager(
                        config=self.config.model,
                        anonymizer=anonymizer,
                        feature_columns=self.config.prediction.feature_columns,
                    )
                    model_manager.anomaly_threshold = self.config.prediction.anomaly_threshold
                    model_manager.high_risk_threshold = self.config.prediction.high_risk_threshold
                    self._components['model_manager'] = model_manager
                except Exception as e:
                    raise ServiceStartError(f"Failed to initialize ModelManager: {e}")

                # Initialize blacklist manager
                try:
                    blacklist_manager = BlacklistManager(
                        config=self.config.enforcement,
                        anonymizer=anonymizer
                    )
                    self._components['blacklist_manager'] = blacklist_manager
                except Exception as e:
                    raise ServiceStartError(f"Failed to initialize BlacklistManager: {e}")

                # Initialize feedback manager (Active Learning)
                try:
                    feedback_manager = FeedbackManager(self.config)
                    self._components['feedback_manager'] = feedback_manager
                except Exception as e:
                    raise ServiceStartError(f"Failed to initialize FeedbackManager: {e}")

                # Initialize Kronos components if available
                kronos_router = None
                ipc_listener = None
                if _KRONOS_AVAILABLE:
                    try:
                        kronos_router = KronosRouter()
                        ipc_listener = IPCListener()
                        ipc_listener.start()
                        self._components['kronos_router'] = kronos_router
                        self._components['ipc_listener'] = ipc_listener
                        log_event(logger, "kronos_components_initialized", level="info")
                    except Exception as k_err:
                        log_event(logger, "kronos_initialization_failed", level="warning", error=str(k_err))
                        # Non-critical failure, continue with local mode
                        kronos_router = None
                        ipc_listener = None

                # Initialize prediction engine
                try:
                    metrics = {
                        'flows_analyzed': AEGIS_FLOWS_ANALYZED,
                        'anomalies_detected': AEGIS_ANOMALIES_DETECTED,
                        'inference_latency': AEGIS_INFERENCE_LATENCY
                    }
                    prediction_engine = PredictionEngine(
                        polling_config=self.config.polling,
                        prediction_config=self.config.prediction,
                        model_manager=model_manager,
                        blacklist_manager=blacklist_manager,
                        anonymizer=anonymizer,
                        feedback_manager=feedback_manager,
                        kronos_router=kronos_router,
                        ipc_listener=ipc_listener,
                        metrics=metrics
                    )
                    self._components['prediction_engine'] = prediction_engine
                except Exception as e:
                    raise ServiceStartError(f"Failed to initialize PredictionEngine: {e}")

                # Load initial model
                try:
                    if not model_manager.load_latest_model():
                        log_event(
                            logger,
                            "initial_model_load_failed",
                            level="warning"
                        )
                except Exception as e:
                    log_event(
                        logger,
                        "model_load_exception",
                        level="error",
                        error=str(e)
                    )
                    # Continue, as ModelManager handles fallbacks

                # Start prediction engine
                try:
                    if not prediction_engine.start():
                        raise ServiceStartError("Failed to start prediction engine")
                except Exception as e:
                    raise ServiceStartError(f"Exception starting prediction engine: {e}")

                # Calculate dry run end time
                self._stats['dry_run_end_time'] = (
                    datetime.now() + timedelta(days=self.config.enforcement.dry_run_duration_days)
                ).isoformat()

                # Set running state
                self._running = True
                self._start_time = datetime.now()
                self._stats['service_start_time'] = self._start_time.isoformat()

                # Start API Server
                try:
                    app.state.daemon = self
                    config = uvicorn.Config(app, host="127.0.0.1", port=8081, log_level="info", loop="asyncio")
                    self._api_server = uvicorn.Server(config)

                    api_thread = threading.Thread(
                        target=self._api_server.run,
                        name="Aegis-API",
                        daemon=True
                    )
                    api_thread.start()
                    log_event(logger, "api_server_started", port=8081)
                except Exception as e:
                    log_event(logger, "api_server_start_failed", level="error", error=str(e))

                # Start background monitoring thread
                monitor_thread = threading.Thread(
                    target=self._monitoring_loop,
                    name="Aegis-Monitor",
                    daemon=True
                )
                monitor_thread.start()

                # Start Watchdog thread
                watchdog_thread = threading.Thread(
                    target=self._watchdog_loop,
                    name="Aegis-Watchdog",
                    daemon=True
                )
                watchdog_thread.start()

                # Start Prometheus metrics exporter
                try:
                    start_http_server(9090)
                    log_event(logger, "prometheus_exporter_started", port=9090)
                except Exception as e:
                    log_event(logger, "prometheus_exporter_failed", error=str(e), level="error")

                # Start Online Learning Thread
                try:
                    feedback_dir = Path(self.config.enforcement.feedback_dir)
                    ol_thread = OnlineLearningThread(
                        prediction_engine=prediction_engine,
                        db_path=feedback_dir / "online_learning.db"
                    )
                    ol_thread.start()
                    self._components['online_learning_thread'] = ol_thread
                except Exception as ol_err:
                    log_event(logger, "online_learning_start_failed", error=str(ol_err))

                log_event(
                    logger,
                    "aegis_daemon_started",
                    level="info",
                    dry_run_duration_days=self.config.enforcement.dry_run_duration_days,
                    dry_run_end_time=self._stats['dry_run_end_time'],
                    components=[k for k, v in self._components.items() if v is not None]
                )

                return True

            except Exception as e:
                # Rollback/Cleanup on failure
                log_event(logger, "startup_sequence_failed", level="error", error=str(e))
                self.stop() # Attempt to clean up anything that started
                raise

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
            
            # Signal shutdown first to stop loops
            self._running = False
            self._shutdown_event.set()
            
            shutdown_errors = []

            # Stop API server
            try:
                if self._api_server:
                    self._api_server.should_exit = True
                    log_event(logger, "api_server_stopping")
            except Exception as e:
                log_event(logger, "api_server_stop_failed", level="warning", error=str(e))

            # Stop prediction engine
            try:
                prediction_engine = self._components.get('prediction_engine')
                if prediction_engine:
                    if not prediction_engine.stop(timeout // 2):
                        log_event(
                            logger,
                            "prediction_engine_stop_failed",
                            level="warning"
                        )
                        shutdown_errors.append("prediction_engine_stop_failed")
            except Exception as e:
                log_event(logger, "prediction_engine_stop_exception", level="error", error=str(e))
                shutdown_errors.append(f"prediction_engine_error: {e}")

            # Stop IPC listener
            try:
                ipc_listener = self._components.get('ipc_listener')
                if ipc_listener:
                    ipc_listener.stop()
            except Exception as e:
                log_event(logger, "ipc_listener_stop_failed", level="warning", error=str(e))
                shutdown_errors.append(f"ipc_listener_error: {e}")
            
            # Stop Online Learning Thread
            try:
                ol_thread = self._components.get('online_learning_thread')
                if ol_thread:
                    ol_thread.stop()
                    ol_thread.join(timeout=5)
            except Exception as e:
                log_event(logger, "online_learning_stop_failed", level="warning", error=str(e))
                shutdown_errors.append(f"online_learning_error: {e}")

            # Wait for monitoring thread to notice _running=False
            time.sleep(1)
            
            # Update statistics
            try:
                if self._start_time:
                    runtime = datetime.now() - self._start_time
                    self._stats['total_runtime_seconds'] = runtime.total_seconds()
            except Exception as e:
                log_event(logger, "stats_update_failed_during_stop", level="warning", error=str(e))

            if shutdown_errors:
                 log_event(
                    logger,
                    "aegis_daemon_stopped_with_errors",
                    level="warning",
                    errors=shutdown_errors,
                    total_runtime_seconds=self._stats.get('total_runtime_seconds', 0)
                )
            else:
                log_event(
                    logger,
                    "aegis_daemon_stopped",
                    level="info",
                    total_runtime_seconds=self._stats.get('total_runtime_seconds', 0)
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
        finally:
            # Absolute guarantee these are set
            self._running = False
            self._shutdown_event.set()
    
    def _watchdog_loop(self) -> None:
        """Watchdog loop to monitor prediction engine health."""
        log_event(logger, "watchdog_started", level="info")
        while self._running:
            try:
                # Check every 30 seconds
                for _ in range(30):
                    if not self._running:
                        return
                    time.sleep(1)

                prediction_engine = self._components.get('prediction_engine')
                if not prediction_engine:
                    continue

                # Check if threads are alive while engine is supposed to be running
                if prediction_engine._running:
                    poll_alive = prediction_engine._poll_thread and prediction_engine._poll_thread.is_alive()
                    pred_alive = prediction_engine._prediction_thread and prediction_engine._prediction_thread.is_alive()

                    ipc_alive = True
                    if prediction_engine.ipc_listener:
                        ipc_alive = prediction_engine._ipc_thread and prediction_engine._ipc_thread.is_alive()

                    if not (poll_alive and pred_alive and ipc_alive):
                        log_event(
                            logger,
                            "watchdog_prediction_engine_unresponsive",
                            level="error",
                            poll_thread=poll_alive,
                            pred_thread=pred_alive,
                            ipc_thread=ipc_alive
                        )

                        # Restart prediction engine
                        try:
                            log_event(logger, "watchdog_restarting_prediction_engine", level="warning")
                            prediction_engine.stop()
                            time.sleep(2)
                            prediction_engine.start()
                            log_event(logger, "watchdog_prediction_engine_restarted", level="info")
                        except Exception as e:
                            log_event(logger, "watchdog_restart_failed", level="error", error=str(e))

            except Exception as e:
                log_event(logger, "watchdog_error", level="error", error=str(e))

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
        consecutive_errors = 0
        max_consecutive_errors = 5

        while self._running:
            try:
                # Health check
                try:
                    self._perform_health_check()
                except Exception as e:
                    log_event(logger, "health_check_failed", level="error", error=str(e))
                
                # Update statistics
                try:
                    self._update_statistics()
                except Exception as e:
                    log_event(logger, "stats_update_failed", level="error", error=str(e))
                
                # Cleanup expired blacklist entries
                blacklist_manager = None
                try:
                    blacklist_manager = self._components.get('blacklist_manager')
                    if blacklist_manager:
                        blacklist_manager.cleanup_expired_entries()
                except Exception as e:
                    log_event(logger, "blacklist_cleanup_failed", level="error", error=str(e))
                
                # Sync with Firebase if enabled
                try:
                    if (blacklist_manager and
                        self._should_sync_firebase()):
                        blacklist_manager.sync_with_firebase()
                except Exception as e:
                    log_event(logger, "firebase_sync_failed", level="error", error=str(e))
                
                # Reset error counter on successful iteration
                consecutive_errors = 0
                
            except Exception as e:
                consecutive_errors += 1
                log_event(
                    logger,
                    "monitoring_loop_critical_error",
                    level="error",
                    error=str(e),
                    consecutive_errors=consecutive_errors
                )

                if consecutive_errors >= max_consecutive_errors:
                    log_event(
                        logger,
                        "monitoring_loop_unstable",
                        level="critical",
                        message="Monitoring loop experiencing persistent errors"
                    )

            finally:
                # Ensure we sleep to prevent tight loop and check shutdown signal
                sleep_time = 60 if consecutive_errors == 0 else 30

                # Sleep in 1-second intervals to respond to shutdown quickly
                for _ in range(sleep_time):
                    if not self._running:
                        break
                    time.sleep(1)
    
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
            
            try:
                for name, component in self._components.items():
                    if component:
                        try:
                            if hasattr(component, 'get_statistics'):
                                component_stats[name] = component.get_statistics()
                            elif hasattr(component, 'get_model_info'):
                                component_stats[name] = component.get_model_info()
                        except Exception as e:
                            log_event(logger, "component_stats_error", component=name, error=str(e))
                            component_stats[name] = {"error": str(e)}
            except Exception as e:
                log_event(logger, "stats_collection_failed", level="error", error=str(e))
            
            # Update Prometheus Gauges
            if 'blacklist_manager' in component_stats:
                bl_stats = component_stats['blacklist_manager']
                if isinstance(bl_stats, dict) and 'active_entries' in bl_stats:
                    AEGIS_ACTIVE_BLOCKS.set(bl_stats['active_entries'])

            if 'model_manager' in component_stats:
                mm_stats = component_stats['model_manager']
                if isinstance(mm_stats, dict):
                    metadata = mm_stats.get('model_metadata', {})
                    if metadata and 'accuracy' in metadata:
                        try:
                            AEGIS_MODEL_ACCURACY.set(float(metadata['accuracy']))
                        except (ValueError, TypeError):
                            pass

            # Combine all statistics
            all_stats = {
                'daemon_stats': self._stats,
                'component_stats': component_stats,
                'config_summary': self.config.to_safe_dict(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Atomic write to statistics file
            stats_file = Path(self.config.stats_file)
            temp_file = stats_file.with_suffix('.tmp')
            
            try:
                stats_file.parent.mkdir(parents=True, exist_ok=True)

                with open(temp_file, 'w') as f:
                    json.dump(all_stats, f, indent=2, default=str)
                    f.flush()
                    os.fsync(f.fileno())

                # Atomic rename
                temp_file.replace(stats_file)

            except (OSError, IOError) as e:
                log_event(logger, "stats_file_write_error", level="error", error=str(e))
                if temp_file.exists():
                    try:
                        temp_file.unlink()
                    except OSError:
                        pass
            
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
            # Safe calculation of service info
            try:
                service_info = {
                    'is_running': self._running,
                    'start_time': self._start_time.isoformat() if self._start_time else None,
                    'uptime_seconds': (
                        (datetime.now() - self._start_time).total_seconds() 
                        if self._start_time else 0
                    ),
                    'dry_run_remaining_days': self._get_dry_run_remaining_days()
                }
            except Exception as e:
                service_info = {'error': str(e), 'is_running': self._running}

            status = {
                'overall_health': 'unknown',
                'components_healthy': 0,
                'total_components': 0,
                'component_details': {},
                'service_info': service_info
            }
            
            # Helper to safely check component health
            def _check_component(name: str, check_fn):
                try:
                    component = self._components.get(name)
                    if not component:
                        return

                    status['total_components'] += 1
                    is_healthy = True
                    details = {}

                    try:
                        is_healthy, details = check_fn(component)
                    except Exception as inner_e:
                        is_healthy = False
                        details = {'error': str(inner_e)}

                    if is_healthy:
                        status['components_healthy'] += 1

                    status['component_details'][name] = {
                        'healthy': is_healthy,
                        **details
                    }
                except Exception as e:
                    # Should not happen given the structure, but zero-trust
                    log_event(logger, "health_check_component_error", component=name, error=str(e))

            # Check model manager
            _check_component('model_manager',
                lambda c: (c.is_model_available(), {'model_info': c.get_model_info()}))
            
            # Check blacklist manager
            _check_component('blacklist_manager',
                lambda c: (True, {'stats': c.get_statistics()}))
            
            # Check prediction engine
            _check_component('prediction_engine',
                lambda c: (c._running, {'stats': c.get_statistics()}))
            
            # Determine overall health
            if status['total_components'] > 0:
                health_ratio = status['components_healthy'] / status['total_components']
                if health_ratio >= 0.8:
                    status['overall_health'] = 'healthy'
                elif health_ratio >= 0.5:
                    status['overall_health'] = 'degraded'
                else:
                    status['overall_health'] = 'unhealthy'
            elif self._running:
                status['overall_health'] = 'degraded'  # Running but no components
            else:
                status['overall_health'] = 'stopped'
            
            return status
            
        except Exception as e:
            return {
                'overall_health': 'error',
                'components_healthy': 0,
                'total_components': 0,
                'component_details': {},
                'error': str(e),
                'service_info': {
                    'is_running': self._running,
                    'start_time': self._start_time.isoformat() if self._start_time else None,
                    'uptime_seconds': 0,
                    'dry_run_remaining_days': 0.0
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