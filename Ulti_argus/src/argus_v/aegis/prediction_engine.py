"""Prediction engine for Aegis shield runtime.

This module provides the core prediction functionality that polls Retina CSV files,
processes flow data through the Mnemosyne model, and makes enforcement decisions.

Kronos integration
------------------
If a KronosRouter instance is passed at construction, each flow is triaged
before enforcement:
  PASS     → skip enforcement entirely (Kronos confident it is normal)
  IF_ONLY  → trust IsolationForest verdict as before
  ESCALATE → request CNN analysis via mnemosyne pytorch_inference
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Dict, List, Optional

import pandas as pd

from ..oracle_core.logging import log_event
from .blacklist_manager import BlacklistManager
from .model_manager import ModelLoadError, ModelManager

# Imports
try:
    import torch
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False

# Kronos is optional — import gracefully so Aegis works without it
try:
    from ..kronos.router import KronosRouter, RoutingPath
    from ..mnemosyne.pytorch_inference import analyze_payload
    _KRONOS_AVAILABLE = True
except ImportError:
    _KRONOS_AVAILABLE = False
    KronosRouter = None  # type: ignore

logger = logging.getLogger(__name__)


class JITInferenceEngine:
    """JIT-compiled inference engine for batched payload analysis."""

    def __init__(self, model_path: str | Path, device: str = "cpu"):
        self.device = torch.device(device)
        self.model = torch.jit.load(str(model_path), map_location=self.device)
        self.model.eval()

    def predict_batch(self, payloads: List[bytes]) -> List[float]:
        if not payloads:
            return []

        # --- Stage 1: Heuristic Safety Filter (Reduce False Positives) ---
        is_standard_web = []
        for p in payloads:
            safe = False
            if p.startswith((b"GET /", b"POST /")):
                if not any(x in p for x in [b"'", b"\"", b";", b"<", b">", b"../"]):
                    safe = True
            is_standard_web.append(safe)

        # --- Stage 2: Neural Inference ---
        tensors = []
        for p in payloads:
            data = list(p[:1024])
            if len(data) < 1024:
                data += [0] * (1024 - len(data))
            tensors.append(data)

        # [Batch, 1024] -> [Batch, 1, 1024]
        X = torch.tensor(tensors, dtype=torch.float32, device=self.device) / 255.0
        X = X.unsqueeze(1)

        with torch.no_grad():
            logits = self.model(X)
            probs = torch.softmax(logits, dim=1)
            raw_scores = probs[:, 1].tolist() # Attack probability

        # --- Stage 3: Threat Boosters (Catch False Negatives) ---
        dangerous_patterns = [
            b"/etc/passwd", b"cmd.exe", b"/bin/sh",
            b"SELECT * FROM", b"UNION SELECT",
            b"<script>", b"onerror=", b"javascript:",
            b"curl http", b"wget http"
        ]

        final_scores = []
        for i, raw_score in enumerate(raw_scores):
            payload = payloads[i]
            boost = 0.0
            payload_lower = payload.lower()
            for pattern in dangerous_patterns:
                if pattern.lower() in payload_lower:
                    boost += 0.5

            final_score = raw_score + boost

            if is_standard_web[i] and final_score < 1.0:
                final_score = min(final_score, 0.1)

            final_scores.append(min(max(final_score, 0.0), 1.0))

        return final_scores


class PredictionEngineError(Exception):
    """Base exception for prediction engine operations."""
    pass


class CSVPollingError(PredictionEngineError):
    """Exception raised when CSV polling operations fail."""
    pass


class PredictionTimeoutError(PredictionEngineError):
    """Exception raised when prediction operations timeout."""
    pass


class PredictionEngine:
    """Core prediction engine that polls Retina and makes enforcement decisions."""
    
    def __init__(
        self, 
        polling_config,
        prediction_config,
        model_manager: ModelManager,
        blacklist_manager: BlacklistManager,
        anonymizer=None,
        feedback_manager=None,
        kronos_router=None,
        ipc_listener=None,
        metrics=None,
    ):
        """Initialize prediction engine.
        
        Args:
            polling_config: Polling configuration
            prediction_config: Prediction configuration
            model_manager: Model manager instance
            blacklist_manager: Blacklist manager instance
            anonymizer: Optional anonymizer for sensitive data
            feedback_manager: Optional feedback manager for trusted IPs
            kronos_router: Optional KronosRouter for intelligent flow triage.
                           When provided, flows are routed to PASS / IF_ONLY /
                           ESCALATE before enforcement decisions are made.
            ipc_listener: Optional IPCListener for real-time DeepPacketSentinel flows.
            metrics: Optional dictionary of Prometheus metrics.
        """
        # zero-trust validation of critical components
        if not polling_config:
            raise ValueError("polling_config is required")
        if not prediction_config:
            raise ValueError("prediction_config is required")
        if not model_manager:
            raise ValueError("model_manager is required")
        if not blacklist_manager:
            raise ValueError("blacklist_manager is required")

        self.polling_config = polling_config
        self.prediction_config = prediction_config
        self.model_manager = model_manager
        self.blacklist_manager = blacklist_manager
        self.anonymizer = anonymizer
        self.feedback_manager = feedback_manager
        self.kronos_router = kronos_router if _KRONOS_AVAILABLE else None
        self.ipc_listener = ipc_listener
        self.metrics = metrics
        
        # JIT Model
        self.jit_engine = None

        # State tracking
        self._running = False
        self._poll_thread = None
        self._prediction_thread = None
        self._ipc_thread = None
        self._csv_queue = Queue()
        self._processed_files = set()

        # IPC batching
        self.ipc_batch_queue = []
        self.ipc_last_process_time = 0.0
        
        # Statistics
        self._stats = {
            'total_flows_processed': 0,
            'total_predictions_made': 0,
            'anomalies_detected': 0,
            'blacklist_additions': 0,
            'enforcement_actions': 0,
            'csv_files_processed': 0,
            'poll_errors': 0,
            'prediction_errors': 0,
            'last_processed_file': None,
            'last_prediction_time': None,
            'average_processing_time': 0.0
        }
        
        # Performance tracking
        self._processing_times = []
        self._max_processing_history = 100
        
        log_event(
            logger,
            "prediction_engine_initialized",
            level="info",
            poll_interval=self.polling_config.poll_interval_seconds,
            batch_size=self.polling_config.batch_size
        )
    
    def _load_jit_model(self) -> None:
        """Load the JIT-compiled payload classifier."""
        try:
            # Determine path from model_manager config or default
            model_dir = Path(self.model_manager.config.model_local_path)
            jit_path = model_dir / "payload_classifier_jit.pt"

            if jit_path.exists():
                log_event(logger, "loading_jit_model", path=str(jit_path))
                self.jit_engine = JITInferenceEngine(jit_path)
                log_event(logger, "jit_model_loaded", level="info")
            else:
                log_event(logger, "jit_model_not_found", path=str(jit_path), level="warning")
        except Exception as e:
            log_event(logger, "jit_model_load_failed", error=str(e), level="error")
            self.jit_engine = None

    def _warmup_model(self) -> None:
        """Run a dummy inference to trigger JIT optimization."""
        if self.jit_engine:
            try:
                log_event(logger, "warming_up_jit_model", level="debug")
                self.jit_engine.predict_batch([b"warmup_payload_data" * 10])
                log_event(logger, "jit_model_warmup_complete", level="info")
            except Exception as e:
                log_event(logger, "jit_model_warmup_failed", error=str(e), level="warning")

    def start(self) -> bool:
        """Start the prediction engine.
        
        Returns:
            True if started successfully, False otherwise
        """
        try:
            if self._running:
                log_event(
                    logger,
                    "prediction_engine_already_running",
                    level="warning"
                )
                return True
            
            log_event(
                logger,
                "prediction_engine_starting",
                level="info"
            )
            
            # Reset statistics
            self._reset_stats()
            
            # Set running state
            self._running = True
            
            # Start polling thread
            self._poll_thread = threading.Thread(
                target=self._poll_csv_files,
                name="Aegis-CSV-Poller",
                daemon=True
            )
            self._poll_thread.start()
            
            # Start prediction thread
            self._prediction_thread = threading.Thread(
                target=self._process_predictions,
                name="Aegis-Predictor",
                daemon=True
            )
            self._prediction_thread.start()
            
            # Start IPC thread if listener provided
            if self.ipc_listener is not None:
                self._ipc_thread = threading.Thread(
                    target=self._poll_ipc_socket,
                    name="Aegis-IPC-Poller",
                    daemon=True
                )
                self._ipc_thread.start()
                log_event(
                    logger,
                    "ipc_polling_started",
                    level="info"
                )
            
            # Load and warmup JIT model
            if _KRONOS_AVAILABLE:
                self._load_jit_model()
                self._warmup_model()

            log_event(
                logger,
                "prediction_engine_started",
                level="info"
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "prediction_engine_start_failed",
                level="error",
                error=str(e)
            )
            self._running = False
            return False
    
    def stop(self, timeout: Optional[int] = None) -> bool:
        """Stop the prediction engine.
        
        Args:
            timeout: Timeout in seconds for graceful shutdown
            
        Returns:
            True if stopped successfully, False otherwise
        """
        try:
            if not self._running:
                log_event(
                    logger,
                    "prediction_engine_not_running",
                    level="debug"
                )
                return True
            
            log_event(
                logger,
                "prediction_engine_stopping",
                level="info"
            )
            
            # Set stopped state
            self._running = False
            
            # Wait for threads to finish
            poll_timeout = timeout or 30
            pred_timeout = timeout or 30
            
            if self._poll_thread and self._poll_thread.is_alive():
                self._poll_thread.join(timeout=poll_timeout)
            
            if self._prediction_thread and self._prediction_thread.is_alive():
                self._prediction_thread.join(timeout=pred_timeout)
            
            if self._ipc_thread and self._ipc_thread.is_alive():
                self._ipc_thread.join(timeout=timeout or 5)
            
            log_event(
                logger,
                "prediction_engine_stopped",
                level="info"
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "prediction_engine_stop_failed",
                level="error",
                error=str(e)
            )
            return False
    
    def _poll_csv_files(self) -> None:
        """Background thread that polls for new CSV files from Retina."""
        consecutive_errors = 0

        # Ensure polling config is valid
        if not hasattr(self.polling_config, 'max_poll_errors') or \
           not hasattr(self.polling_config, 'poll_retry_delay') or \
           not hasattr(self.polling_config, 'poll_interval_seconds'):
            log_event(logger, "polling_config_invalid", level="critical")
            self._running = False
            return

        max_consecutive_errors = self.polling_config.max_poll_errors
        
        while self._running:
            try:
                # Check for new CSV files
                new_files = self._find_new_csv_files()
                
                if new_files:
                    log_event(
                        logger,
                        "new_csv_files_found",
                        level="debug",
                        file_count=len(new_files),
                        files=[str(f) for f in new_files]
                    )
                    
                    # Add files to processing queue
                    for csv_file in new_files:
                        if csv_file not in self._processed_files:
                            self._csv_queue.put(csv_file)
                    
                    consecutive_errors = 0
                else:
                    time.sleep(1)  # Brief pause before next check
                
            except Exception as e:
                consecutive_errors += 1
                self._stats['poll_errors'] += 1
                
                log_event(
                    logger,
                    "csv_polling_error",
                    level="error",
                    error=str(e),
                    consecutive_errors=consecutive_errors,
                    max_errors=max_consecutive_errors
                )
                
                if consecutive_errors >= max_consecutive_errors:
                    log_event(
                        logger,
                        "csv_polling_too_many_errors",
                        level="critical",
                        errors=consecutive_errors
                    )
                    time.sleep(self.polling_config.poll_retry_delay)
                    consecutive_errors = 0
                else:
                    time.sleep(5)  # Brief pause before retry
            
            # Sleep for polling interval
            if self._running:
                time.sleep(self.polling_config.poll_interval_seconds)
    
    def _find_new_csv_files(self) -> List[Path]:
        """Find new CSV files in Retina output directory.
        
        Returns:
            List of new CSV file paths
        """
        try:
            if not self.polling_config or not hasattr(self.polling_config, 'csv_directory'):
                raise ValueError("Invalid polling configuration")

            csv_dir = Path(self.polling_config.csv_directory)
            
            if not csv_dir.exists():
                log_event(
                    logger,
                    "csv_directory_not_found",
                    level="warning",
                    csv_directory=str(csv_dir)
                )
                return []
            
            # Find CSV files
            csv_files = list(csv_dir.glob("*.csv"))
            
            # Filter out processed files
            new_files = [
                f for f in csv_files 
                if f.name not in self._processed_files
            ]
            
            # Sort by modification time (newest first)
            new_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            return new_files[:self.polling_config.batch_size]  # Limit batch size
            
        except Exception as e:
            log_event(
                logger,
                "find_new_csv_files_failed",
                level="error",
                error=str(e)
            )
            return []
    
    def _process_predictions(self) -> None:
        """Background thread that processes CSV files and makes predictions."""
        while self._running:
            try:
                # Get CSV file from queue with timeout
                try:
                    csv_file = self._csv_queue.get(timeout=10)
                except Empty:
                    continue
                
                if not csv_file:
                    continue

                # Process the file
                # _process_csv_file returns True if processed OR if permanent error occurred
                # It returns False if transient error occurred (needs retry)
                success = self._process_csv_file(csv_file)
                
                if success:
                    self._processed_files.add(csv_file.name)
                    self._stats['csv_files_processed'] += 1
                else:
                    # Put file back in queue for retry
                    self._csv_queue.put(csv_file)
                
                self._csv_queue.task_done()
                
            except Exception as e:
                self._stats['prediction_errors'] += 1
                log_event(
                    logger,
                    "prediction_processing_error",
                    level="error",
                    error=str(e)
                )

    def _poll_ipc_socket(self) -> None:
        """Background thread that continuously reads FlowFrames from Kronos IPC."""
        while self._running:
            try:
                if not self.ipc_listener:
                    time.sleep(5)
                    continue

                # Accumulate batch
                start_collect = time.time()
                while len(self.ipc_batch_queue) < self.polling_config.batch_size:
                    # Check timeout (max latency 100ms)
                    if self.ipc_batch_queue and (time.time() - start_collect > 0.1):
                        break

                    try:
                        # Short timeout for polling
                        frame = self.ipc_listener.get_frame(timeout=0.05)
                        if frame:
                            self.ipc_batch_queue.append(frame)
                    except Exception:
                        pass # Timeout or error, just continue loop

                    if not self._running:
                        break

                if not self.ipc_batch_queue:
                    continue

                # Process collected batch
                frames = list(self.ipc_batch_queue)
                self.ipc_batch_queue.clear()
                
                # Convert multiple FlowFrames to a DataFrame
                try:
                    flow_dict = {
                        "src_ip": [f.src_ip for f in frames],
                        "dst_ip": [f.dst_ip for f in frames],
                        "src_port": [f.src_port for f in frames],
                        "dst_port": [f.dst_port for f in frames],
                        "protocol": [f.protocol for f in frames],
                        "bytes_in": [f.bytes_in for f in frames],
                        "bytes_out": [f.bytes_out for f in frames],
                        "duration": [f.duration for f in frames],
                        "packets_in": [1] * len(frames),
                        "packets_out": [0] * len(frames),
                        "timestamp": [datetime.now()] * len(frames),
                        "__raw_payload__": [f.payload for f in frames]
                    }

                    df = pd.DataFrame(flow_dict)
                    df = self._clean_flow_data(df)

                    if df.empty:
                        continue
                except Exception as e:
                    log_event(logger, "ipc_frame_processing_error", level="error", error=str(e))
                    continue
                
                # Dynamic prediction
                try:
                    if not self.model_manager.is_model_available():
                        if not self.model_manager.load_latest_model():
                            continue

                    with self._model_lock:
                        start_pred = time.time()
                        predictions_df = self.model_manager.predict_flows(df)
                        if self.metrics:
                            self.metrics['inference_latency'].observe(time.time() - start_pred)
                            self.metrics['flows_analyzed'].inc(len(df))
                except Exception as e:
                    log_event(logger, "ipc_model_prediction_error", level="error", error=str(e))
                    continue
                
                # Process batch predictions
                try:
                    # Payload is already in the dataframe from flow_dict
                    self._process_batch_predictions(predictions_df)

                    self._stats['total_flows_processed'] += len(predictions_df)
                    self._stats['total_predictions_made'] += len(predictions_df)
                except Exception as e:
                    log_event(logger, "ipc_batch_processing_error", level="error", error=str(e))

            except Exception as e:
                log_event(
                    logger,
                    "ipc_polling_error",
                    level="error",
                    error=str(e)
                )
                time.sleep(1)
    
    def _process_csv_file(self, csv_file: Path, force: bool = False) -> bool:
        """Process a single CSV file and make predictions.
        
        Args:
            csv_file: Path to CSV file to process
            force: Whether to force processing regardless of running state
            
        Returns:
            True if processing successful or permanent failure (do not retry),
            False if transient failure (retry)
        """
        start_time = time.time()
        
        try:
            log_event(
                logger,
                "processing_csv_file",
                level="debug",
                file_path=str(csv_file),
                file_size=csv_file.stat().st_size if csv_file.exists() else 0
            )
            
            # Load CSV data
            try:
                flows_df = self._load_csv_data(csv_file)
            except CSVPollingError as e:
                # If loading fails (e.g. malformed CSV), we should probably not retry forever.
                # Treat as handled (failed permanently)
                log_event(logger, "csv_load_permanent_failure", file_path=str(csv_file), error=str(e))
                return True

            if flows_df.empty:
                log_event(
                    logger,
                    "empty_csv_file",
                    level="warning",
                    file_path=str(csv_file)
                )
                return True  # Empty file is not an error
            
            # Ensure model is available
            if not self.model_manager.is_model_available():
                log_event(
                    logger,
                    "model_not_available",
                    level="warning"
                )
                # Try to load model
                if not self.model_manager.load_latest_model():
                    log_event(
                        logger,
                        "model_load_failed",
                        level="error"
                    )
                    return False  # Transient error, retry later
            
            # Process flows in batches
            batch_size = min(self.prediction_config.max_flows_per_batch, len(flows_df))
            
            for i in range(0, len(flows_df), batch_size):
                if not force and not self._running:  # Check if still running
                    break
                
                batch_df = flows_df.iloc[i:i+batch_size]
                
                try:
                    # Make predictions
                    with self._model_lock:
                        start_pred = time.time()
                        predictions_df = self.model_manager.predict_flows(batch_df)
                        if self.metrics:
                            self.metrics['inference_latency'].observe(time.time() - start_pred)
                    
                    # Process predictions and make enforcement decisions
                    self._process_batch_predictions(predictions_df)
                    
                    # Update statistics
                    self._stats['total_flows_processed'] += len(batch_df)
                    self._stats['total_predictions_made'] += len(predictions_df)
                    
                    if self.metrics:
                        self.metrics['flows_analyzed'].inc(len(batch_df))

                except ModelLoadError as e:
                    log_event(
                        logger,
                        "model_prediction_failed",
                        level="error",
                        error=str(e)
                    )
                    return False # Transient error
                except Exception as e:
                    log_event(
                        logger,
                        "batch_prediction_failed",
                        level="error",
                        batch_index=i // batch_size,
                        error=str(e)
                    )
                    # If one batch fails, do we retry the whole file?
                    # Or continue to next batch?
                    # Zero-trust suggests we try to process as much as possible.
                    # Continuing to next batch seems safer than infinite retry loop.
                    continue
            
            # Mark file as processed
            try:
                processed_file_path = csv_file.parent / f"{csv_file.name}{self.polling_config.processed_file_suffix}"
                processed_file_path.touch()
            except Exception as e:
                log_event(logger, "failed_to_mark_processed", error=str(e))
                # Not fatal for processing, but might cause re-processing if not handled.
                # Return True anyway as we processed it.
            
            # Update processing time statistics
            processing_time = time.time() - start_time
            self._processing_times.append(processing_time)
            if len(self._processing_times) > self._max_processing_history:
                self._processing_times.pop(0)
            
            # Update last processed file
            self._stats['last_processed_file'] = str(csv_file)
            self._stats['last_prediction_time'] = datetime.now().isoformat()
            
            # Calculate average processing time
            if self._processing_times:
                self._stats['average_processing_time'] = sum(self._processing_times) / len(self._processing_times)
            
            log_event(
                logger,
                "csv_file_processed_successfully",
                level="debug",
                file_path=str(csv_file),
                flow_count=len(flows_df),
                processing_time=processing_time,
                avg_time=self._stats['average_processing_time']
            )
            
            return True
            
        except Exception as e:
            processing_time = time.time() - start_time
            log_event(
                logger,
                "csv_file_processing_failed",
                level="error",
                file_path=str(csv_file),
                processing_time=processing_time,
                error=str(e)
            )
            # Default to transient failure (retry) for unknown exceptions
            return False
    
    def _load_csv_data(self, csv_file: Path) -> pd.DataFrame:
        """Load flow data from CSV file.
        
        Args:
            csv_file: Path to CSV file
            
        Returns:
            DataFrame containing flow data
        """
        try:
            # Check if file is empty
            if csv_file.stat().st_size == 0:
                return pd.DataFrame()

            # Read CSV with error handling
            df = pd.read_csv(
                csv_file,
                dtype={
                    # Legacy flow schema
                    "src_ip": str,
                    "dst_ip": str,
                    "src_port": "Int64",
                    "dst_port": "Int64",
                    "protocol": str,
                    "bytes_in": "Int64",
                    "bytes_out": "Int64",
                    "packets_in": "Int64",
                    "packets_out": "Int64",
                    "duration": "Float64",

                    # Retina window/flow schema (csv_rotator.py)
                    "src_ip_anon": str,
                    "dst_ip_anon": str,
                    "packet_count": "Int64",
                    "byte_count": "Int64",
                    "duration_seconds": "Float64",
                    "rate_pps": "Float64",
                    "rate_bps": "Float64",
                    "src_flow_packets": "Int64",
                    "src_flow_bytes": "Int64",
                    "dst_flow_packets": "Int64",
                    "dst_flow_bytes": "Int64",
                },
                na_values=['', 'null', 'None'],
                keep_default_na=True
            )
            
            # Clean and validate data
            df = self._clean_flow_data(df)
            
            log_event(
                logger,
                "csv_data_loaded",
                level="debug",
                file_path=str(csv_file),
                row_count=len(df),
                columns=list(df.columns)
            )
            
            return df
            
        except Exception as e:
            log_event(
                logger,
                "csv_data_load_failed",
                level="error",
                file_path=str(csv_file),
                error=str(e)
            )
            raise CSVPollingError(f"Failed to load CSV data: {e}") from e
    
    def _clean_flow_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and validate flow data.
        
        Args:
            df: Raw flow data DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        try:
            if df is None:
                return pd.DataFrame()

            original_rows = int(len(df))
            if original_rows == 0:
                return df

            # Normalize between the legacy schema (bytes_in/bytes_out/...) and the
            # current Retina CSV schema produced by csv_rotator.py.
            if "src_ip" not in df.columns and "src_ip_anon" in df.columns:
                df["src_ip"] = df["src_ip_anon"]
            if "dst_ip" not in df.columns and "dst_ip_anon" in df.columns:
                df["dst_ip"] = df["dst_ip_anon"]

            if "duration" not in df.columns and "duration_seconds" in df.columns:
                df["duration"] = df["duration_seconds"]

            if "bytes_in" not in df.columns:
                if "src_flow_bytes" in df.columns:
                    df["bytes_in"] = df["src_flow_bytes"]
                elif "byte_count" in df.columns:
                    df["bytes_in"] = df["byte_count"]
                else:
                    df["bytes_in"] = 0

            if "bytes_out" not in df.columns:
                if "dst_flow_bytes" in df.columns:
                    df["bytes_out"] = df["dst_flow_bytes"]
                else:
                    df["bytes_out"] = 0

            if "packets_in" not in df.columns:
                if "src_flow_packets" in df.columns:
                    df["packets_in"] = df["src_flow_packets"]
                elif "packet_count" in df.columns:
                    df["packets_in"] = df["packet_count"]
                else:
                    df["packets_in"] = 0

            if "packets_out" not in df.columns:
                if "dst_flow_packets" in df.columns:
                    df["packets_out"] = df["dst_flow_packets"]
                else:
                    df["packets_out"] = 0

            # Remove rows with missing essential data
            essential_cols = ["src_ip", "dst_ip", "bytes_in", "bytes_out"]
            # Check existence first
            existing_essential = [c for c in essential_cols if c in df.columns]
            if len(existing_essential) < len(essential_cols):
                 # Missing essential columns structure entirely
                 log_event(logger, "missing_essential_columns", columns=essential_cols, existing=df.columns.tolist())
                 # If essential columns are missing, we might not be able to proceed safely.
                 # But we'll try to drop NA on what exists.
                 pass

            df = df.dropna(subset=existing_essential, how="any")

            # Convert numeric columns
            numeric_cols = [
                "src_port",
                "dst_port",
                "bytes_in",
                "bytes_out",
                "packets_in",
                "packets_out",
                "duration",
                "packet_count",
                "byte_count",
                "rate_pps",
                "rate_bps",
                "src_flow_packets",
                "src_flow_bytes",
                "dst_flow_packets",
                "dst_flow_bytes",
            ]

            for col in numeric_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

            # Ensure timestamp column exists and is valid
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
                df = df.dropna(subset=["timestamp"])
            elif "window_start" in df.columns:
                df["timestamp"] = pd.to_datetime(df["window_start"], errors="coerce")
                df = df.dropna(subset=["timestamp"])
            else:
                df["timestamp"] = datetime.now()

            # Add anonymized IP columns if anonymizer available
            if self.anonymizer:
                def safe_anonymize(ip):
                    try:
                        if pd.isna(ip):
                            return ""
                        return self.anonymizer.anonymize_ip(str(ip))
                    except ValueError:
                        # Assume already anonymized or invalid, return as is
                        return str(ip)
                    except Exception:
                        return str(ip)

                if "src_ip" in df.columns:
                    df["src_ip_hash"] = df["src_ip"].apply(safe_anonymize)
                if "dst_ip" in df.columns:
                    df["dst_ip_hash"] = df["dst_ip"].apply(safe_anonymize)

            cleaned_rows = int(len(df))
            log_event(
                logger,
                "flow_data_cleaned",
                level="debug",
                original_rows=original_rows,
                cleaned_rows=cleaned_rows,
                dropped_rows=original_rows - cleaned_rows,
            )

            return df
            
        except Exception as e:
            log_event(
                logger,
                "flow_data_cleaning_failed",
                level="error",
                error=str(e)
            )
            # Raise to be caught by caller
            raise
    
    def _process_batch_predictions(self, predictions_df: pd.DataFrame) -> None:
        """Process predictions and make enforcement decisions.
        
        Args:
            predictions_df: DataFrame with prediction results
        """
        try:
            # 1. Kronos Triage & Escalation (Batch Mode)
            if self.kronos_router is not None:
                payloads_to_scan = []
                indices_to_scan = []

                # First pass: Ask Kronos what to do
                for idx, row in predictions_df.iterrows():
                    src_ip = row.get('src_ip', '')
                    dst_ip = row.get('dst_ip', '')
                    payload_bytes = row.get('__raw_payload__', None)
                    anomaly_score = row.get('anomaly_score', 0)

                    try:
                        decision = self.kronos_router.route(
                            if_score=float(anomaly_score),
                            src_ip=str(src_ip) if src_ip else "",
                            dst_ip=str(dst_ip) if dst_ip else "",
                            protocol=str(row.get('protocol', 'OTHER')),
                            dst_port=int(row.get('dst_port', 0)),
                            payload_available=(payload_bytes is not None),
                        )

                        if decision.path == RoutingPath.PASS:
                            predictions_df.at[idx, 'prediction'] = 1 # Force Normal
                            predictions_df.at[idx, '__skip_enforcement__'] = True
                            log_event(logger, "kronos_fast_pass", src_ip=src_ip, if_score=float(anomaly_score))

                        elif decision.path == RoutingPath.ESCALATE:
                            payloads_to_scan.append(payload_bytes or b"")
                            indices_to_scan.append(idx)

                    except Exception as e:
                        log_event(logger, "kronos_route_error", error=str(e))

                # Batch Scan with CNN
                if payloads_to_scan:
                    cnn_scores = []
                    # Try JIT model first
                    if self.jit_engine:
                        try:
                            cnn_scores = self.jit_engine.predict_batch(payloads_to_scan)
                        except Exception as e:
                            log_event(logger, "jit_batch_predict_failed", error=str(e))

                    # Fallback to legacy if JIT failed or unavailable
                    if not cnn_scores:
                        for p in payloads_to_scan:
                            try:
                                cnn_scores.append(analyze_payload(p))
                            except Exception:
                                cnn_scores.append(0.0)

                    # Update predictions based on CNN scores
                    for i, idx in enumerate(indices_to_scan):
                        score = cnn_scores[i]
                        row = predictions_df.loc[idx]
                        src_ip = row.get('src_ip', '')
                        anomaly_score = row.get('anomaly_score', 0)

                        log_event(logger, "kronos_cnn_escalation", src_ip=src_ip, if_score=float(anomaly_score), cnn_score=score)

                        if score < 0.30:
                            predictions_df.at[idx, 'prediction'] = 1 # Suppress
                            predictions_df.at[idx, '__skip_enforcement__'] = True
                        elif score >= 0.65:
                            predictions_df.at[idx, 'prediction'] = -1 # Confirm Anomaly

            for _, row in predictions_df.iterrows():
                if row.get('__skip_enforcement__', False):
                    continue

                try:
                    # Determine if action is needed
                    action_needed = False
                    action_reason = ""
                    risk_level = "low"
                    
                    # Check prediction results
                    prediction = row.get('prediction', 1)
                    anomaly_score = row.get('anomaly_score', 0)
                    risk_level = row.get('risk_level', 'low')

                    # Check for trusted IPs (Immediate Relief)
                    src_ip = row.get('src_ip', '')
                    dst_ip = row.get('dst_ip', '')

                    is_trusted = False
                    if self.feedback_manager:
                        try:
                            if src_ip and self.feedback_manager.is_trusted(src_ip):
                                is_trusted = True
                            elif dst_ip and self.feedback_manager.is_trusted(dst_ip):
                                is_trusted = True
                        except Exception as fb_err:
                            log_event(logger, "feedback_manager_error", level="error", error=str(fb_err))

                    if is_trusted:
                        # Trusted IP (Active Learning Feedback) - suppress alert
                        log_event(
                            logger,
                            "anomaly_suppressed_trusted_ip",
                            level="debug",
                            src_ip=src_ip,
                            dst_ip=dst_ip
                        )
                        continue

                    if prediction == -1:  # Anomaly detected
                        action_needed = True

                        # Generate explanation for the anomaly
                        try:
                            explanation = self.model_manager.explain_anomaly(row)
                            explanation_str = ", ".join(explanation)
                        except Exception:
                            explanation_str = "unknown_anomaly"

                        action_reason = f"Anomaly detected: {explanation_str} (score: {anomaly_score:.3f})"

                        if risk_level in ['high', 'critical']:
                            action_needed = True
                            action_reason = f"High-risk anomaly: {explanation_str} (score: {anomaly_score:.3f}, risk: {risk_level})"
                    
                    # Check for blacklist violations
                    if src_ip and self.blacklist_manager.is_blacklisted(src_ip):
                        action_needed = True
                        action_reason = f"Source IP {src_ip} is blacklisted"
                    elif dst_ip and self.blacklist_manager.is_blacklisted(dst_ip):
                        action_needed = True
                        action_reason = f"Destination IP {dst_ip} is blacklisted"

                    # Take enforcement action if needed
                    if action_needed:
                        # Add violating IPs to blacklist
                        if src_ip:
                            try:
                                success = self.blacklist_manager.add_to_blacklist(
                                    ip_address=src_ip,
                                    reason=f"Aegis prediction: {action_reason}",
                                    source="prediction",
                                    risk_level=risk_level,
                                    enforce=False,  # Will be enforced by blacklist manager based on dry-run mode
                                    metadata={
                                        'csv_file': self._stats.get('last_processed_file'),
                                        'prediction_score': float(anomaly_score),
                                        'flow_details': {
                                            'dst_ip': dst_ip,
                                            'src_port': row.get('src_port'),
                                            'dst_port': row.get('dst_port'),
                                            'protocol': row.get('protocol'),
                                            'bytes_in': row.get('bytes_in'),
                                            'bytes_out': row.get('bytes_out')
                                        }
                                    }
                                )

                                if success:
                                    self._stats['blacklist_additions'] += 1
                            except Exception as bl_err:
                                log_event(logger, "blacklist_addition_failed", level="error", error=str(bl_err), ip=src_ip)

                        # Log enforcement decision
                        log_event(
                            logger,
                            "enforcement_action_decision",
                            level="info",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            reason=action_reason,
                            risk_level=risk_level,
                            prediction_score=float(anomaly_score)
                        )
                    
                    # Update anomaly statistics
                    if prediction == -1:
                        self._stats['anomalies_detected'] += 1
                        if self.metrics:
                            self.metrics['anomalies_detected'].inc()

                        log_event(
                            logger,
                            "anomaly_detected",
                            level="info",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            anomaly_score=float(anomaly_score),
                            risk_level=risk_level
                        )
                except Exception as row_err:
                    log_event(
                        logger,
                        "row_processing_error",
                        level="error",
                        error=str(row_err)
                    )
                    continue

            log_event(
                logger,
                "batch_predictions_processed",
                level="debug",
                batch_size=len(predictions_df),
                anomalies_detected=len(predictions_df[predictions_df['prediction'] == -1]),
                enforcement_actions=self._stats['blacklist_additions']
            )
            
        except Exception as e:
            log_event(
                logger,
                "batch_prediction_processing_failed",
                level="error",
                error=str(e)
            )
            raise
    
    def _reset_stats(self) -> None:
        """Reset internal statistics."""
        self._stats.update({
            'total_flows_processed': 0,
            'total_predictions_made': 0,
            'anomalies_detected': 0,
            'blacklist_additions': 0,
            'enforcement_actions': 0,
            'csv_files_processed': 0,
            'poll_errors': 0,
            'prediction_errors': 0,
            'last_processed_file': None,
            'last_prediction_time': None,
            'average_processing_time': 0.0
        })
        self._processing_times.clear()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current prediction engine statistics.
        
        Returns:
            Dictionary containing statistics
        """
        stats = self._stats.copy()
        
        # Add queue statistics
        stats['csv_queue_size'] = self._csv_queue.qsize()
        stats['processed_files_count'] = len(self._processed_files)
        stats['is_running'] = self._running
        
        # Add model information
        try:
            model_info = self.model_manager.get_model_info()
            stats['model_info'] = model_info
        except Exception:
            stats['model_info'] = "unavailable"
        
        # Add blacklist information
        try:
            blacklist_stats = self.blacklist_manager.get_statistics()
            stats['blacklist_stats'] = blacklist_stats
        except Exception:
            stats['blacklist_stats'] = "unavailable"
        
        return stats
    
    def force_process_file(self, csv_file: Path) -> bool:
        """Force processing of a specific CSV file (for testing/manual processing).
        
        Args:
            csv_file: Path to CSV file to process
            
        Returns:
            True if processing successful, False otherwise
        """
        try:
            if not csv_file.exists():
                log_event(
                    logger,
                    "force_process_file_not_found",
                    level="error",
                    file_path=str(csv_file)
                )
                return False
            
            log_event(
                logger,
                "force_processing_file",
                level="info",
                file_path=str(csv_file)
            )
            
            # Process the file directly
            success = self._process_csv_file(csv_file, force=True)
            
            if success:
                self._processed_files.add(csv_file.name)
                self._stats['csv_files_processed'] += 1
            
            return success
            
        except Exception as e:
            log_event(
                logger,
                "force_process_file_failed",
                level="error",
                file_path=str(csv_file),
                error=str(e)
            )
            return False
