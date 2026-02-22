"""Prediction engine for Aegis shield runtime.

This module provides the core prediction functionality that polls Retina CSV files,
processes flow data through the Mnemosyne model, and makes enforcement decisions.
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

logger = logging.getLogger(__name__)


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
        feedback_manager=None
    ):
        """Initialize prediction engine.
        
        Args:
            polling_config: Polling configuration
            prediction_config: Prediction configuration
            model_manager: Model manager instance
            blacklist_manager: Blacklist manager instance
            anonymizer: Optional anonymizer for sensitive data
            feedback_manager: Optional feedback manager for trusted IPs
        """
        self.polling_config = polling_config
        self.prediction_config = prediction_config
        self.model_manager = model_manager
        self.blacklist_manager = blacklist_manager
        self.anonymizer = anonymizer
        self.feedback_manager = feedback_manager
        
        # State tracking
        self._running = False
        self._poll_thread = None
        self._prediction_thread = None
        self._csv_queue = Queue()
        self._processed_files = set()
        
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
                csv_file = self._csv_queue.get(timeout=10)
                
                # Process the file
                success = self._process_csv_file(csv_file)
                
                if success:
                    self._processed_files.add(csv_file.name)
                    self._stats['csv_files_processed'] += 1
                else:
                    # Put file back in queue for retry
                    self._csv_queue.put(csv_file)
                
                self._csv_queue.task_done()
                
            except Empty:
                # Queue timeout - continue loop
                continue
            except Exception as e:
                self._stats['prediction_errors'] += 1
                log_event(
                    logger,
                    "prediction_processing_error",
                    level="error",
                    error=str(e)
                )
    
    def _process_csv_file(self, csv_file: Path) -> bool:
        """Process a single CSV file and make predictions.
        
        Args:
            csv_file: Path to CSV file to process
            
        Returns:
            True if processing successful, False otherwise
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
            flows_df = self._load_csv_data(csv_file)
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
                    return False
            
            # Process flows in batches
            batch_size = min(self.prediction_config.max_flows_per_batch, len(flows_df))
            
            for i in range(0, len(flows_df), batch_size):
                if not self._running:  # Check if still running
                    break
                
                batch_df = flows_df.iloc[i:i+batch_size]
                
                try:
                    # Make predictions
                    predictions_df = self.model_manager.predict_flows(batch_df)
                    
                    # Process predictions and make enforcement decisions
                    self._process_batch_predictions(predictions_df)
                    
                    # Update statistics
                    self._stats['total_flows_processed'] += len(batch_df)
                    self._stats['total_predictions_made'] += len(predictions_df)
                    
                except ModelLoadError as e:
                    log_event(
                        logger,
                        "model_prediction_failed",
                        level="error",
                        error=str(e)
                    )
                    return False
                except Exception as e:
                    log_event(
                        logger,
                        "batch_prediction_failed",
                        level="error",
                        batch_index=i // batch_size,
                        error=str(e)
                    )
                    continue
            
            # Mark file as processed
            processed_file_path = csv_file.parent / f"{csv_file.name}{self.polling_config.processed_file_suffix}"
            processed_file_path.touch()
            
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
            return False
    
    def _load_csv_data(self, csv_file: Path) -> pd.DataFrame:
        """Load flow data from CSV file.
        
        Args:
            csv_file: Path to CSV file
            
        Returns:
            DataFrame containing flow data
        """
        try:
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
            raise CSVPollingError(f"Failed to load CSV data: {e}")
    
    def _clean_flow_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and validate flow data.
        
        Args:
            df: Raw flow data DataFrame
            
        Returns:
            Cleaned DataFrame
        """
        try:
            original_rows = int(len(df))

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
            df = df.dropna(subset=essential_cols, how="any")

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
                        return self.anonymizer.anonymize_ip(ip)
                    except ValueError:
                        # Assume already anonymized or invalid, return as is
                        return ip

                df["src_ip_hash"] = df["src_ip"].apply(safe_anonymize)
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
            raise
    
    def _process_batch_predictions(self, predictions_df: pd.DataFrame) -> None:
        """Process predictions and make enforcement decisions.
        
        Args:
            predictions_df: DataFrame with prediction results
        """
        try:
            for _, row in predictions_df.iterrows():
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
                    if src_ip and self.feedback_manager.is_trusted(src_ip):
                        is_trusted = True
                    elif dst_ip and self.feedback_manager.is_trusted(dst_ip):
                        is_trusted = True

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
                    explanation = self.model_manager.explain_anomaly(row)
                    explanation_str = ", ".join(explanation)

                    action_reason = f"Anomaly detected: {explanation_str} (score: {anomaly_score:.3f})"
                    
                    if risk_level in ['high', 'critical']:
                        action_needed = True
                        action_reason = f"High-risk anomaly: {explanation_str} (score: {anomaly_score:.3f}, risk: {risk_level})"
                
                # Check for blacklist violations
                src_ip = row.get('src_ip', '')
                dst_ip = row.get('dst_ip', '')
                
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
                    
                    log_event(
                        logger,
                        "anomaly_detected",
                        level="info",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        anomaly_score=float(anomaly_score),
                        risk_level=risk_level
                    )
            
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
        model_info = self.model_manager.get_model_info()
        stats['model_info'] = model_info
        
        # Add blacklist information
        blacklist_stats = self.blacklist_manager.get_statistics()
        stats['blacklist_stats'] = blacklist_stats
        
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
            success = self._process_csv_file(csv_file)
            
            if success:
                self._processed_files.add(csv_file.name)
            
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