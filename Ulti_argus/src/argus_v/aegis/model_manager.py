"""Model management for Aegis shield runtime.

This module provides functionality to download, validate, and manage Mnemosyne
models and scalers from Firebase Storage, with fallback support and caching.
"""

from __future__ import annotations

import logging
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import firebase_admin
    from firebase_admin import credentials, storage
    from google.cloud import storage as gcs
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)


class ModelLoadError(Exception):
    """Exception raised when model loading fails."""
    pass


class ModelValidationError(Exception):
    """Exception raised when model validation fails."""
    pass


class ScalerValidationError(Exception):
    """Exception raised when scaler validation fails."""
    pass


class ModelManager:
    """Manages Mnemosyne model and scaler loading with caching and validation."""

    def __init__(
        self,
        config,
        anonymizer: Any | None = None,
        feature_columns: list[str] | None = None,
    ):
        """Initialize model manager.

        Args:
            config: Model configuration
            anonymizer: Optional hash anonymizer for IP anonymization
            feature_columns: Feature columns expected by the model/scaler. If omitted,
                defaults to the legacy 8-feature flow schema used by existing tests.
        """
        self.config = config
        self.anonymizer = anonymizer

        self.feature_columns = feature_columns or [
            "bytes_in",
            "bytes_out",
            "packets_in",
            "packets_out",
            "duration",
            "src_port",
            "dst_port",
            "protocol",
        ]

        # Prediction thresholds typically live in the PredictionConfig, but tests
        # instantiate ModelManager with only ModelConfig. Provide sensible defaults.
        self.anomaly_threshold = float(getattr(config, "anomaly_threshold", 0.7))
        self.high_risk_threshold = float(getattr(config, "high_risk_threshold", 0.9))

        self._model = None
        self._scaler = None
        self._model_metadata = None
        self._last_load_time = None
        self._load_failures = 0
        self._max_load_failures = 5
        
        # Initialize Firebase if available
        self._storage_client = None
        self._firebase_app = None
        if self._has_firebase_support():
            self._initialize_firebase()
        
        # Ensure local directories exist
        self._ensure_directories()
    
    def _has_firebase_support(self) -> bool:
        """Check if Firebase dependencies are available."""
        return FIREBASE_AVAILABLE
    
    def _initialize_firebase(self) -> None:
        """Initialize Firebase Admin SDK and Storage client."""
        if not FIREBASE_AVAILABLE:
            return
            
        try:
            # Note: This assumes Firebase config is available via environment
            # In a real deployment, the Firebase config would be passed in
            log_event(
                logger,
                "firebase_init_attempted",
                level="info"
            )
            # For now, we'll handle this in a more flexible way
        except Exception as e:
            log_event(
                logger,
                "firebase_initialization_failed",
                level="warning",
                error=str(e)
            )
    
    def _ensure_directories(self) -> None:
        """Ensure required local directories exist."""
        model_dir = Path(self.config.model_local_path)
        scaler_dir = Path(self.config.scaler_local_path)
        
        model_dir.mkdir(parents=True, exist_ok=True)
        scaler_dir.mkdir(parents=True, exist_ok=True)
        
        log_event(
            logger,
            "directories_ensured",
            level="debug",
            model_dir=str(model_dir),
            scaler_dir=str(scaler_dir)
        )
    
    def load_latest_model(self) -> bool:
        """Load the latest Mnemosyne model and scaler.
        
        Returns:
            True if model loaded successfully, False otherwise
        """
        try:
            log_event(
                logger,
                "model_load_attempted",
                level="info"
            )
            
            # Step 1: Get list of available models
            available_models = self._list_remote_models()
            if not available_models:
                log_event(
                    logger,
                    "no_models_available",
                    level="warning"
                )
                return self._use_fallback_model()
            
            # Step 2: Select best model (newest, meets age requirements)
            selected_model = self._select_best_model(available_models)
            if not selected_model:
                log_event(
                    logger,
                    "no_suitable_model_found",
                    level="warning"
                )
                return self._use_fallback_model()
            
            # Step 3: Download model and scaler
            local_paths = self._download_model_artifacts(selected_model)
            if not local_paths:
                log_event(
                    logger,
                    "model_download_failed",
                    level="error"
                )
                return self._use_fallback_model()
            
            # Step 4: Load and validate model
            if not self._load_and_validate_model(local_paths):
                log_event(
                    logger,
                    "model_validation_failed",
                    level="error"
                )
                return self._use_fallback_model()
            
            # Step 5: Update metadata and reset failure count
            self._model_metadata = selected_model
            self._last_load_time = datetime.now()
            self._load_failures = 0
            
            log_event(
                logger,
                "model_loaded_successfully",
                level="info",
                model_name=selected_model.get('name'),
                timestamp=selected_model.get('timestamp'),
                size_mb=selected_model.get('size_mb')
            )
            
            return True
            
        except Exception as e:
            self._load_failures += 1
            log_event(
                logger,
                "model_load_failed",
                level="error",
                error=str(e),
                failure_count=self._load_failures
            )
            return self._use_fallback_model()
    
    def _list_remote_models(self) -> List[Dict[str, Any]]:
        """List available models from Firebase Storage."""
        if not FIREBASE_AVAILABLE:
            return []
        
        try:
            # This would use the actual Firebase Storage client
            # For now, return empty list to simulate no remote access
            log_event(
                logger,
                "remote_models_listed",
                level="debug",
                model_count=0
            )
            return []
            
        except Exception as e:
            log_event(
                logger,
                "failed_to_list_remote_models",
                level="error",
                error=str(e)
            )
            return []
    
    def _select_best_model(self, models: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Select the best model based on age and timestamp.
        
        Args:
            models: List of model metadata dictionaries
            
        Returns:
            Best model metadata or None if no suitable model found
        """
        if not models:
            return None
        
        # Filter models by age requirements
        now = datetime.now()
        min_age = timedelta(hours=self.config.min_model_age_hours)
        max_age = timedelta(days=self.config.max_model_age_days)
        
        suitable_models = []
        for model in models:
            try:
                # Parse model timestamp
                model_time = datetime.strptime(
                    model['timestamp'], 
                    "%Y%m%d_%H%M%S"
                )
                age = now - model_time
                
                if min_age <= age <= max_age:
                    suitable_models.append(model)
                    
            except (ValueError, KeyError) as e:
                log_event(
                    logger,
                    "model_timestamp_parse_error",
                    level="warning",
                    model_name=model.get('name', 'unknown'),
                    error=str(e)
                )
                continue
        
        if not suitable_models:
            # If no models meet age requirements, use newest model anyway
            suitable_models = models
        
        # Select newest model
        best_model = max(
            suitable_models,
            key=lambda x: x['timestamp'],
            default=None
        )
        
        log_event(
            logger,
            "best_model_selected",
            level="info",
            candidate_count=len(suitable_models),
            selected_model=best_model.get('name') if best_model else None
        )
        
        return best_model
    
    def _download_model_artifacts(self, model_info: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Download model and scaler artifacts.
        
        Args:
            model_info: Model metadata dictionary
            
        Returns:
            Dictionary mapping artifact types to local paths, or None if failed
        """
        try:
            timestamp = model_info['timestamp']
            local_model_path = Path(self.config.model_local_path) / f"model_{timestamp}.pkl"
            local_scaler_path = Path(self.config.scaler_local_path) / f"scaler_{timestamp}.pkl"
            
            # For now, simulate successful downloads
            # In real implementation, would download from Firebase Storage
            if local_model_path.exists() and local_scaler_path.exists():
                log_event(
                    logger,
                    "model_artifacts_found_locally",
                    level="info",
                    model_path=str(local_model_path),
                    scaler_path=str(local_scaler_path)
                )
                return {
                    'model': str(local_model_path),
                    'scaler': str(local_scaler_path)
                }
            
            # Simulate download by creating placeholder files for testing
            local_model_path.parent.mkdir(parents=True, exist_ok=True)
            local_scaler_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create mock model and scaler for development/testing
            n_features = max(1, int(len(self.feature_columns)))
            mock_model = IsolationForest(random_state=42)
            mock_model.fit(np.random.randn(100, n_features))

            class MockScaler:
                mean_ = np.zeros(n_features)
                scale_ = np.ones(n_features)

                def transform(self, X):
                    return X

                def fit_transform(self, X):
                    return X

                def inverse_transform(self, X):
                    return X

            mock_scaler = MockScaler()
            
            with open(local_model_path, 'wb') as f:
                pickle.dump(mock_model, f)
            
            with open(local_scaler_path, 'wb') as f:
                pickle.dump(mock_scaler, f)
            
            log_event(
                logger,
                "model_artifacts_downloaded",
                level="info",
                model_path=str(local_model_path),
                scaler_path=str(local_scaler_path)
            )
            
            return {
                'model': str(local_model_path),
                'scaler': str(local_scaler_path)
            }
            
        except Exception as e:
            log_event(
                logger,
                "model_download_failed",
                level="error",
                error=str(e)
            )
            return None
    
    def _load_and_validate_model(self, local_paths: Dict[str, str]) -> bool:
        """Load and validate model and scaler.
        
        Args:
            local_paths: Dictionary mapping artifact types to local paths
            
        Returns:
            True if validation successful, False otherwise
        """
        try:
            model_path = local_paths['model']
            scaler_path = local_paths['scaler']
            
            # Load model
            with open(model_path, 'rb') as f:
                self._model = pickle.load(f)
            
            # Validate model
            if not self._validate_model():
                raise ModelValidationError("Model validation failed")
            
            # Load scaler
            with open(scaler_path, 'rb') as f:
                self._scaler = pickle.load(f)
            
            # Validate scaler
            if not self._validate_scaler():
                raise ScalerValidationError("Scaler validation failed")
            
            log_event(
                logger,
                "model_and_scaler_loaded",
                level="info",
                model_type=type(self._model).__name__,
                scaler_type=type(self._scaler).__name__
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "model_validation_failed",
                level="error",
                error=str(e)
            )
            self._model = None
            self._scaler = None
            return False
    
    def _validate_model(self) -> bool:
        """Validate that the loaded model is suitable for predictions.
        
        Returns:
            True if model is valid, False otherwise
        """
        try:
            if self._model is None:
                return False
            
            # Check if model has required methods
            required_methods = ['predict', 'decision_function', 'score_samples']
            for method in required_methods:
                if not hasattr(self._model, method):
                    log_event(
                        logger,
                        "model_missing_method",
                        level="error",
                        method=method
                    )
                    return False
            
            n_features = int(getattr(self._model, "n_features_in_", len(self.feature_columns)))
            n_features = max(1, n_features)

            test_data = np.arange(1, n_features * 2 + 1, dtype=float).reshape(2, n_features)
            if self._scaler is not None and hasattr(self._scaler, "transform"):
                test_data_scaled = self._scaler.transform(test_data)
            else:
                test_data_scaled = test_data
            
            predictions = self._model.predict(test_data_scaled)
            scores = self._model.decision_function(test_data_scaled)

            # Basic sanity checks
            if len(predictions) != len(test_data) or len(scores) != len(test_data):
                log_event(
                    logger,
                    "model_prediction_length_mismatch",
                    level="error"
                )
                return False
            
            if not all(score in [-1, 1] for score in predictions):
                log_event(
                    logger,
                    "model_prediction_values_invalid",
                    level="error"
                )
                return False
            
            log_event(
                logger,
                "model_validation_passed",
                level="debug"
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "model_validation_error",
                level="error",
                error=str(e)
            )
            return False
    
    def _validate_scaler(self) -> bool:
        """Validate that the loaded scaler is suitable for preprocessing.
        
        Returns:
            True if scaler is valid, False otherwise
        """
        try:
            if self._scaler is None:
                return False
            
            # Check if scaler has required methods
            required_methods = ['transform']
            for method in required_methods:
                if not hasattr(self._scaler, method):
                    log_event(
                        logger,
                        "scaler_missing_method",
                        level="error",
                        method=method
                    )
                    return False
            
            # Test scaler with dummy data
            n_features = len(getattr(self._scaler, "mean_", [])) or len(self.feature_columns)
            n_features = max(1, int(n_features))
            test_data = np.arange(1, n_features * 2 + 1, dtype=float).reshape(2, n_features)

            try:
                scaled_data = self._scaler.transform(test_data)
                if np.asarray(scaled_data).shape != test_data.shape:
                    log_event(
                        logger,
                        "scaler_output_shape_mismatch",
                        level="error"
                    )
                    return False
            except Exception as e:
                log_event(
                    logger,
                    "scaler_transform_failed",
                    level="error",
                    error=str(e)
                )
                return False
            
            log_event(
                logger,
                "scaler_validation_passed",
                level="debug"
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "scaler_validation_error",
                level="error",
                error=str(e)
            )
            return False
    
    def _use_fallback_model(self) -> bool:
        """Use fallback model when main model loading fails.
        
        Prioritizes:
        1. Foundation Model (Shipped with appliance)
        2. Random Noise Model (Last resort)

        Returns:
            True if fallback model loaded successfully, False otherwise
        """
        # Try loading foundation model first
        if self._load_foundation_model():
            return True

        try:
            if not self.config.use_fallback_model:
                log_event(
                    logger,
                    "fallback_model_disabled",
                    level="info"
                )
                return False
            
            n_features = max(1, int(len(self.feature_columns)))

            # Create a simple fallback model.
            # NOTE: fallback_prediction_threshold is not the same as IsolationForest's
            # contamination parameter (which must be <= 0.5). Use a conservative default.
            self._model = IsolationForest(
                contamination=0.1,
                random_state=42,
            )

            dummy_data = np.random.randn(200, n_features)
            self._model.fit(dummy_data)

            class FallbackScaler:
                mean_ = np.zeros(n_features)
                scale_ = np.ones(n_features)

                def transform(self, X):
                    return X

                def fit_transform(self, X):
                    return X

                def inverse_transform(self, X):
                    return X

            self._scaler = FallbackScaler()
            
            self._load_failures += 1
            
            log_event(
                logger,
                "fallback_model_loaded",
                level="warning",
                failure_count=self._load_failures
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "fallback_model_load_failed",
                level="error",
                error=str(e)
            )
            return False

    def _load_foundation_model(self) -> bool:
        """Load the shipped Foundation Model.

        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            model_path = Path(self.config.foundation_model_path)
            scaler_path = Path(self.config.foundation_scaler_path)

            if not (model_path.exists() and scaler_path.exists()):
                log_event(
                    logger,
                    "foundation_model_not_found",
                    level="debug",
                    model_path=str(model_path),
                    scaler_path=str(scaler_path)
                )
                return False

            # Load model
            with open(model_path, 'rb') as f:
                self._model = pickle.load(f)

            # Validate model
            if not self._validate_model():
                raise ModelValidationError("Foundation model validation failed")

            # Load scaler
            with open(scaler_path, 'rb') as f:
                self._scaler = pickle.load(f)

            # Validate scaler
            if not self._validate_scaler():
                raise ScalerValidationError("Foundation scaler validation failed")

            self._model_metadata = {
                'name': 'Foundation Model',
                'timestamp': '00000000_000000', # Epoch
                'type': 'foundation'
            }

            log_event(
                logger,
                "foundation_model_loaded",
                level="info"
            )

            return True

        except Exception as e:
            log_event(
                logger,
                "foundation_model_load_failed",
                level="error",
                error=str(e)
            )
            return False
    
    def is_model_available(self) -> bool:
        """Check if a valid model is currently loaded.
        
        Returns:
            True if model is available and valid
        """
        return (self._model is not None and 
                self._scaler is not None and 
                self._validate_model() and 
                self._validate_scaler())
    
    def predict_flows(self, flows_df: pd.DataFrame) -> pd.DataFrame:
        """Make predictions on a batch of flows.
        
        Args:
            flows_df: DataFrame containing flow data
            
        Returns:
            DataFrame with predictions added
        """
        if not self.is_model_available():
            raise ModelLoadError("No valid model available for predictions")
        
        try:
            # Extract features
            features_df = self._extract_features(flows_df)
            
            # Scale features
            if self._scaler:
                features_scaled = self._scaler.transform(features_df.values)
            else:
                features_scaled = features_df.values
            
            # Make predictions
            predictions = self._model.predict(features_scaled)
            scores = self._model.decision_function(features_scaled)
            probabilities = self._model.score_samples(features_scaled)
            
            # Add results to original dataframe
            result_df = flows_df.copy()
            result_df['prediction'] = predictions
            result_df['anomaly_score'] = scores
            result_df['probability'] = probabilities
            
            # Classify risk levels
            result_df['risk_level'] = result_df['anomaly_score'].apply(
                self._classify_risk_level
            )
            
            log_event(
                logger,
                "predictions_completed",
                level="debug",
                flow_count=len(flows_df),
                anomaly_count=len(result_df[result_df['prediction'] == -1]),
                avg_score=result_df['anomaly_score'].mean()
            )
            
            return result_df
            
        except Exception as e:
            log_event(
                logger,
                "prediction_failed",
                level="error",
                error=str(e),
                flow_count=len(flows_df)
            )
            raise
    
    def _extract_features(self, flows_df: pd.DataFrame) -> pd.DataFrame:
        """Extract and prepare features from flow data.
        
        Args:
            flows_df: DataFrame containing flow data
            
        Returns:
            DataFrame with extracted features
        """
        try:
            # Ensure required columns exist
            required_cols = self.feature_columns
            missing_cols = [col for col in required_cols if col not in flows_df.columns]
            
            if missing_cols:
                raise ValueError(f"Missing required columns: {missing_cols}")
            
            # Select and prepare features
            features_df = flows_df[required_cols].copy()
            
            # Convert to numeric, replacing non-numeric values with 0
            for col in features_df.columns:
                features_df[col] = pd.to_numeric(features_df[col], errors='coerce').fillna(0)
            
            # Handle categorical features
            if 'protocol' in features_df.columns:
                # Convert protocol to numeric (TCP=1, UDP=2, ICMP=3, etc.)
                protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'OTHER': 0}
                features_df['protocol'] = features_df['protocol'].map(protocol_map).fillna(0)
            
            return features_df
            
        except Exception as e:
            log_event(
                logger,
                "feature_extraction_failed",
                level="error",
                error=str(e)
            )
            raise
    
    def _classify_risk_level(self, anomaly_score: float) -> str:
        """Classify risk level based on anomaly score.
        
        Args:
            anomaly_score: Anomaly score from model (-1 = anomaly, 1 = normal)
            
        Returns:
            Risk level string: "low", "medium", "high", "critical"
        """
        # Note: anomaly_score is typically negative for anomalies
        # We'll use the absolute value for classification
        abs_score = abs(anomaly_score)
        
        if abs_score >= self.high_risk_threshold:
            return "critical"
        elif abs_score >= self.anomaly_threshold:
            return "high"
        elif abs_score >= self.anomaly_threshold * 0.5:
            return "medium"
        else:
            return "low"
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the currently loaded model.
        
        Returns:
            Dictionary with model information
        """
        info = {
            'model_available': self.is_model_available(),
            'model_type': type(self._model).__name__ if self._model else None,
            'scaler_type': type(self._scaler).__name__ if self._scaler else None,
            'last_load_time': self._last_load_time.isoformat() if self._last_load_time else None,
            'load_failures': self._load_failures,
            'fallback_in_use': self._load_failures >= self._max_load_failures
        }
        
        if self._model_metadata:
            info['model_metadata'] = self._model_metadata
        
        return info

    def explain_anomaly(self, flow_features: pd.Series, top_k: int = 3) -> List[str]:
        """Explain why a flow was flagged as anomalous using Z-score heuristics.

        Uses a heuristic approach by calculating Z-scores for each feature based on
        the scaler's mean and scale. Features with the largest absolute Z-scores
        are considered the primary contributors to the anomaly.

        Args:
            flow_features: Series containing the feature values for the anomalous flow.
            top_k: Number of top contributing features to return.

        Returns:
            List of human-readable explanation strings (e.g. "bytes_out (+4.2s)").
        """
        if not self._scaler or not hasattr(self._scaler, 'mean_') or not hasattr(self._scaler, 'scale_'):
            return ["Explanation unavailable (no scaler stats)"]

        try:
            # Ensure input is numeric
            features = pd.to_numeric(flow_features, errors='coerce').fillna(0)

            # Reindex to match scaler features if needed
            # (Assuming flow_features comes from the same source as predict_flows input)

            # Calculate Z-scores: (x - mean) / scale
            # Note: We need to handle potential shape mismatches if features are passed differently
            # The scaler expects features in the order of self.feature_columns

            z_scores = {}
            for i, col in enumerate(self.feature_columns):
                if col in features.index:
                    val = features[col]
                    mean = self._scaler.mean_[i]
                    scale = self._scaler.scale_[i]

                    if scale == 0:
                        z_score = 0
                    else:
                        z_score = (val - mean) / scale

                    z_scores[col] = z_score

            # Sort by absolute Z-score (descending)
            sorted_features = sorted(z_scores.items(), key=lambda item: abs(item[1]), reverse=True)

            explanations = []
            for col, z in sorted_features[:top_k]:
                # Only report if significantly deviating (e.g. > 2 sigma)
                # But for the top contributor, we might want to show it regardless?
                # Let's show the top_k regardless, but formatted nicely.
                sign = "+" if z >= 0 else ""
                explanations.append(f"{col} ({sign}{z:.1f}σ)")

            return explanations

        except Exception as e:
            log_event(
                logger,
                "anomaly_explanation_failed",
                level="warning",
                error=str(e)
            )
            return ["Explanation calculation failed"]