"""Model trainer for Mnemosyne pipeline.

This module provides functionality for training IsolationForest models on preprocessed
network flow data using scikit-learn, including model validation, serialization, and artifact management.
"""

from __future__ import annotations

import logging
import warnings
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import skops.io as sio
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import GridSearchCV, train_test_split

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)


class IsolationForestTrainer:
    """Trainer for IsolationForest anomaly detection models."""
    
    def __init__(self, config):
        """Initialize trainer with configuration."""
        self.config = config
        self._best_model = None
        self._best_scaler = None
        self._training_stats = {}
        
    def _generate_model_name(self, model_stats: Dict[str, Any]) -> str:
        """Generate a unique model name based on stats and timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sample_count = model_stats.get('sample_count', 0)
        contamination = model_stats.get('contamination', 0)
        
        return f"isolation_forest_{timestamp}_s{sample_count}_c{contamination:.3f}"
    
    def _validate_data_sufficiency(self, df: pd.DataFrame) -> Tuple[bool, str]:
        """Validate that data is sufficient for training.
        
        Args:
            df: Preprocessed feature DataFrame
            
        Returns:
            Tuple of (is_sufficient, reason)
        """
        min_samples = self.config.min_samples_for_training
        
        if len(df) < min_samples:
            return False, f"Insufficient samples: {len(df)} < {min_samples}"
        
        if df.empty:
            return False, "DataFrame is empty"
        
        # Check for sufficient feature variance
        if df.var().min() == 0:
            return False, "One or more features have zero variance"
        
        # Check for NaN values
        if df.isnull().any().any():
            return False, "Data contains NaN values"
        
        return True, "Data validation passed"
    
    def _create_parameter_grid(self) -> Dict[str, List[Any]]:
        """Create parameter grid for hyperparameter tuning.
        
        Returns:
            Dictionary of parameter names to lists of values
        """
        min_estimators, max_estimators = self.config.n_estimators_range
        min_samples, max_samples = self.config.max_samples_range
        
        param_grid = {
            'n_estimators': list(range(min_estimators, max_estimators + 1, 25)),
            'max_samples': list(np.linspace(min_samples, max_samples, 3)),
            'bootstrap': self.config.bootstrap_options
        }
        
        return param_grid
    
    def train_isolation_forest(self, X_train: pd.DataFrame, contamination: float) -> IsolationForest:
        """Train IsolationForest with hyperparameter tuning.
        
        Args:
            X_train: Training feature matrix
            contamination: Contamination parameter value
            
        Returns:
            Trained IsolationForest model
        """
        param_grid = self._create_parameter_grid()
        
        # Add contamination to parameter grid
        param_grid['contamination'] = [contamination]
        
        # Create base estimator
        base_estimator = IsolationForest(random_state=self.config.random_state)
        
        # Perform grid search with reduced CV folds for efficiency
        cv_folds = min(self.config.cross_validation_folds, 3)
        
        log_event(
            logger,
            "hyperparameter_tuning_started",
            level="info",
            param_combinations=len(param_grid['n_estimators']) * len(param_grid['max_samples']) * len(param_grid['bootstrap']),
            cv_folds=cv_folds
        )
        
        def _unsupervised_scorer(estimator, X, y=None):  # noqa: ARG001
            # IsolationForest.score returns the mean score_samples; higher is "more normal".
            return float(estimator.score(X))

        grid_search = GridSearchCV(
            base_estimator,
            param_grid,
            cv=cv_folds,
            scoring=_unsupervised_scorer,
            n_jobs=1,  # Single-threaded for reproducibility
            verbose=0,
        )
        
        # Suppress sklearn warnings about sample weights
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            grid_search.fit(X_train)
        
        best_model = grid_search.best_estimator_
        
        log_event(
            logger,
            "hyperparameter_tuning_completed",
            level="info",
            best_params=grid_search.best_params_,
            best_score=grid_search.best_score_,
            n_features=X_train.shape[1]
        )
        
        return best_model
    
    def evaluate_model(self, model: IsolationForest, X_test: pd.DataFrame, y_test: Optional[pd.Series] = None) -> Dict[str, Any]:
        """Evaluate trained model performance.
        
        Args:
            model: Trained IsolationForest model
            X_test: Test feature matrix
            y_test: True labels (if available)
            
        Returns:
            Dictionary containing evaluation metrics
        """
        # Get anomaly scores and predictions
        anomaly_scores = model.decision_function(X_test)
        predictions = model.predict(X_test)
        
        # Calculate anomaly rate
        anomalies = (predictions == -1).sum()
        anomaly_rate = anomalies / len(predictions)
        
        evaluation_stats = {
            'total_samples': len(X_test),
            'anomalies_detected': int(anomalies),
            'anomaly_rate': float(anomaly_rate),
            'mean_anomaly_score': float(np.mean(anomaly_scores)),
            'std_anomaly_score': float(np.std(anomaly_scores)),
            'min_anomaly_score': float(np.min(anomaly_scores)),
            'max_anomaly_score': float(np.max(anomaly_scores))
        }
        
        # If true labels are available, calculate additional metrics
        if y_test is not None:
            try:
                # Convert predictions to binary (1 for anomaly, 0 for normal)
                pred_binary = (predictions == -1).astype(int)
                y_binary = (y_test == -1).astype(int)
                
                # Calculate AUC if we have both classes
                if len(np.unique(y_binary)) > 1:
                    auc_score = roc_auc_score(y_binary, -anomaly_scores)  # Negative scores for AUC
                    evaluation_stats['auc_score'] = float(auc_score)
                
                # Classification report
                class_report = classification_report(y_binary, pred_binary, output_dict=True)
                evaluation_stats['classification_report'] = class_report
                
            except Exception as e:
                log_event(
                    logger,
                    "detailed_evaluation_failed",
                    level="warning",
                    error=str(e)
                )
        
        log_event(
            logger,
            "model_evaluation_completed",
            level="info",
            evaluation_stats=evaluation_stats
        )
        
        return evaluation_stats
    
    def train_model(
        self,
        features_df: pd.DataFrame,
        true_labels: Optional[pd.Series] = None,
        contamination: float | None = None,
    ) -> Dict[str, Any]:
        """Train IsolationForest model with validation.

        Args:
            features_df: Preprocessed feature DataFrame
            true_labels: True anomaly labels (optional)
            contamination: Optional contamination override to use during training

        Returns:
            Dictionary containing training results and statistics
        """
        is_sufficient, reason = self._validate_data_sufficiency(features_df)
        if not is_sufficient:
            raise ValueError(f"Insufficient data for training: {reason}")

        log_event(
            logger,
            "training_started",
            level="info",
            sample_count=len(features_df),
            feature_count=features_df.shape[1],
        )

        test_size = self.config.validation_split
        if len(features_df) < 100:
            test_size = min(0.2, 20 / len(features_df))

        if true_labels is not None:
            X_train, X_test, _, y_test = train_test_split(
                features_df,
                true_labels,
                test_size=test_size,
                random_state=self.config.random_state,
            )
        else:
            X_train, X_test = train_test_split(
                features_df,
                test_size=test_size,
                random_state=self.config.random_state,
            )
            y_test = None

        if contamination is not None:
            training_contamination = float(contamination)
        else:
            contam_range = getattr(self.config, "contamination_range", None)
            if contam_range is not None:
                min_contam, max_contam = contam_range
                training_contamination = float((min_contam + max_contam) / 2)
            else:
                training_contamination = 0.05

        # Keep within sklearn's expected range
        training_contamination = float(min(max(training_contamination, 0.001), 0.5))

        model = self.train_isolation_forest(X_train, training_contamination)

        eval_stats = self.evaluate_model(model, X_test, y_test)

        self._training_stats = {
            "training_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "feature_count": int(features_df.shape[1]),
            "model_parameters": model.get_params(),
            "training_contamination": float(training_contamination),
            "evaluation": eval_stats,
            "training_timestamp": datetime.now().isoformat(),
            "random_state": int(self.config.random_state),
        }

        self._best_model = model

        log_event(
            logger,
            "training_completed",
            level="info",
            training_stats=self._training_stats,
        )

        return self._training_stats
    
    def serialize_model(self, output_path: str, scaler: Any) -> Dict[str, str]:
        """Serialize trained model and scaler to files.
        
        Args:
            output_path: Directory path for saving artifacts
            scaler: Fitted scaler object
            
        Returns:
            Dictionary containing paths to saved artifacts
        """
        if self._best_model is None:
            raise ValueError("No trained model available. Call train_model() first.")
        
        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate model name
        model_name = self._generate_model_name({
            'sample_count': self._training_stats.get('training_samples', 0),
            'contamination': self._training_stats.get('training_contamination', 0)
        })
        
        # Define artifact paths
        model_path = output_dir / f"{model_name}_model.skops"
        scaler_path = output_dir / f"{model_name}_scaler.skops"
        metadata_path = output_dir / f"{model_name}_metadata.json"
        
        try:
            # Serialize model
            sio.dump(self._best_model, model_path)
            
            # Serialize scaler
            sio.dump(scaler, scaler_path)
            
            # Create metadata
            metadata = {
                'model_name': model_name,
                'training_stats': self._training_stats,
                'serialization_timestamp': datetime.now().isoformat(),
                'model_type': 'IsolationForest',
                'feature_columns': getattr(scaler, 'feature_names_in_', None),
                'scaler_type': type(scaler).__name__,
                'model_file': model_path.name,
                'scaler_file': scaler_path.name
            }
            
            import json
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            
            # Check file sizes
            model_size_mb = model_path.stat().st_size / (1024 * 1024)
            scaler_size_mb = scaler_path.stat().st_size / (1024 * 1024)
            total_size_mb = model_size_mb + scaler_size_mb
            
            if total_size_mb > self.config.max_model_size_mb:
                log_event(
                    logger,
                    "model_size_warning",
                    level="warning",
                    total_size_mb=total_size_mb,
                    max_size_mb=self.config.max_model_size_mb
                )
            
            artifact_paths = {
                'model_path': str(model_path),
                'scaler_path': str(scaler_path),
                'metadata_path': str(metadata_path),
                'model_size_mb': model_size_mb,
                'scaler_size_mb': scaler_size_mb,
                'total_size_mb': total_size_mb
            }
            
            log_event(
                logger,
                "model_serialization_completed",
                level="info",
                artifact_paths=artifact_paths
            )
            
            return artifact_paths
            
        except Exception as e:
            log_event(
                logger,
                "model_serialization_failed",
                level="error",
                error=str(e),
                model_path=str(model_path),
                scaler_path=str(scaler_path)
            )
            raise
    
    def load_model(self, model_path: str) -> IsolationForest:
        """Load serialized model from disk.
        
        Args:
            model_path: Path to serialized model file
            
        Returns:
            Loaded IsolationForest model
        """
        try:
            # Get untrusted types from the file to explicitly trust them
            # This is safe because we trust the files we generate, but explicit trust
            # is required by skops >= 0.10 for security.
            trusted_types = sio.get_untrusted_types(file=model_path)
            model = sio.load(model_path, trusted=trusted_types)
            
            log_event(
                logger,
                "model_loaded_successfully",
                level="info",
                model_path=model_path,
                model_type=type(model).__name__
            )
            
            return model
            
        except Exception as e:
            log_event(
                logger,
                "model_loading_failed",
                level="error",
                model_path=model_path,
                error=str(e)
            )
            raise
    
    def get_training_stats(self) -> Dict[str, Any]:
        """Get training statistics from the last training session.
        
        Returns:
            Dictionary containing training statistics
        """
        return self._training_stats.copy()