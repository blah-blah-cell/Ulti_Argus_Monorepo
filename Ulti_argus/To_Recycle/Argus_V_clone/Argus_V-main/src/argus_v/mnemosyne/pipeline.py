"""Main Mnemosyne trainer pipeline orchestration.

This module provides the main pipeline class that orchestrates data loading,
preprocessing, training, and artifact management for the mnemosyne trainer.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from ..oracle_core.logging import log_event
from .artifact_manager import ArtifactManager
from .config import MnemosyneConfig
from .data_loader import FirebaseDataLoader
from .preprocessing import FlowPreprocessor
from .trainer import IsolationForestTrainer

logger = logging.getLogger(__name__)


class MnemosynePipeline:
    """Main orchestrator for the Mnemosyne training pipeline."""
    
    def __init__(self, config: MnemosyneConfig):
        """Initialize the pipeline with configuration."""
        self.config = config
        self._data_loader = None
        self._preprocessor = None
        self._trainer = None
        self._artifact_manager = None
        self._temp_dir = None
        
        # Initialize components
        self._initialize_components()
    
    def _initialize_components(self) -> None:
        """Initialize all pipeline components."""
        try:
            # Initialize data loader
            self._data_loader = FirebaseDataLoader(self.config.firebase)
            
            # Initialize preprocessor
            self._preprocessor = FlowPreprocessor(self.config.preprocessing)
            
            # Initialize trainer
            self._trainer = IsolationForestTrainer(self.config.training)
            
            # Initialize artifact manager
            self._artifact_manager = ArtifactManager(self.config.firebase)
            
            # Create temporary directory for local artifacts
            self._temp_dir = Path(tempfile.mkdtemp(prefix="mnemosyne_"))
            
            log_event(
                logger,
                "mnemosyne_pipeline_initialized",
                level="info",
                config_summary=self.config.to_safe_dict()
            )
            
        except Exception as e:
            log_event(
                logger,
                "mnemosyne_pipeline_initialization_failed",
                level="error",
                error=str(e)
            )
            raise
    
    def run_training_pipeline(self, max_training_data_age_hours: Optional[int] = None) -> Dict[str, Any]:
        """Execute the complete training pipeline.
        
        Args:
            max_training_data_age_hours: Maximum age of training data to use
            
        Returns:
            Dictionary containing pipeline execution results and statistics
        """
        pipeline_stats = {
            'pipeline_start': None,
            'pipeline_end': None,
            'data_loading': {},
            'preprocessing': {},
            'training': {},
            'artifact_management': {},
            'cleanup': {}
        }
        
        try:
            import datetime
            pipeline_stats['pipeline_start'] = datetime.datetime.now().isoformat()
            
            log_event(
                logger,
                "mnemosyne_training_pipeline_started",
                level="info",
                max_training_data_age_hours=max_training_data_age_hours
            )
            
            # Step 1: Load training data
            log_event(logger, "step_1_data_loading", level="info")
            training_files = self._data_loader.list_training_csvs(max_age_hours=max_training_data_age_hours)
            
            if not training_files:
                raise ValueError("No training data files found")
            
            log_event(
                logger,
                "training_files_found",
                level="info",
                file_count=len(training_files),
                files=training_files
            )
            
            # Load and combine all training data
            combined_df = self._data_loader.combine_flows(training_files)
            
            pipeline_stats['data_loading'] = {
                'files_processed': len(training_files),
                'total_rows': len(combined_df),
                'columns': list(combined_df.columns),
                'date_range': {
                    'start': combined_df['timestamp'].min().isoformat(),
                    'end': combined_df['timestamp'].max().isoformat()
                }
            }
            
            log_event(
                logger,
                "data_loading_completed",
                level="info",
                pipeline_stats=pipeline_stats['data_loading']
            )
            
            # Step 2: Preprocess data
            log_event(logger, "step_2_preprocessing", level="info")
            preprocessed_df, preprocessing_stats = self._preprocessor.preprocess_pipeline(combined_df)
            
            pipeline_stats['preprocessing'] = preprocessing_stats
            
            log_event(
                logger,
                "preprocessing_completed",
                level="info",
                pipeline_stats=pipeline_stats['preprocessing']
            )
            
            # Step 3: Train model
            log_event(logger, "step_3_training", level="info")

            contamination = None
            if isinstance(preprocessing_stats, dict):
                contamination = preprocessing_stats.get("optimal_contamination")

            if contamination is not None:
                training_stats = self._trainer.train_model(preprocessed_df, contamination=contamination)
            else:
                training_stats = self._trainer.train_model(preprocessed_df)

            pipeline_stats['training'] = training_stats
            
            log_event(
                logger,
                "training_completed",
                level="info",
                pipeline_stats=pipeline_stats['training']
            )
            
            # Step 4: Serialize and upload artifacts
            log_event(logger, "step_4_artifact_management", level="info")
            artifact_paths = self._trainer.serialize_model(
                str(self._temp_dir), 
                self._preprocessor._scaler
            )
            
            # Upload artifacts to Firebase
            upload_stats = self._artifact_manager.upload_model_artifacts(artifact_paths)
            
            pipeline_stats['artifact_management'] = {
                'serialization': artifact_paths,
                'upload': upload_stats
            }
            
            log_event(
                logger,
                "artifact_management_completed",
                level="info",
                pipeline_stats=pipeline_stats['artifact_management']
            )
            
            # Step 5: Cleanup old training data
            log_event(logger, "step_5_cleanup", level="info")
            cleanup_stats = self._data_loader.delete_old_training_data(
                self.config.firebase.cleanup_threshold_hours
            )
            
            pipeline_stats['cleanup'] = cleanup_stats
            
            log_event(
                logger,
                "cleanup_completed",
                level="info",
                pipeline_stats=pipeline_stats['cleanup']
            )
            
            pipeline_stats['pipeline_end'] = datetime.datetime.now().isoformat()
            
            # Calculate total execution time
            start_time = datetime.datetime.fromisoformat(pipeline_stats['pipeline_start'])
            end_time = datetime.datetime.fromisoformat(pipeline_stats['pipeline_end'])
            execution_time = (end_time - start_time).total_seconds()
            
            pipeline_stats['execution_time_seconds'] = execution_time
            
            log_event(
                logger,
                "mnemosyne_training_pipeline_completed",
                level="info",
                execution_time_seconds=execution_time,
                final_stats=pipeline_stats
            )
            
            return pipeline_stats
            
        except Exception as e:
            pipeline_stats['pipeline_end'] = datetime.datetime.now().isoformat()
            pipeline_stats['error'] = str(e)
            
            log_event(
                logger,
                "mnemosyne_training_pipeline_failed",
                level="error",
                error=str(e),
                pipeline_stats=pipeline_stats
            )
            
            raise
    
    def validate_setup(self) -> Dict[str, Any]:
        """Validate that the pipeline setup is correct.
        
        Returns:
            Dictionary containing validation results
        """
        validation_results = {
            'firebase_connection': False,
            'service_account_accessible': False,
            'storage_permissions': False,
            'training_data_accessible': False,
            'overall_status': 'invalid'
        }
        
        try:
            # Check service account file
            service_account_path = Path(self.config.firebase.service_account_path)
            if service_account_path.exists():
                validation_results['service_account_accessible'] = True
            else:
                log_event(
                    logger,
                    "service_account_file_not_found",
                    level="error",
                    path=str(service_account_path)
                )
            
            # Test Firebase connection
            test_files = self._data_loader.list_training_csvs(max_age_hours=24*7)  # Last week
            validation_results['training_data_accessible'] = True
            
            # Test storage permissions (try to list models)
            try:
                existing_models = self._artifact_manager.list_existing_models(max_age_days=1)
                validation_results['storage_permissions'] = True
            except Exception as e:
                log_event(
                    logger,
                    "storage_permission_test_failed",
                    level="error",
                    error=str(e)
                )
            
            validation_results['firebase_connection'] = True
            
            # Determine overall status
            if all([
                validation_results['service_account_accessible'],
                validation_results['firebase_connection'],
                validation_results['storage_permissions']
            ]):
                validation_results['overall_status'] = 'valid'
            elif validation_results['firebase_connection']:
                validation_results['overall_status'] = 'partial'
            
            log_event(
                logger,
                "setup_validation_completed",
                level="info",
                validation_results=validation_results
            )
            
            return validation_results
            
        except Exception as e:
            validation_results['error'] = str(e)
            
            log_event(
                logger,
                "setup_validation_failed",
                level="error",
                error=str(e)
            )
            
            return validation_results
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current status of the pipeline and storage.
        
        Returns:
            Dictionary containing pipeline status information
        """
        status = {
            'timestamp': None,
            'storage_usage': {},
            'recent_models': [],
            'pipeline_health': 'unknown'
        }
        
        try:
            import datetime
            status['timestamp'] = datetime.datetime.now().isoformat()
            
            # Get storage usage
            status['storage_usage'] = self._artifact_manager.get_storage_usage()
            
            # Get recent models
            status['recent_models'] = self._artifact_manager.list_existing_models(max_age_days=30)
            
            # Determine pipeline health
            if status['storage_usage']['total_size_mb'] < 1000:  # Less than 1GB
                status['pipeline_health'] = 'healthy'
            elif status['storage_usage']['total_size_mb'] < 5000:  # Less than 5GB
                status['pipeline_health'] = 'moderate'
            else:
                status['pipeline_health'] = 'high_usage'
            
            log_event(
                logger,
                "pipeline_status_retrieved",
                level="info",
                status=status
            )
            
            return status
            
        except Exception as e:
            status['error'] = str(e)
            status['pipeline_health'] = 'error'
            
            log_event(
                logger,
                "pipeline_status_failed",
                level="error",
                error=str(e)
            )
            
            return status
    
    def cleanup(self) -> None:
        """Clean up temporary resources."""
        try:
            # Remove temporary directory
            if self._temp_dir and self._temp_dir.exists():
                import shutil
                shutil.rmtree(self._temp_dir)
                log_event(
                    logger,
                    "temporary_directory_cleaned",
                    level="info",
                    temp_dir=str(self._temp_dir)
                )
            
            # Clean up Firebase connections
            if self._data_loader:
                self._data_loader.__del__()
            
            if self._artifact_manager:
                self._artifact_manager.__del__()
                
        except Exception as e:
            log_event(
                logger,
                "cleanup_failed",
                level="error",
                error=str(e)
            )
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.cleanup()