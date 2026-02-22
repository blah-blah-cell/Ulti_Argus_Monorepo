"""Artifact manager for Mnemosyne trainer pipeline.

This module handles uploading trained models to Firebase Storage, managing artifacts,
and cleaning up old training data and models.
"""

from __future__ import annotations

import json
import logging
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

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)


class ArtifactManager:
    """Manages model artifacts and Firebase Storage operations."""
    
    def __init__(self, config):
        """Initialize artifact manager with Firebase configuration."""
        self.config = config
        self._storage_client = None
        self._firebase_app = None
        
        if not FIREBASE_AVAILABLE:
            raise ImportError(
                "firebase-admin and google-cloud-storage are required for Firebase operations. "
                "Install with: pip install firebase-admin google-cloud-storage"
            )
        
        self._initialize_firebase()
    
    def _initialize_firebase(self) -> None:
        """Initialize Firebase Admin SDK and Storage client."""
        try:
            # Initialize Firebase Admin SDK
            cred = credentials.Certificate(self.config.service_account_path)
            self._firebase_app = firebase_admin.initialize_app(
                cred, 
                {
                    'projectId': self.config.project_id,
                    'storageBucket': self.config.storage_bucket,
                }
            )
            
            # Initialize Cloud Storage client
            self._storage_client = storage.bucket(
                name=self.config.storage_bucket,
                app=self._firebase_app
            )
            
            log_event(
                logger, 
                "artifact_manager_firebase_initialized",
                level="info",
                project_id=self.config.project_id,
                storage_bucket=self.config.storage_bucket
            )
            
        except Exception as e:
            log_event(
                logger,
                "artifact_manager_firebase_initialization_failed",
                level="error",
                error=str(e)
            )
            raise
    
    def upload_model_artifacts(self, local_paths: Dict[str, str]) -> Dict[str, Any]:
        """Upload model artifacts to Firebase Storage.
        
        Args:
            local_paths: Dictionary mapping artifact types to local file paths
            
        Returns:
            Dictionary containing upload statistics and remote paths
        """
        upload_stats = {
            'uploaded_files': {},
            'total_size_mb': 0.0,
            'upload_timestamp': datetime.now().isoformat()
        }
        
        try:
            # Generate timestamp for remote paths
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            for artifact_type, local_path in local_paths.items():
                if artifact_type in ['model_path', 'scaler_path', 'metadata_path']:
                    local_file = Path(local_path)
                    if not local_file.exists():
                        raise FileNotFoundError(f"Local file not found: {local_path}")
                    
                    # Calculate remote path
                    filename = local_file.name
                    remote_path = f"{self.config.model_output_path}/{timestamp}/{filename}"
                    
                    # Upload file
                    blob = self._storage_client.blob(remote_path)
                    blob.upload_from_filename(local_path)
                    
                    # Get file size
                    file_size_mb = local_file.stat().st_size / (1024 * 1024)
                    upload_stats['total_size_mb'] += file_size_mb
                    
                    # Store upload info
                    upload_stats['uploaded_files'][artifact_type] = {
                        'local_path': local_path,
                        'remote_path': remote_path,
                        'size_mb': file_size_mb
                    }
                    
                    log_event(
                        logger,
                        "artifact_uploaded",
                        level="info",
                        artifact_type=artifact_type,
                        local_path=local_path,
                        remote_path=remote_path,
                        size_mb=file_size_mb
                    )
            
            # Upload a summary file
            summary_data = {
                'model_info': upload_stats['uploaded_files'],
                'total_size_mb': upload_stats['total_size_mb'],
                'upload_timestamp': upload_stats['upload_timestamp'],
                'config': self.config.to_safe_dict()
            }
            
            summary_path = f"{self.config.model_output_path}/{timestamp}/model_summary.json"
            summary_blob = self._storage_client.blob(summary_path)
            summary_blob.upload_from_string(
                json.dumps(summary_data, indent=2, default=str)
            )
            
            upload_stats['summary_remote_path'] = summary_path
            
            log_event(
                logger,
                "model_artifacts_uploaded",
                level="info",
                uploaded_files=len(upload_stats['uploaded_files']),
                total_size_mb=upload_stats['total_size_mb'],
                summary_path=summary_path
            )
            
            return upload_stats
            
        except Exception as e:
            log_event(
                logger,
                "artifact_upload_failed",
                level="error",
                error=str(e),
                local_paths=local_paths
            )
            raise
    
    def list_existing_models(self, max_age_days: Optional[int] = None) -> List[Dict[str, Any]]:
        """List existing model artifacts in Firebase Storage.
        
        Args:
            max_age_days: If specified, only return models newer than this age
            
        Returns:
            List of model metadata dictionaries
        """
        models = []
        
        try:
            cutoff_time = None
            if max_age_days is not None:
                cutoff_time = datetime.now() - timedelta(days=max_age_days)
            
            # List all files in the model output directory
            prefix = f"{self.config.model_output_path}/"
            blobs = self._storage_client.list_blobs(prefix=prefix)
            
            for blob in blobs:
                if not blob.name.endswith(('.pkl', '.skops', '.json')):
                    continue
                
                if cutoff_time and blob.updated < cutoff_time:
                    continue
                
                # Parse model info from path
                path_parts = blob.name.split('/')
                if len(path_parts) < 3:
                    continue
                
                model_timestamp = path_parts[-2]
                filename = path_parts[-1]
                model_prefix = path_parts[-3]
                
                models.append({
                    'name': f"{model_prefix}_{filename}",
                    'timestamp': model_timestamp,
                    'remote_path': blob.name,
                    'size_mb': blob.size / (1024 * 1024),
                    'last_modified': blob.updated.isoformat(),
                    'content_type': blob.content_type
                })
            
            # Sort by timestamp (newest first)
            models.sort(key=lambda x: x['timestamp'], reverse=True)
            
            log_event(
                logger,
                "existing_models_listed",
                level="info",
                model_count=len(models),
                max_age_days=max_age_days
            )
            
            return models
            
        except Exception as e:
            log_event(
                logger,
                "failed_to_list_existing_models",
                level="error",
                error=str(e)
            )
            raise
    
    def cleanup_old_models(self, max_age_days: int = 30) -> Dict[str, int]:
        """Delete old model artifacts from Firebase Storage.
        
        Args:
            max_age_days: Maximum age in days for models to keep
            
        Returns:
            Dictionary with counts of deleted and remaining models
        """
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        deleted_count = 0
        remaining_count = 0
        
        try:
            prefix = f"{self.config.model_output_path}/"
            blobs = self._storage_client.list_blobs(prefix=prefix)
            
            for blob in blobs:
                if blob.updated < cutoff_time:
                    blob.delete()
                    deleted_count += 1
                    log_event(
                        logger,
                        "old_model_deleted",
                        level="info",
                        model_path=blob.name,
                        last_modified=blob.updated.isoformat(),
                        age_days=(datetime.now() - blob.updated).days
                    )
                else:
                    remaining_count += 1
            
            log_event(
                logger,
                "model_cleanup_completed",
                level="info",
                deleted_count=deleted_count,
                remaining_count=remaining_count,
                max_age_days=max_age_days
            )
            
            return {
                "deleted_count": deleted_count,
                "remaining_count": remaining_count
            }
            
        except Exception as e:
            log_event(
                logger,
                "model_cleanup_failed",
                level="error",
                error=str(e),
                max_age_days=max_age_days
            )
            raise
    
    def download_model(self, remote_path: str, local_path: str) -> bool:
        """Download a model artifact from Firebase Storage.
        
        Args:
            remote_path: Remote path in Firebase Storage
            local_path: Local path to save the file
            
        Returns:
            True if download was successful, False otherwise
        """
        try:
            blob = self._storage_client.blob(remote_path)
            
            # Create local directory if it doesn't exist
            local_file = Path(local_path)
            local_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Download file
            blob.download_to_filename(local_path)
            
            file_size_mb = local_file.stat().st_size / (1024 * 1024)
            
            log_event(
                logger,
                "model_downloaded",
                level="info",
                remote_path=remote_path,
                local_path=local_path,
                size_mb=file_size_mb
            )
            
            return True
            
        except Exception as e:
            log_event(
                logger,
                "model_download_failed",
                level="error",
                remote_path=remote_path,
                local_path=local_path,
                error=str(e)
            )
            return False
    
    def cleanup_training_data(self, max_age_hours: int) -> Dict[str, int]:
        """Clean up old training CSV files.
        
        Args:
            max_age_hours: Maximum age in hours for training data to keep
            
        Returns:
            Dictionary with cleanup statistics
        """
        deleted_count = 0
        remaining_count = 0
        
        try:
            prefix = f"{self.config.training_data_path}/"
            blobs = self._storage_client.list_blobs(prefix=prefix)
            
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            
            for blob in blobs:
                if not blob.name.endswith('.csv'):
                    continue
                
                if blob.updated < cutoff_time:
                    blob.delete()
                    deleted_count += 1
                    log_event(
                        logger,
                        "training_data_deleted",
                        level="info",
                        file_path=blob.name,
                        last_modified=blob.updated.isoformat(),
                        age_hours=(datetime.now() - blob.updated).total_seconds() / 3600
                    )
                else:
                    remaining_count += 1
            
            log_event(
                logger,
                "training_data_cleanup_completed",
                level="info",
                deleted_count=deleted_count,
                remaining_count=remaining_count,
                max_age_hours=max_age_hours
            )
            
            return {
                "deleted_count": deleted_count,
                "remaining_count": remaining_count
            }
            
        except Exception as e:
            log_event(
                logger,
                "training_data_cleanup_failed",
                level="error",
                error=str(e),
                max_age_hours=max_age_hours
            )
            raise
    
    def get_storage_usage(self) -> Dict[str, Any]:
        """Get storage usage statistics for training data and models.
        
        Returns:
            Dictionary containing storage usage information
        """
        usage_stats = {
            'training_data': {'file_count': 0, 'total_size_mb': 0.0},
            'models': {'file_count': 0, 'total_size_mb': 0.0}
        }
        
        try:
            # Calculate training data usage
            training_prefix = f"{self.config.training_data_path}/"
            training_blobs = self._storage_client.list_blobs(prefix=training_prefix)
            
            for blob in training_blobs:
                if blob.name.endswith('.csv'):
                    usage_stats['training_data']['file_count'] += 1
                    usage_stats['training_data']['total_size_mb'] += blob.size / (1024 * 1024)
            
            # Calculate model usage
            model_prefix = f"{self.config.model_output_path}/"
            model_blobs = self._storage_client.list_blobs(prefix=model_prefix)
            
            for blob in model_blobs:
                usage_stats['models']['file_count'] += 1
                usage_stats['models']['total_size_mb'] += blob.size / (1024 * 1024)
            
            usage_stats['total_size_mb'] = (
                usage_stats['training_data']['total_size_mb'] + 
                usage_stats['models']['total_size_mb']
            )
            
            log_event(
                logger,
                "storage_usage_calculated",
                level="info",
                usage_stats=usage_stats
            )
            
            return usage_stats
            
        except Exception as e:
            log_event(
                logger,
                "storage_usage_calculation_failed",
                level="error",
                error=str(e)
            )
            raise
    
    def __del__(self):
        """Clean up Firebase connections."""
        if hasattr(self, '_firebase_app') and self._firebase_app:
            try:
                firebase_admin.delete_app(self._firebase_app)
            except Exception:
                pass