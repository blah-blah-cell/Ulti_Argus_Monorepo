"""Firebase data loader for Mnemosyne trainer pipeline.

This module provides functionality to load aggregated CSV flows from Firebase
Storage and Realtime Database for ML training.
"""

from __future__ import annotations

import logging
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Generator, List, Optional

import pandas as pd

try:
    import firebase_admin
    from firebase_admin import credentials, storage
    from google.cloud import storage as gcs  # noqa: F401
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)


class FirebaseDataLoader:
    """Loads CSV flow data from Firebase Storage for training."""
    
    def __init__(self, config):
        """Initialize Firebase client with service account credentials."""
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
                "firebase_initialized",
                level="info",
                project_id=self.config.project_id,
                storage_bucket=self.config.storage_bucket
            )
            
        except Exception as e:
            log_event(
                logger,
                "firebase_initialization_failed",
                level="error",
                error=str(e),
                service_account_path=self.config.service_account_path
            )
            raise
    
    def list_training_csvs(self, max_age_hours: Optional[int] = None) -> List[str]:
        """List available training CSV files from Firebase Storage.
        
        Args:
            max_age_hours: If specified, only return files newer than this age.
            
        Returns:
            List of file paths in the training data directory.
        """
        try:
            files = []
            prefix = f"{self.config.training_data_path}/"
            
            # List all files in the training data directory
            blobs = self._storage_client.list_blobs(prefix=prefix)
            
            cutoff_time = None
            if max_age_hours is not None:
                cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            
            for blob in blobs:
                if not blob.name.endswith('.csv'):
                    continue
                    
                if cutoff_time and blob.updated < cutoff_time:
                    continue
                    
                files.append(blob.name)
            
            log_event(
                logger,
                "training_files_listed",
                level="info",
                files_count=len(files),
                max_age_hours=max_age_hours,
                prefix=prefix
            )
            
            return sorted(files)
            
        except Exception as e:
            log_event(
                logger,
                "failed_to_list_training_files",
                level="error",
                error=str(e)
            )
            raise
    
    def load_csv_flows(self, file_paths: List[str]) -> Generator[pd.DataFrame, None, None]:
        """Load CSV flow data from Firebase Storage.
        
        Args:
            file_paths: List of file paths in Firebase Storage
            
        Yields:
            DataFrames containing flow data from each CSV file
        """
        for file_path in file_paths:
            # Use a secure temporary directory for each file to prevent TOCTOU/symlink attacks
            with tempfile.TemporaryDirectory(prefix="argus_mnemosyne_") as temp_dir:
                try:
                    # Download file to temporary location
                    blob = self._storage_client.blob(file_path)
                    temp_path = Path(temp_dir) / Path(file_path).name

                    blob.download_to_filename(str(temp_path))

                    # Load CSV data
                    df = pd.read_csv(temp_path)

                    # Validate expected columns
                    expected_columns = [
                        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                        'protocol', 'bytes_in', 'bytes_out', 'packets_in', 'packets_out',
                        'duration'
                    ]

                    missing_columns = [col for col in expected_columns if col not in df.columns]
                    if missing_columns:
                        log_event(
                            logger,
                            "missing_columns_in_csv",
                            level="warning",
                            file_path=file_path,
                            missing_columns=missing_columns
                        )
                        continue

                    # Convert timestamp column
                    df['timestamp'] = pd.to_datetime(df['timestamp'])

                    # Basic data validation
                    df = df.dropna()
                    df = df[(df['bytes_in'] >= 0) & (df['bytes_out'] >= 0)]

                    log_event(
                        logger,
                        "csv_loaded_successfully",
                        level="info",
                        file_path=file_path,
                        rows=len(df),
                        columns=list(df.columns)
                    )

                    yield df

                except Exception as e:
                    log_event(
                        logger,
                        "failed_to_load_csv",
                        level="error",
                        file_path=file_path,
                        error=str(e)
                    )
                    continue
    
    def combine_flows(self, file_paths: List[str]) -> pd.DataFrame:
        """Combine multiple CSV files into a single DataFrame.
        
        Args:
            file_paths: List of file paths in Firebase Storage
            
        Returns:
            Combined DataFrame with all flow data
        """
        dataframes = []
        
        for df in self.load_csv_flows(file_paths):
            dataframes.append(df)
        
        if not dataframes:
            raise ValueError("No valid flow data found in provided files")
        
        combined_df = pd.concat(dataframes, ignore_index=True)
        
        # Remove duplicates
        initial_rows = len(combined_df)
        combined_df = combined_df.drop_duplicates()
        final_rows = len(combined_df)
        
        log_event(
            logger,
            "flows_combined",
            level="info",
            file_paths=file_paths,
            initial_rows=initial_rows,
            final_rows=final_rows,
            duplicates_removed=initial_rows - final_rows
        )
        
        return combined_df
    
    def delete_old_training_data(self, max_age_hours: int) -> Dict[str, int]:
        """Delete training CSV files older than specified age.
        
        Args:
            max_age_hours: Maximum age in hours for files to keep
            
        Returns:
            Dictionary with counts of deleted and remaining files
        """
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        deleted_count = 0
        remaining_count = 0
        
        try:
            prefix = f"{self.config.training_data_path}/"
            blobs = self._storage_client.list_blobs(prefix=prefix)
            
            for blob in blobs:
                if not blob.name.endswith('.csv'):
                    continue
                
                if blob.updated < cutoff_time:
                    blob.delete()
                    deleted_count += 1
                    log_event(
                        logger,
                        "old_file_deleted",
                        level="info",
                        file_path=blob.name,
                        last_modified=blob.updated.isoformat()
                    )
                else:
                    remaining_count += 1
            
            log_event(
                logger,
                "cleanup_completed",
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
                "cleanup_failed",
                level="error",
                error=str(e),
                max_age_hours=max_age_hours
            )
            raise
    
    def __del__(self):
        """Clean up Firebase connections."""
        if hasattr(self, '_firebase_app') and self._firebase_app:
            try:
                firebase_admin.delete_app(self._firebase_app)
            except Exception:
                pass