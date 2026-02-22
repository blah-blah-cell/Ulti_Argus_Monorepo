"""Firebase uploader for Argus_V."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import firebase_admin
from firebase_admin import credentials, storage

logger = logging.getLogger(__name__)


class FirebaseUploader:
    """Handles file uploads to Firebase Storage."""

    def __init__(
        self,
        bucket_name: str,
        credentials_path: Optional[str] = None,
        upload_prefix: str = "retina_logs/",
    ):
        """Initialize the Firebase uploader.

        Args:
            bucket_name: Name of the Firebase Storage bucket.
            credentials_path: Path to the service account JSON file.
            upload_prefix: Prefix to add to uploaded filenames (folder structure).
        """
        self.bucket_name = bucket_name
        self.upload_prefix = upload_prefix

        self._initialize_app(credentials_path)
        self._bucket = storage.bucket(self.bucket_name)

    def _initialize_app(self, credentials_path: Optional[str]) -> None:
        """Initialize the Firebase Admin SDK app."""
        try:
            # Check if app is already initialized to avoid ValueError
            firebase_admin.get_app()
            logger.debug("Firebase app already initialized")
        except ValueError:
            # App not initialized, proceed with initialization
            if credentials_path:
                cred = credentials.Certificate(credentials_path)
                firebase_admin.initialize_app(cred)
                logger.info(f"Initialized Firebase app with credentials from {credentials_path}")
            else:
                # Use default credentials (e.g., from environment variables or Google Cloud environment)
                firebase_admin.initialize_app()
                logger.info("Initialized Firebase app with default credentials")

    def upload_file(self, file_path: Path) -> bool:
        """Upload a file to Firebase Storage.

        Args:
            file_path: Path to the local file to upload.

        Returns:
            True if upload was successful, False otherwise.
        """
        if not file_path.exists():
            logger.error(f"File not found for upload: {file_path}")
            return False

        try:
            destination_blob_name = f"{self.upload_prefix}{file_path.name}"
            blob = self._bucket.blob(destination_blob_name)

            logger.debug(f"Uploading {file_path} to {self.bucket_name}/{destination_blob_name}")
            blob.upload_from_filename(str(file_path))

            logger.info(f"Successfully uploaded {file_path.name} to Firebase Storage")
            return True

        except Exception as e:
            logger.error(f"Failed to upload {file_path}: {e}")
            return False
