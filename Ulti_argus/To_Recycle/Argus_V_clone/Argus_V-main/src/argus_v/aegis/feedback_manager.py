"""Feedback manager for Aegis shield active learning.

This module provides functionality to handle user feedback on false positives,
store trusted IPs, and trigger model retraining.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)

class FeedbackManager:
    """Manages user feedback and retraining triggers for Active Learning."""

    def __init__(self, config):
        """Initialize feedback manager.

        Args:
            config: Aegis configuration object
        """
        self.config = config
        self.feedback_dir = Path(config.enforcement.feedback_dir)
        self.trusted_ips_file = self.feedback_dir / "trusted_ips.json"
        self.retrain_flag_file = Path(config.enforcement.retrain_flag_file)

        # Cache for trusted IPs to avoid O(N) disk I/O on every prediction
        self._trusted_ips_cache = None

        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        self.feedback_dir.mkdir(parents=True, exist_ok=True)
        self.retrain_flag_file.parent.mkdir(parents=True, exist_ok=True)

        if not self.trusted_ips_file.exists():
            with open(self.trusted_ips_file, 'w') as f:
                json.dump([], f)

    def report_false_positive(self, ip_address: str, reason: str = "User reported false positive") -> bool:
        """Report an IP as a false positive (trusted).

        Args:
            ip_address: The IP address to trust.
            reason: Reason for trusting.

        Returns:
            True if successful, False otherwise.
        """
        try:
            # Load existing trusted IPs (uses cache if available)
            trusted_ips = self._load_trusted_ips()

            # Check if already trusted
            if any(entry['ip'] == ip_address for entry in trusted_ips):
                log_event(logger, "ip_already_trusted", ip_address=ip_address)
                return True

            # Add new entry
            entry = {
                'ip': ip_address,
                'reason': reason,
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            }
            trusted_ips.append(entry)

            # Save back to file
            with open(self.trusted_ips_file, 'w') as f:
                json.dump(trusted_ips, f, indent=2)

            # Update cache
            self._trusted_ips_cache = trusted_ips

            log_event(logger, "false_positive_reported", ip_address=ip_address)
            return True

        except Exception as e:
            log_event(logger, "report_false_positive_failed", error=str(e))
            return False

    def trigger_retrain(self) -> bool:
        """Trigger an incremental retrain of the model.

        Returns:
            True if trigger set successfully.
        """
        try:
            # Create flag file
            self.retrain_flag_file.touch()
            log_event(logger, "retrain_triggered", flag_file=str(self.retrain_flag_file))
            return True
        except Exception as e:
            log_event(logger, "retrain_trigger_failed", error=str(e))
            return False

    def _load_trusted_ips(self) -> List[Dict[str, Any]]:
        """Load trusted IPs from storage or cache."""
        # Return in-memory cache if available
        if self._trusted_ips_cache is not None:
            return self._trusted_ips_cache

        # Otherwise load from disk
        try:
            with open(self.trusted_ips_file, 'r') as f:
                data = json.load(f)
                self._trusted_ips_cache = data
                return data
        except Exception:
            return []

    def get_trusted_ips(self) -> List[Dict[str, Any]]:
        """Get list of trusted IPs."""
        return self._load_trusted_ips()

    def is_trusted(self, ip_address: str) -> bool:
        """Check if an IP address is trusted.

        Args:
            ip_address: IP address to check.

        Returns:
            True if IP is in trusted list, False otherwise.
        """
        # Use cached list for performance
        trusted_ips = self._load_trusted_ips()
        return any(entry['ip'] == ip_address for entry in trusted_ips)
