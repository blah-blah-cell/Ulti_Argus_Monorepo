import os
import pytest
from unittest.mock import MagicMock, patch
from argus_v.aegis.blacklist_manager import BlacklistManager
from argus_v.aegis.config import EnforcementConfig, ValidationError
from argus_v.oracle_core.anonymize import HashAnonymizer

class TestBlacklistSecurity:
    """Security tests for BlacklistManager."""

    def test_missing_salt_raises_error(self):
        """Test that missing salt in config raises ValueError when initializing BlacklistManager."""
        config = MagicMock(spec=EnforcementConfig)
        config.blacklist_db_path = "/tmp/test.db"
        config.blacklist_json_path = "/tmp/test.json"

        # Simulate config where anonymization_salt attribute is missing or None
        # Since MagicMock will create a Mock object for any attribute access by default,
        # we need to explicitly set it to None or make it raise AttributeError if accessed via getattr

        # Approach 1: Set it to None
        config.anonymization_salt = None

        with pytest.raises(ValueError, match="Anonymization salt must be configured"):
            BlacklistManager(config)

    def test_configured_salt_is_used(self):
        """Test that the configured salt is used by BlacklistManager."""
        config = MagicMock(spec=EnforcementConfig)
        config.blacklist_db_path = "/tmp/test.db"
        config.blacklist_json_path = "/tmp/test.json"
        config.anonymization_salt = "secure-test-salt"
        config.firebase_sync_enabled = False

        # Mock ensure_directories and initialize_database to avoid filesystem ops
        with patch.object(BlacklistManager, '_ensure_directories'), \
             patch.object(BlacklistManager, '_initialize_database'):

            manager = BlacklistManager(config)

            # Verify the anonymizer uses the configured salt
            assert manager.anonymizer._salt == "secure-test-salt"

            # Verify it's not using the old hardcoded salt
            assert manager.anonymizer._salt != "aegis-blacklist"

    def test_enforcement_config_validation(self):
        """Test that EnforcementConfig validation requires salt."""
        data = {
            "dry_run_duration_days": 7,
            "blacklist_db_path": "/tmp/db",
            "blacklist_json_path": "/tmp/json",
            "feedback_dir": "/tmp/feedback",
            "retrain_flag_file": "/tmp/retrain"
        }

        # Should fail validation without salt
        with pytest.raises(ValidationError) as exc:
            EnforcementConfig.from_mapping(data, path="test")

        assert "anonymization_salt" in str(exc.value)

        # Should pass with salt in config
        data_with_salt = data.copy()
        data_with_salt["anonymization_salt"] = "config-salt"
        config = EnforcementConfig.from_mapping(data_with_salt, path="test")
        assert config.anonymization_salt == "config-salt"

        # Should pass with salt in environment variable
        with patch.dict(os.environ, {"ARGUS_ANONYMIZATION_SALT": "env-salt"}):
            config = EnforcementConfig.from_mapping(data, path="test")
            assert config.anonymization_salt == "env-salt"
