import argparse
import logging
from pathlib import Path
import pytest
from argus_v.retina.cli import configure_logging_from_args

def test_configure_logging_with_file(tmp_path):
    log_file = tmp_path / "test.log"

    # Mock args
    args = argparse.Namespace(log_level="INFO", log_file=str(log_file))

    # Run
    # This will configure the root logger.
    logger = configure_logging_from_args(args)

    try:
        # Verify logger level (root logger level should be set)
        root = logging.getLogger()
        assert root.getEffectiveLevel() == logging.INFO

        # Log a message
        logger.info("Test message for file logging")

        # Verify file created
        assert log_file.exists()

        # Verify file content
        content = log_file.read_text()
        assert "Test message for file logging" in content
        # JSON formatter uses compact separators
        assert '"level":"INFO"' in content

    finally:
        # Cleanup handlers
        root = logging.getLogger()
        handlers_to_remove = []
        for h in root.handlers:
            if getattr(h, "name", "") in ["argus_file", "argus_json"]:
                h.close()
                handlers_to_remove.append(h)

        for h in handlers_to_remove:
            root.removeHandler(h)

def test_configure_logging_without_file(tmp_path):
    # Mock args
    args = argparse.Namespace(log_level="INFO", log_file=None)

    # Run
    logger = configure_logging_from_args(args)

    try:
        # Verify logger level
        root = logging.getLogger()
        assert root.getEffectiveLevel() == logging.INFO

        # Log a message
        logger.info("Test message for console logging")

        # Verify no file created
        assert not list(tmp_path.iterdir())

    finally:
        # Cleanup handlers
        root = logging.getLogger()
        handlers_to_remove = []
        for h in root.handlers:
            if getattr(h, "name", "") in ["argus_file", "argus_json"]:
                h.close()
                handlers_to_remove.append(h)

        for h in handlers_to_remove:
            root.removeHandler(h)
