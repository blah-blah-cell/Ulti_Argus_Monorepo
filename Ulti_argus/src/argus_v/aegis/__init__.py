"""Argus_V Aegis Shield Runtime Service.

This module provides the Aegis runtime service for Raspberry Pi that:
- Loads latest Mnemosyne model and scaler
- Polls Retina CSV output every 5 seconds  
- Computes features and runs predictions
- Enforces blacklist decisions with dry-run support
- Provides decentralized blacklist storage with Firebase sync
"""

from .blacklist_manager import BlacklistManager
from .config import AegisConfig
from .daemon import AegisDaemon
from .model_manager import ModelManager
from .prediction_engine import PredictionEngine

__all__ = [
    "AegisConfig",
    "AegisDaemon", 
    "ModelManager",
    "PredictionEngine",
    "BlacklistManager"
]