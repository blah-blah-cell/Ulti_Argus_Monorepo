"""Mnemosyne inference engine — payload threat scoring.

Combines neural inference with lightweight heuristic rules to produce a
final ``[0, 1]`` threat score for an arbitrary byte payload.

Usage
-----
::

    from argus_v.mnemosyne.pytorch_inference import InferenceEngine

    engine = InferenceEngine("/opt/argus_v/models/payload_classifier.pth")
    score  = engine.analyze(raw_bytes)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import torch

from .pytorch_model import PayloadClassifier

logger = logging.getLogger(__name__)

# ── Heuristic signature sets ──────────────────────────────────────────────

_CRITICAL_PATTERNS: list[bytes] = [
    b"/etc/passwd", b"/etc/shadow", b"cmd.exe", b"/bin/sh", b"/bin/bash",
    b"${jndi:", b"UNION SELECT", b"SELECT * FROM",
    b"<script>", b"javascript:", b"onerror=",
    b"curl http", b"wget http", b"powershell",
]

_SAFE_METHODS: tuple[bytes, ...] = (b"GET /", b"POST /", b"PUT /", b"HEAD /")

_BENIGN_INDICATORS: list[bytes] = [
    b"Content-Type: text/html",
    b"Content-Type: application/json",
    b"HTTP/1.1 200",
    b"HTTP/1.1 301",
    b"HTTP/1.1 304",
]


# ── InferenceEngine ───────────────────────────────────────────────────────

class InferenceEngine:
    """Stateful inference wrapper around :class:`PayloadClassifier`.

    The engine lazily loads the model weights on first call if a checkpoint
    exists.  If no weights are found it still returns conservative heuristic
    scores.
    """

    def __init__(
        self,
        model_path: str | os.PathLike[str] | None = None,
        *,
        device: str | None = None,
        input_len: int = 1024,
    ):
        self._input_len = input_len

        if device:
            self.device = torch.device(device)
        else:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        self.model = PayloadClassifier(input_len=input_len).to(self.device)
        self.model.eval()
        self._weights_loaded = False

        if model_path is None:
            model_path = os.environ.get(
                "MNEMOSYNE_MODEL_PATH",
                "/opt/argus_v/models/payload_classifier.pth",
            )

        self.model_path = Path(model_path)
        self._try_load_weights()

    # ── Weight loading ────────────────────────────────────────────────

    def _try_load_weights(self) -> None:
        if self.model_path.exists():
            try:
                state = torch.load(
                    self.model_path,
                    map_location=self.device,
                    weights_only=True,
                )
                self.model.load_state_dict(state)
                self._weights_loaded = True
                logger.info("Mnemosyne model loaded from %s", self.model_path)
            except Exception as exc:
                logger.warning("Failed to load model weights: %s", exc)
        else:
            logger.warning(
                "Model checkpoint not found at %s — using uninitialised weights",
                self.model_path,
            )

    def reload(self, path: str | os.PathLike[str] | None = None) -> bool:
        """Hot-reload model weights (optionally from a different *path*)."""
        if path:
            self.model_path = Path(path)
        self._try_load_weights()
        return self._weights_loaded

    # ── Preprocessing ─────────────────────────────────────────────────

    def preprocess(self, payload: bytes) -> torch.Tensor:
        """Raw bytes → normalised ``[1, 1, input_len]`` float tensor."""
        data = list(payload[: self._input_len])
        pad = self._input_len - len(data)
        if pad > 0:
            data += [0] * pad
        t = torch.tensor(data, dtype=torch.float32).div_(255.0)
        return t.unsqueeze(0).unsqueeze(0).to(self.device)

    # ── Core analysis pipeline ────────────────────────────────────────

    def analyze(self, payload: bytes) -> float:
        """Return a ``[0.0, 1.0]`` threat score for *payload*.

        Pipeline stages:
        1. **Heuristic fast-path** — benign web traffic is suppressed early.
        2. **Neural inference** — softmax probability of the *attack* class.
        3. **Signature boost** — known-dangerous byte patterns raise the score.
        4. **Suppression gate** — clean HTTP that passed stage-1 is clamped.
        """
        if not payload:
            return 0.0

        # ── Stage 1: Benign fast-path ─────────────────────────────────
        is_safe_http = False
        payload_lower = payload.lower()
        if payload.startswith(_SAFE_METHODS):
            # Only suppress if no dangerous substrings at all
            if not any(p in payload_lower for p in _CRITICAL_PATTERNS):
                is_safe_http = True

        # ── Stage 2: Neural inference ─────────────────────────────────
        with torch.no_grad():
            inp = self.preprocess(payload)
            logits = self.model(inp)
            probs = torch.softmax(logits, dim=1)
            raw_score: float = probs[0, 1].item()

        # ── Stage 3: Signature boost ──────────────────────────────────
        boost = 0.0
        for pat in _CRITICAL_PATTERNS:
            if pat.lower() in payload_lower:
                boost += 0.35
        boost = min(boost, 0.6)             # cap cumulative boost

        final = raw_score + boost

        # ── Stage 4: Suppression gate ─────────────────────────────────
        if is_safe_http and final < 0.8:
            final = min(final, 0.05)

        return max(0.0, min(final, 1.0))

    @property
    def is_ready(self) -> bool:
        return self._weights_loaded


# ── Module-level convenience accessor ─────────────────────────────────────

_engine: Optional[InferenceEngine] = None


def get_engine() -> InferenceEngine:
    """Return the lazily-initialised global engine instance."""
    global _engine
    if _engine is None:
        _engine = InferenceEngine()
    return _engine


def analyze_payload(payload: bytes) -> float:
    """Convenience function used by the broader Aegis pipeline."""
    return get_engine().analyze(payload)
