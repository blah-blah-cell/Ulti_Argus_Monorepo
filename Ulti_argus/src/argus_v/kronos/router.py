"""Kronos Router — Trained meta-router for dual-model offloading.

This is the heart of the Kronos bridge. It uses a trained gradient-boosted
classifier to decide, for each flow, which path gives the best outcome:

  PASS        → Skip all heavy models; clearly normal traffic.
  IF_ONLY     → Run IsolationForest; its verdict is sufficient here.
  ESCALATE    → Run IsolationForest AND CNN; uncertain/complex case.

When no trained model is available (first boot, before training data
accumulates), a rule-based bootstrap fallback is used that mimics the
expected trained behaviour.
"""

from __future__ import annotations

import logging
import pickle
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from ..oracle_core.logging import log_event
from .ip_history import IPHistoryStore
from .temporal import TemporalContext, TemporalFeatures

logger = logging.getLogger(__name__)


class RoutingPath(str, Enum):
    """Decision returned by KronosRouter for a single flow."""
    PASS = "pass"           # Clearly normal — skip IF and CNN
    IF_ONLY = "if_only"     # IF verdict is sufficient
    ESCALATE = "escalate"   # Route to CNN for deep inspection


# Numeric label mapping used during training and inference
_PATH_LABELS: Dict[int, RoutingPath] = {
    0: RoutingPath.PASS,
    1: RoutingPath.IF_ONLY,
    2: RoutingPath.ESCALATE,
}


@dataclass
class KronosDecision:
    """Full routing decision for a single flow."""
    path: RoutingPath
    confidence: float          # Model confidence for the chosen path (0–1)
    if_score: float            # Raw IF score
    src_ip: str = ""
    dst_ip: str = ""
    features: Optional[Dict] = None  # Feature dict used for the decision
    used_fallback: bool = False       # True if bootstrap rules were used

    @property
    def needs_cnn(self) -> bool:
        return self.path == RoutingPath.ESCALATE

    @property
    def needs_if(self) -> bool:
        return self.path in (RoutingPath.IF_ONLY, RoutingPath.ESCALATE)


class KronosRouter:
    """Meta-router that intelligently distributes flows between models.

    Args:
        ip_history:      IPHistoryStore for behavioral delta signals.
        temporal:        TemporalContext for time-of-day signals.
        model_path:      Path to a pickled trained GBT routing model.
        if_clear_threshold:   IF scores above this are PASS candidates.
        if_critical_threshold: IF scores below this are always ESCALATE.
    """

    def __init__(
        self,
        ip_history: IPHistoryStore,
        temporal: TemporalContext,
        model_path: Optional[str] = None,
        if_clear_threshold: float = -0.2,
        if_critical_threshold: float = -0.7,
    ):
        self.ip_history = ip_history
        self.temporal = temporal
        self.if_clear_threshold = if_clear_threshold
        self.if_critical_threshold = if_critical_threshold

        self._model = None
        self._feature_names: List[str] = []

        if model_path:
            self.load_model(model_path)

        log_event(
            logger,
            "kronos_router_initialized",
            level="info",
            model_loaded=self._model is not None,
            if_clear_threshold=if_clear_threshold,
            if_critical_threshold=if_critical_threshold,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route(
        self,
        if_score: float,
        src_ip: str = "",
        dst_ip: str = "",
        protocol: str = "OTHER",
        dst_port: int = 0,
        payload_available: bool = False,
        now: Optional[float] = None,
    ) -> KronosDecision:
        """Determine the routing path for a single flow.

        Args:
            if_score:          IsolationForest decision_function score.
            src_ip:            Source IP string.
            dst_ip:            Destination IP string.
            protocol:          Protocol string (TCP / UDP / ICMP / OTHER).
            dst_port:          Destination port number.
            payload_available: Whether raw payload bytes are available (CNN gate).
            now:               Current Unix timestamp (defaults to time.time()).

        Returns:
            KronosDecision with path, confidence, and metadata.
        """
        now = now or time.time()

        # Record this flow into IP history (happens before feature extraction)
        record = self.ip_history.record(src_ip, if_score, timestamp=now)

        # Build feature dict
        features = self._build_features(
            if_score=if_score,
            src_ip=src_ip,
            protocol=protocol,
            dst_port=dst_port,
            payload_available=payload_available,
            record=record,
            now=now,
        )

        # Route via trained model or fallback
        if self._model is not None:
            path, confidence = self._model_route(features)
            used_fallback = False
        else:
            path, confidence = self._fallback_route(if_score, payload_available, record)
            used_fallback = True

        # CNN escalation without payload is pointless — downgrade to IF_ONLY
        if path == RoutingPath.ESCALATE and not payload_available:
            path = RoutingPath.IF_ONLY
            confidence *= 0.8  # Slight confidence penalty for downgrade

        decision = KronosDecision(
            path=path,
            confidence=confidence,
            if_score=if_score,
            src_ip=src_ip,
            dst_ip=dst_ip,
            features=features,
            used_fallback=used_fallback,
        )

        log_event(
            logger,
            "kronos_decision",
            level="debug",
            path=path.value,
            confidence=round(confidence, 3),
            if_score=round(if_score, 4),
            src_ip=src_ip,
            used_fallback=used_fallback,
        )

        return decision

    def load_model(self, model_path: str) -> bool:
        """Load a pre-trained routing model from disk.

        Returns:
            True if loaded successfully.
        """
        try:
            path = Path(model_path)
            if not path.exists():
                log_event(
                    logger,
                    "kronos_model_not_found",
                    level="warning",
                    path=str(path),
                )
                return False

            with open(path, "rb") as f:
                payload = pickle.load(f)

            self._model = payload["model"]
            self._feature_names = payload.get("feature_names", [])

            log_event(
                logger,
                "kronos_model_loaded",
                level="info",
                path=str(path),
                feature_count=len(self._feature_names),
            )
            return True

        except Exception as e:
            log_event(
                logger,
                "kronos_model_load_failed",
                level="error",
                error=str(e),
            )
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_features(
        self,
        if_score: float,
        src_ip: str,
        protocol: str,
        dst_port: int,
        payload_available: bool,
        record,
        now: float,
    ) -> Dict[str, Any]:
        """Assemble the complete feature dict for one flow."""
        # Behavioral delta features
        score_delta = record.score_delta(if_score) or 0.0
        ip_seen = int(self.ip_history.is_known(src_ip))
        flow_count = record.flow_count

        # Interval features
        interval_raw = list(record.intervals)[-1] if record.intervals else 0.0
        mean_interval = record.mean_interval

        # Temporal features
        temporal_feats: TemporalFeatures = self.temporal.extract(
            interval_raw=interval_raw,
            ip_mean_interval=mean_interval,
            ip_intervals=list(record.intervals),
            now=now,
        )

        # Protocol encoding
        proto_map = {"TCP": 1, "UDP": 2, "ICMP": 3}
        proto_enc = proto_map.get(protocol.upper(), 0)

        features = {
            # IF score
            "if_score": if_score,
            # Behavioral delta
            "ip_score_delta": score_delta,
            "ip_seen_before": ip_seen,
            "ip_flow_count": min(flow_count, 1000),  # cap to bound the feature
            # Temporal
            **temporal_feats.to_dict(),
            # Flow metadata
            "protocol": proto_enc,
            "dst_port": dst_port,
            "payload_available": int(payload_available),
        }

        return features

    def _model_route(self, features: Dict[str, Any]):
        """Use the trained GBT model to decide routing path."""
        try:
            # Build feature vector in same column order as training
            if self._feature_names:
                x = np.array([[features.get(f, 0.0) for f in self._feature_names]])
            else:
                x = np.array([[v for v in features.values()]])

            label = int(self._model.predict(x)[0])
            proba = self._model.predict_proba(x)[0]
            confidence = float(np.max(proba))
            path = _PATH_LABELS.get(label, RoutingPath.IF_ONLY)
            return path, confidence

        except Exception as e:
            log_event(
                logger,
                "kronos_model_inference_failed",
                level="error",
                error=str(e),
            )
            # Graceful degrade to fallback
            return self._fallback_route(
                features.get("if_score", 0.0),
                bool(features.get("payload_available", False)),
                None,
            )

    def _fallback_route(self, if_score: float, payload_available: bool, record):
        """Bootstrap rule-based router used before the model is trained.

        Priority:
          1. Known periodic IPs with good baseline → PASS
          2. IF score above clear threshold → IF_ONLY (borderline normal)
          3. IF score below critical threshold → ESCALATE (very bad)
          4. New IP with anomaly → ESCALATE
          5. Grey zone → ESCALATE if payload available, else IF_ONLY
        """
        # Periodic known-good IP
        if record and record.flow_count > 20:
            if record.mean_score is not None and record.mean_score > self.if_clear_threshold:
                if if_score > self.if_clear_threshold:
                    return RoutingPath.PASS, 0.75

        if if_score > self.if_clear_threshold:
            return RoutingPath.IF_ONLY, 0.80

        if if_score <= self.if_critical_threshold:
            return RoutingPath.ESCALATE, 0.90

        # Grey zone
        if payload_available:
            return RoutingPath.ESCALATE, 0.65
        return RoutingPath.IF_ONLY, 0.60
