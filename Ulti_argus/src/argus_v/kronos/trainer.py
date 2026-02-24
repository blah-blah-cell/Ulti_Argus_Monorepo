"""Kronos Trainer — Fits the gradient-boosted routing model.

Kronos learns from the combined verdicts of IsolationForest + CNN on past
flows.  Each training example is a feature vector (same schema as router.py)
paired with a routing label derived from what *actually* happened:

  PASS (0)     → IF flagged normal, CNN confirmed normal (or not run).
  IF_ONLY (1)  → IF was sufficient; CNN agreed or wasn't needed.
  ESCALATE (2) → CNN was needed and changed the verdict vs IF alone.

Bootstrap mode: When no labelled data exists, synthetic examples are
generated from rule-based logic so the model starts with a sensible
baseline on day 0.

Training is called by MnemosynePipeline.run_training_pipeline() as a
secondary target after the IsolationForest is trained.
"""

from __future__ import annotations

import logging
import pickle
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)

# Label encoding (must match router.py _PATH_LABELS)
_LABEL_PASS = 0
_LABEL_IF_ONLY = 1
_LABEL_ESCALATE = 2

# Minimum samples required before attempting real training
_MIN_REAL_SAMPLES = 200

# Column order for the feature matrix (must match _build_features in router.py)
FEATURE_NAMES = [
    "if_score",
    "ip_score_delta",
    "ip_seen_before",
    "ip_flow_count",
    "hour_of_day",
    "day_of_week",
    "is_night",
    "is_business_hours",
    "in_boot_window",
    "interval_raw",
    "interval_delta",
    "is_burst",
    "is_slow",
    "is_periodic",
    "protocol",
    "dst_port",
    "payload_available",
]


class KronosTrainer:
    """Trains (or retrains) the Kronos gradient-boosted routing model.

    Args:
        model_save_path: Where to pickle the trained model.
        n_estimators:    Number of GBT estimators.
        max_depth:       Tree depth (keep shallow for Pi inference speed).
        random_state:    Reproducibility seed.
    """

    def __init__(
        self,
        model_save_path: str = "/var/lib/argus_v/kronos/kronos_router.pkl",
        n_estimators: int = 100,
        max_depth: int = 4,
        random_state: int = 42,
    ):
        self.model_save_path = Path(model_save_path)
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state

        log_event(
            logger,
            "kronos_trainer_initialized",
            level="info",
            model_save_path=str(self.model_save_path),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train(
        self,
        samples: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Train the Kronos routing model.

        Args:
            samples: List of labelled training dicts, each with keys
                     matching FEATURE_NAMES plus a "label" key (0/1/2).
                     If None or too small, synthetic bootstrap data is used.

        Returns:
            Training statistics dict.
        """
        start = time.time()

        if samples and len(samples) >= _MIN_REAL_SAMPLES:
            X, y = self._samples_to_arrays(samples)
            source = "real"
        else:
            real_count = len(samples) if samples else 0
            log_event(
                logger,
                "kronos_using_bootstrap_data",
                level="info",
                real_samples=real_count,
                min_required=_MIN_REAL_SAMPLES,
            )
            X, y = self._generate_bootstrap_data(n=2000)
            source = "bootstrap"

        model = self._fit(X, y)
        stats = self._evaluate(model, X, y)
        stats["source"] = source
        stats["n_samples"] = len(y)
        stats["training_time_seconds"] = round(time.time() - start, 2)

        self._save(model)

        log_event(
            logger,
            "kronos_training_completed",
            level="info",
            **stats,
        )

        return stats

    def build_sample(
        self,
        features: Dict[str, Any],
        if_verdict: int,      # -1 = anomaly, 1 = normal (sklearn IF convention)
        cnn_verdict: Optional[float] = None,  # 0.0–1.0 or None if CNN not run
        cnn_threshold: float = 0.65,
    ) -> Dict[str, Any]:
        """Create a labelled training sample from a past inference event.

        Args:
            features:     Feature dict from KronosRouter._build_features().
            if_verdict:   IsolationForest.predict() output (-1 or 1).
            cnn_verdict:  CNN threat probability, or None if CNN wasn't used.
            cnn_threshold: CNN score above this = attack.

        Returns:
            Dict with feature values + label suitable for train().
        """
        if cnn_verdict is None:
            # CNN was not run; IF was the final arbiter
            label = _LABEL_IF_ONLY if if_verdict == 1 else _LABEL_IF_ONLY
        else:
            cnn_attack = cnn_verdict >= cnn_threshold
            if_attack = if_verdict == -1

            if not if_attack and not cnn_attack:
                label = _LABEL_PASS
            elif if_attack == cnn_attack:
                label = _LABEL_IF_ONLY  # Both agreed — IF alone would have sufficed
            else:
                label = _LABEL_ESCALATE  # CNN changed the outcome → escalation was worth it

        sample = {**features, "label": label}
        return sample

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _samples_to_arrays(
        self, samples: List[Dict]
    ) -> Tuple[np.ndarray, np.ndarray]:
        X = np.array(
            [[s.get(f, 0.0) for f in FEATURE_NAMES] for s in samples],
            dtype=np.float32,
        )
        y = np.array([s["label"] for s in samples], dtype=np.int32)
        return X, y

    def _generate_bootstrap_data(self, n: int = 2000) -> Tuple[np.ndarray, np.ndarray]:
        """Synthetic training set derived from the bootstrap routing rules.

        This gives the trained model the same decision boundary as the
        fallback rules on day 0, ensuring smooth handoff once real data
        arrives.
        """
        rng = np.random.default_rng(self.random_state)
        rows, labels = [], []

        for _ in range(n):
            if_score = rng.uniform(-1.0, 0.1)
            ip_seen = rng.integers(0, 2)
            flow_count = rng.integers(0, 500)
            ip_score_delta = rng.uniform(-0.5, 0.5)
            hour = rng.integers(0, 24)
            dow = rng.integers(0, 7)
            is_periodic = rng.integers(0, 2)
            payload_available = rng.integers(0, 2)
            protocol = rng.integers(0, 4)
            dst_port = int(rng.choice([53, 80, 443, 123, 22, 8080,
                                       rng.integers(1024, 65535)]))

            # Apply bootstrap rules to assign label
            if ip_seen and flow_count > 20 and ip_score_delta > -0.2 and if_score > -0.2:
                label = _LABEL_PASS
            elif if_score > -0.2:
                label = _LABEL_IF_ONLY
            elif if_score <= -0.7:
                label = _LABEL_ESCALATE
            elif payload_available:
                label = _LABEL_ESCALATE
            else:
                label = _LABEL_IF_ONLY

            row = [
                if_score, ip_score_delta, ip_seen, flow_count,
                hour, dow,
                int(0 <= hour < 6), int(8 <= hour < 18 and dow < 5),
                0,  # in_boot_window — rare, don't bake in
                rng.uniform(0.01, 120.0), rng.uniform(-30.0, 30.0),
                int(rng.uniform(0, 1) < 0.1),  # is_burst
                int(rng.uniform(0, 1) < 0.2),  # is_slow
                is_periodic, protocol, dst_port, payload_available,
            ]
            rows.append(row)
            labels.append(label)

        return np.array(rows, dtype=np.float32), np.array(labels, dtype=np.int32)

    def _fit(self, X: np.ndarray, y: np.ndarray):
        """Fit a HistGradientBoostingClassifier (fast, handles mixed features)."""
        try:
            from sklearn.ensemble import HistGradientBoostingClassifier
        except ImportError:
            from sklearn.ensemble import (
                GradientBoostingClassifier as HistGradientBoostingClassifier,
            )

        model = HistGradientBoostingClassifier(
            max_iter=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_state,
            early_stopping=False,
        )
        model.fit(X, y)
        return model

    def _evaluate(self, model, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Basic accuracy stats on the training set."""
        preds = model.predict(X)
        accuracy = float(np.mean(preds == y))
        counts = {int(k): int(v) for k, v in zip(*np.unique(y, return_counts=True), strict=False)}
        return {
            "train_accuracy": round(accuracy, 4),
            "label_distribution": counts,
        }

    def _save(self, model) -> None:
        """Pickle the model and feature names for KronosRouter to load."""
        self.model_save_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"model": model, "feature_names": FEATURE_NAMES}
        with open(self.model_save_path, "wb") as f:
            pickle.dump(payload, f)
        log_event(
            logger,
            "kronos_model_saved",
            level="info",
            path=str(self.model_save_path),
        )
