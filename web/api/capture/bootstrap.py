"""Community capture singletons and the explicitly configured baseline."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "Ulti_argus" / "src"))

from argus_v.baseline import BaselineModel, load_model  # noqa: E402
from argus_v.dpi.features import FeatureVector  # noqa: E402
from argus_v.dpi.patterns import PatternEngine  # noqa: E402

pattern_engine = PatternEngine()
feature_vector = FeatureVector()

baseline_model: BaselineModel | None = None
baseline_error: str | None = None
configured_path = os.getenv("ARGUS_BASELINE_MODEL", "").strip()
if configured_path:
    try:
        baseline_model = load_model(configured_path)
    except (OSError, ValueError):
        baseline_error = "configured artifact rejected"
