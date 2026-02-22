from unittest.mock import MagicMock

import numpy as np
import pandas as pd
import pytest

from src.argus_v.aegis.model_manager import ModelManager


class MockScaler:
    def __init__(self, mean, scale):
        self.mean_ = np.array(mean)
        self.scale_ = np.array(scale)

    def transform(self, X):
        return (X - self.mean_) / self.scale_

@pytest.fixture
def model_manager():
    config = MagicMock()
    config.anomaly_threshold = 0.7
    config.high_risk_threshold = 0.9
    config.model_local_path = "/tmp/model.pkl"
    config.scaler_local_path = "/tmp/scaler.pkl"

    # Feature columns for testing
    feature_columns = ["f1", "f2", "f3"]

    manager = ModelManager(config, feature_columns=feature_columns)

    # Mock scaler
    # f1: mean=10, scale=2
    # f2: mean=100, scale=10
    # f3: mean=5, scale=1

    manager._scaler = MockScaler(
        mean=[10.0, 100.0, 5.0],
        scale=[2.0, 10.0, 1.0]
    )

    return manager

def test_explain_anomaly_basic(model_manager):
    # f1: (14 - 10) / 2 = 2.0
    # f2: (90 - 100) / 10 = -1.0
    # f3: (5 - 5) / 1 = 0.0

    flow_features = pd.Series({
        "f1": 14.0,
        "f2": 90.0,
        "f3": 5.0
    })

    explanations = model_manager.explain_anomaly(flow_features, top_k=3)

    # Expected order: f1 (2.0), f2 (-1.0), f3 (0.0)
    assert len(explanations) == 3
    assert "f1 (+2.0σ)" in explanations[0]
    assert "f2 (-1.0σ)" in explanations[1]
    assert "f3 (+0.0σ)" in explanations[2]

def test_explain_anomaly_top_k(model_manager):
    flow_features = pd.Series({
        "f1": 14.0, # 2.0
        "f2": 90.0, # -1.0
        "f3": 5.0   # 0.0
    })

    explanations = model_manager.explain_anomaly(flow_features, top_k=1)

    assert len(explanations) == 1
    assert "f1 (+2.0σ)" in explanations[0]

def test_explain_anomaly_missing_scaler():
    config = MagicMock()
    config.model_local_path = "/tmp/model.pkl"
    config.scaler_local_path = "/tmp/scaler.pkl"
    manager = ModelManager(config)
    manager._scaler = None

    explanations = manager.explain_anomaly(pd.Series({"a": 1}))
    assert explanations == ["Explanation unavailable (no scaler stats)"]

def test_explain_anomaly_zero_scale(model_manager):
    # Set scale of f1 to 0
    model_manager._scaler.scale_[0] = 0.0

    flow_features = pd.Series({
        "f1": 14.0,
        "f2": 90.0,
        "f3": 5.0
    })

    explanations = model_manager.explain_anomaly(flow_features, top_k=3)

    # f1 z-score should be 0 because scale is 0
    # f2 is -1.0
    # f3 is 0.0

    # Sorting by abs z-score: f2 (-1.0) is top
    assert "f2 (-1.0σ)" in explanations[0]

    # f1 and f3 are tied at 0.0.
    remaining = explanations[1:]
    assert any("f1 (+0.0σ)" in e for e in remaining)
    assert any("f3 (+0.0σ)" in e for e in remaining)
