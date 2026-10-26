from __future__ import annotations

import json

import numpy as np
import pytest
from web.api.capture import bootstrap
from web.api.capture.analyzer import analyze_flow

from argus_v.baseline import (
    FEATURE_NAMES,
    BaselineModel,
    load_model,
    prepare_csv,
    save_artifact,
    train,
    vectorize,
)


def _observation(index: int, *, attack: bool) -> dict[str, float]:
    factor = 20 if attack else 1
    return {
        "bytes_in": 400 * factor + index,
        "bytes_out": 120 * factor,
        "packets_in": 8 * factor,
        "packets_out": 3 * factor,
        "duration": 0.2 + index / 100,
        "pkt_size_mean": 64 * factor,
        "pkt_size_std": 5 * factor,
        "inter_arrival_mean": 0.02 / factor,
        "inter_arrival_std": 0.004 / factor,
        "tcp_syn_count": (8 if attack else 1),
        "tcp_fin_count": 1,
        "tcp_rst_count": (5 if attack else 0),
    }


def test_vectorize_is_finite_and_schema_sized() -> None:
    vector = vectorize({"bytes_in": "120", "duration": float("nan")})
    assert vector.shape == (len(FEATURE_NAMES),)
    assert np.isfinite(vector).all()


def test_train_save_and_load_json_artifact(tmp_path) -> None:
    observations = [
        *[_observation(index, attack=False) for index in range(8)],
        *[_observation(index, attack=True) for index in range(8)],
    ]
    x = np.vstack([vectorize(row) for row in observations])
    y = np.asarray([0] * 8 + [1] * 8, dtype=np.float64)

    artifact, metrics = train(x, y, epochs=100, seed=11)
    output = tmp_path / "baseline.argus-baseline.json"
    save_artifact(artifact, output, force=False)
    model = load_model(output)

    assert set(metrics) == {"accuracy", "precision", "recall", "f1"}
    assert 0.0 <= model.predict_score(observations[0]) <= 1.0
    assert model.trained_samples > 0
    assert len(model.model_id) == 16


def test_loader_rejects_wrong_schema(tmp_path) -> None:
    output = tmp_path / "bad.argus-baseline.json"
    output.write_text(json.dumps({"artifact_type": "other"}), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact type"):
        load_model(output)


def test_prepare_csv_exports_only_baseline_fields(tmp_path) -> None:
    output = tmp_path / "flows.csv"
    assert prepare_csv([_observation(1, attack=False)], output) == 1
    text = output.read_text(encoding="utf-8")
    assert "bytes_in" in text
    assert "label" in text
    assert "src_ip" not in text


def test_capture_analyzer_applies_only_an_explicit_model(monkeypatch) -> None:
    model = BaselineModel(
        weights=np.zeros(len(FEATURE_NAMES)),
        bias=8.0,
        mean=np.zeros(len(FEATURE_NAMES)),
        scale=np.ones(len(FEATURE_NAMES)),
        threshold=0.5,
        model_id="0123456789abcdef",
        trained_samples=20,
    )
    monkeypatch.setattr(bootstrap, "baseline_model", model)

    result = analyze_flow(
        {
            "flow_id": "baseline-contract",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "src_port": 40000,
            "dst_port": 443,
            "protocol": "TCP",
            "packets_in": 1,
            "packets_out": 0,
            "bytes_in": 60,
            "bytes_out": 0,
            "duration": 0.1,
            "payloads": [],
        }
    )

    assert result["status"] == "SUSPICIOUS"
    assert result["baseline_score"] > result["decision_provenance"]["threshold"]
    assert result["decision_provenance"]["model_id"] == model.model_id
