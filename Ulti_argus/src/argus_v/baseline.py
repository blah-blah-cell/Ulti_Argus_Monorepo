"""Small, auditable logistic baseline for user-labelled flow observations."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

SCHEMA_VERSION = "argus.flow-baseline.v1"
ARTIFACT_TYPE = "argus.logistic-baseline"
MAX_ARTIFACT_BYTES = 1_000_000

RAW_FIELDS = (
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "duration",
    "pkt_size_mean",
    "pkt_size_std",
    "inter_arrival_mean",
    "inter_arrival_std",
    "tcp_syn_count",
    "tcp_fin_count",
    "tcp_rst_count",
)

FEATURE_NAMES = (
    "log_bytes_total",
    "log_packets_total",
    "log_duration_ms",
    "log_packet_size_mean",
    "log_packet_size_std",
    "log_inter_arrival_mean_ms",
    "log_inter_arrival_std_ms",
    "inbound_packet_ratio",
    "inbound_byte_ratio",
    "tcp_syn_ratio",
    "tcp_fin_ratio",
    "tcp_rst_ratio",
)


def _number(value: Any) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return 0.0
    return result if math.isfinite(result) else 0.0


def _positive(value: Any) -> float:
    return max(0.0, _number(value))


def _log(value: float) -> float:
    return min(math.log1p(max(0.0, value)), 20.0)


def vectorize(observation: Mapping[str, Any]) -> np.ndarray:
    """Transform fields available at flow decision time into the v1 schema."""
    bytes_in = _positive(observation.get("bytes_in"))
    bytes_out = _positive(observation.get("bytes_out"))
    packets_in = _positive(observation.get("packets_in"))
    packets_out = _positive(observation.get("packets_out"))
    packet_total = packets_in + packets_out
    byte_total = bytes_in + bytes_out
    divisor_packets = max(packet_total, 1.0)
    divisor_bytes = max(byte_total, 1.0)

    values = (
        _log(byte_total),
        _log(packet_total),
        _log(_positive(observation.get("duration")) * 1_000.0),
        _log(_positive(observation.get("pkt_size_mean"))),
        _log(_positive(observation.get("pkt_size_std"))),
        _log(_positive(observation.get("inter_arrival_mean")) * 1_000.0),
        _log(_positive(observation.get("inter_arrival_std")) * 1_000.0),
        min(packets_in / divisor_packets, 1.0),
        min(bytes_in / divisor_bytes, 1.0),
        min(_positive(observation.get("tcp_syn_count")) / divisor_packets, 1.0),
        min(_positive(observation.get("tcp_fin_count")) / divisor_packets, 1.0),
        min(_positive(observation.get("tcp_rst_count")) / divisor_packets, 1.0),
    )
    return np.asarray(values, dtype=np.float64)


def _sigmoid(value: np.ndarray | float) -> np.ndarray | float:
    clipped = np.clip(value, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-clipped))


@dataclass(frozen=True)
class BaselineModel:
    weights: np.ndarray
    bias: float
    mean: np.ndarray
    scale: np.ndarray
    threshold: float
    model_id: str
    trained_samples: int

    def predict_score(self, observation: Mapping[str, Any]) -> float:
        normalized = (vectorize(observation) - self.mean) / self.scale
        return float(_sigmoid(float(normalized @ self.weights + self.bias)))

    def is_suspicious(self, observation: Mapping[str, Any]) -> bool:
        return self.predict_score(observation) >= self.threshold


def _finite_vector(value: Any, name: str) -> np.ndarray:
    result = np.asarray(value, dtype=np.float64)
    if result.shape != (len(FEATURE_NAMES),) or not np.isfinite(result).all():
        raise ValueError(f"{name} must contain {len(FEATURE_NAMES)} finite values")
    return result


def load_model(path: str | os.PathLike[str]) -> BaselineModel:
    artifact_path = Path(path).expanduser().resolve()
    size = artifact_path.stat().st_size
    if size <= 0 or size > MAX_ARTIFACT_BYTES:
        raise ValueError("baseline artifact has an invalid size")
    raw = artifact_path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("baseline artifact must be a JSON object")
    if payload.get("artifact_type") != ARTIFACT_TYPE:
        raise ValueError("unsupported baseline artifact type")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported baseline feature schema")
    if tuple(payload.get("feature_names", ())) != FEATURE_NAMES:
        raise ValueError("baseline feature order does not match the runtime")

    weights = _finite_vector(payload.get("weights"), "weights")
    mean = _finite_vector(payload.get("mean"), "mean")
    scale = _finite_vector(payload.get("scale"), "scale")
    if np.any(scale <= 0):
        raise ValueError("baseline scale values must be positive")
    bias = _number(payload.get("bias"))
    threshold = _number(payload.get("threshold"))
    if not 0.0 < threshold < 1.0:
        raise ValueError("baseline threshold must be between zero and one")
    trained_samples = int(payload.get("trained_samples", 0))
    if trained_samples < 4:
        raise ValueError("baseline artifact reports too few training samples")

    return BaselineModel(
        weights=weights,
        bias=bias,
        mean=mean,
        scale=scale,
        threshold=threshold,
        model_id=hashlib.sha256(raw).hexdigest()[:16],
        trained_samples=trained_samples,
    )


def _label(value: Any) -> int:
    normalized = str(value).strip().lower()
    labels = {
        "0": 0,
        "benign": 0,
        "normal": 0,
        "1": 1,
        "attack": 1,
        "malicious": 1,
        "suspicious": 1,
    }
    if normalized not in labels:
        raise ValueError(f"unsupported label {value!r}; use 0/1 or benign/malicious")
    return labels[normalized]


def read_labelled_csv(path: str | os.PathLike[str], label_column: str) -> tuple[np.ndarray, np.ndarray]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        names = set(reader.fieldnames or ())
        missing = set(RAW_FIELDS) - names
        if missing or label_column not in names:
            required = ", ".join(sorted(missing | ({label_column} - names)))
            raise ValueError(f"CSV is missing required columns: {required}")
        rows = list(reader)
    if len(rows) < 10:
        raise ValueError("at least 10 labelled flows are required")
    x = np.vstack([vectorize(row) for row in rows])
    y = np.asarray([_label(row[label_column]) for row in rows], dtype=np.float64)
    counts = np.bincount(y.astype(np.int64), minlength=2)
    if np.any(counts < 2):
        raise ValueError("both classes need at least two labelled flows")
    return x, y


def _split(y: np.ndarray, validation_fraction: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    generator = np.random.default_rng(seed)
    train: list[int] = []
    validation: list[int] = []
    for label in (0.0, 1.0):
        indices = np.flatnonzero(y == label)
        generator.shuffle(indices)
        validation_count = min(max(1, round(len(indices) * validation_fraction)), len(indices) - 1)
        validation.extend(indices[:validation_count].tolist())
        train.extend(indices[validation_count:].tolist())
    generator.shuffle(train)
    generator.shuffle(validation)
    return np.asarray(train), np.asarray(validation)


def _metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    predicted = scores >= threshold
    positive = labels == 1.0
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & ~positive))
    fn = int(np.sum(~predicted & positive))
    tn = int(np.sum(~predicted & ~positive))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        "accuracy": round((tp + tn) / max(len(labels), 1), 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(2 * precision * recall / max(precision + recall, 1e-12), 6),
    }


def train(
    x: np.ndarray,
    y: np.ndarray,
    *,
    epochs: int = 400,
    learning_rate: float = 0.05,
    l2: float = 0.001,
    threshold: float = 0.5,
    validation_fraction: float = 0.2,
    seed: int = 7,
) -> tuple[dict[str, Any], dict[str, float]]:
    if epochs < 1 or learning_rate <= 0 or l2 < 0:
        raise ValueError("training hyperparameters must be positive")
    if not 0.0 < threshold < 1.0 or not 0.0 < validation_fraction < 0.5:
        raise ValueError("threshold or validation fraction is outside its valid range")

    train_indices, validation_indices = _split(y, validation_fraction, seed)
    train_x = x[train_indices]
    train_y = y[train_indices]
    mean = train_x.mean(axis=0)
    scale = train_x.std(axis=0)
    scale[scale < 1e-8] = 1.0
    normalized = (train_x - mean) / scale

    weights = np.zeros(len(FEATURE_NAMES), dtype=np.float64)
    bias = 0.0
    counts = np.bincount(train_y.astype(np.int64), minlength=2)
    class_weights = len(train_y) / (2.0 * np.maximum(counts, 1))
    sample_weights = class_weights[train_y.astype(np.int64)]

    for _ in range(epochs):
        scores = normalized @ weights + bias
        error = (_sigmoid(scores) - train_y) * sample_weights
        weights -= learning_rate * ((normalized.T @ error) / len(train_y) + l2 * weights)
        bias -= learning_rate * float(np.mean(error))

    validation_scores = _sigmoid(((x[validation_indices] - mean) / scale) @ weights + bias)
    metrics = _metrics(y[validation_indices], np.asarray(validation_scores), threshold)
    artifact = {
        "artifact_type": ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "feature_names": list(FEATURE_NAMES),
        "weights": weights.tolist(),
        "bias": bias,
        "mean": mean.tolist(),
        "scale": scale.tolist(),
        "threshold": threshold,
        "trained_samples": int(len(train_indices)),
        "validation_samples": int(len(validation_indices)),
        "training": {
            "epochs": epochs,
            "learning_rate": learning_rate,
            "l2": l2,
            "seed": seed,
            "validation_metrics": metrics,
        },
    }
    return artifact, metrics


def save_artifact(payload: Mapping[str, Any], path: str | os.PathLike[str], *, force: bool) -> None:
    output = Path(path).expanduser().resolve()
    if output.exists() and not force:
        raise FileExistsError(f"refusing to overwrite {output}; pass --force to replace it")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, output)


def prepare_csv(records: Iterable[Mapping[str, Any]], output: str | os.PathLike[str]) -> int:
    rows = list(records)
    output_path = Path(output).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*RAW_FIELDS, "label"])
        writer.writeheader()
        for row in rows:
            writer.writerow({**{field: row.get(field, 0) for field in RAW_FIELDS}, "label": ""})
    return len(rows)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="convert API flow JSON to a CSV for labelling")
    prepare.add_argument("--input", required=True, help="JSON array returned by /api/detect/flows")
    prepare.add_argument("--output", required=True)

    trainer = subparsers.add_parser("train", help="train and validate the logistic baseline")
    trainer.add_argument("--csv", required=True)
    trainer.add_argument("--output", required=True)
    trainer.add_argument("--label-column", default="label")
    trainer.add_argument("--epochs", type=int, default=400)
    trainer.add_argument("--learning-rate", type=float, default=0.05)
    trainer.add_argument("--l2", type=float, default=0.001)
    trainer.add_argument("--threshold", type=float, default=0.5)
    trainer.add_argument("--validation-fraction", type=float, default=0.2)
    trainer.add_argument("--seed", type=int, default=7)
    trainer.add_argument("--force", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "prepare":
        records = json.loads(Path(args.input).read_text(encoding="utf-8"))
        if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
            raise ValueError("input must be a JSON array of flow objects")
        count = prepare_csv(records, args.output)
        print(json.dumps({"prepared_rows": count, "output": str(Path(args.output).resolve())}))
        return 0

    x, y = read_labelled_csv(args.csv, args.label_column)
    artifact, metrics = train(
        x,
        y,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        l2=args.l2,
        threshold=args.threshold,
        validation_fraction=args.validation_fraction,
        seed=args.seed,
    )
    save_artifact(artifact, args.output, force=args.force)
    print(json.dumps({"validation": metrics, "output": str(Path(args.output).resolve())}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
