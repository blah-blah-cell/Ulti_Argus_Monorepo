from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    path: str
    message: str


class ValidationError(ValueError):
    def __init__(self, issues: Iterable[ValidationIssue]):
        self.issues = tuple(issues)
        msg = "; ".join(f"{i.path}: {i.message}" for i in self.issues) or "validation failed"
        super().__init__(msg)


def as_mapping(value: Any, *, path: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    raise ValidationError([ValidationIssue(path, "expected a mapping/object")])


def as_list(value: Any, *, path: str) -> list[Any]:
    if isinstance(value, list):
        return value
    raise ValidationError([ValidationIssue(path, "expected a list")])


def as_bool(value: Any, *, path: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValidationError([ValidationIssue(path, "expected a boolean")])


def as_int(value: Any, *, path: str) -> int:
    if isinstance(value, bool):
        raise ValidationError([ValidationIssue(path, "expected an integer")])
    if isinstance(value, int):
        return value
    raise ValidationError([ValidationIssue(path, "expected an integer")])


def as_float(value: Any, *, path: str) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    raise ValidationError([ValidationIssue(path, "expected a number")])


def as_str(value: Any, *, path: str) -> str:
    if isinstance(value, str):
        return value
    raise ValidationError([ValidationIssue(path, "expected a string")])


def require_non_empty_str(value: Any, *, path: str) -> str:
    s = as_str(value, path=path)
    if not s.strip():
        raise ValidationError([ValidationIssue(path, "must be a non-empty string")])
    return s


def require_positive_int(value: Any, *, path: str) -> int:
    i = as_int(value, path=path)
    if i <= 0:
        raise ValidationError([ValidationIssue(path, "must be > 0")])
    return i


def require_range_float(value: Any, min_val: float, max_val: float, *, path: str) -> float:
    f = as_float(value, path=path)
    if not (min_val <= f <= max_val):
        raise ValidationError([ValidationIssue(path, f"must be between {min_val} and {max_val}")])
    return f


def require_non_negative_int(value: Any, *, path: str) -> int:
    i = as_int(value, path=path)
    if i < 0:
        raise ValidationError([ValidationIssue(path, "must be >= 0")])
    return i


def get_optional(mapping: Mapping[str, Any], key: str, default: Any = None) -> Any:
    return mapping.get(key, default)


def get_required(mapping: Mapping[str, Any], key: str, *, path: str) -> Any:
    if key not in mapping:
        raise ValidationError([ValidationIssue(path, f"missing required key '{key}'")])
    return mapping[key]
