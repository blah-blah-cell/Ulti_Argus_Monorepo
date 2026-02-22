from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA_VERSION = 1

# Shared feature keys used by collectors/aggregators. Components should extend these
# keys in their own domains, but prefer reusing these where possible.
FEATURE_SCHEMA_VERSION = "schema_version"
FEATURE_OBSERVED_AT = "observed_at"
FEATURE_SOURCE = "source"
FEATURE_IP_HASH = "ip_hash"
FEATURE_TIME_BUCKET = "time_bucket"


@dataclass(frozen=True, slots=True)
class FeatureRecord:
    """A minimal, shared container for feature payloads.

    Components may add additional keys in `features` as needed.
    """

    observed_at: datetime
    source: str
    features: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            FEATURE_SCHEMA_VERSION: self.schema_version,
            FEATURE_OBSERVED_AT: self.observed_at.astimezone(timezone.utc).isoformat(),
            FEATURE_SOURCE: self.source,
            **dict(self.features),
        }


def ensure_timezone_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
