"""Read-only access to the bundled deterministic signature engine."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from web.api.deps import get_api_key, limiter
from web.api.live_capture import feature_vector, get_pattern_matches, pattern_engine

router = APIRouter(
    prefix="/api/signatures",
    tags=["signatures"],
    dependencies=[Depends(get_api_key)],
)


@limiter.limit("120/minute")
@router.get("/patterns")
async def signatures_patterns(request: Request, matches: bool = False, limit: int = 50):
    if matches:
        return get_pattern_matches(max(1, min(limit, 500)))
    return {
        "stats": pattern_engine.get_stats(),
        "feature_schema": {
            "size": feature_vector.vector_size,
            "names": feature_vector.get_feature_names(),
        },
        "patterns": [
            {
                "name": item.name,
                "description": item.description,
                "severity": item.severity,
                "enabled": item.enabled,
            }
            for item in pattern_engine.patterns
        ],
    }
