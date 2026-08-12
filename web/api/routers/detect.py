"""Read-only flow observations from the current process session."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from web.api.deps import get_api_key, limiter
from web.api.live_capture import get_flow_by_id, get_results

router = APIRouter(
    prefix="/api/detect", tags=["flows"], dependencies=[Depends(get_api_key)]
)


@limiter.limit("120/minute")
@router.get("/flows")
async def detect_flows(request: Request, limit: int = 50):
    return get_results(max(1, min(limit, 500)))


@limiter.limit("120/minute")
@router.get("/flows/{flow_id}")
async def detect_flow_detail(request: Request, flow_id: str):
    flow = get_flow_by_id(flow_id)
    if flow is None:
        return JSONResponse(status_code=404, content={"error": "Flow not found"})
    return flow


@limiter.limit("120/minute")
@router.get("/alerts")
async def detect_alerts(request: Request, limit: int = 50):
    return [
        item
        for item in get_results(max(1, min(limit * 4, 500)))
        if item.get("status") == "SUSPICIOUS"
    ][:limit]
