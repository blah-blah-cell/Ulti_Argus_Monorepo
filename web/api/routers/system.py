"""Small, truthful system and live-capture API."""

from __future__ import annotations

import os
import threading
import time
from typing import Any

import psutil
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from web.api.deps import get_api_key, limiter, sanitize_error
from web.api.live_capture import flush_tracker, get_results, get_stats, packet_callback

router = APIRouter(
    prefix="/api/system", tags=["system"], dependencies=[Depends(get_api_key)]
)

_capture_lock = threading.Lock()
_sniffer: Any | None = None
_capture_error: str | None = None
_started = time.monotonic()


def _interfaces() -> list[str]:
    try:
        from scapy.all import get_if_list

        return sorted(set(get_if_list()))
    except Exception:
        return sorted(psutil.net_if_addrs())


def _capture_active() -> bool:
    return bool(_sniffer is not None and getattr(_sniffer, "running", False))


@limiter.limit("120/minute")
@router.get("")
async def system_overview(request: Request):
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(os.path.abspath(os.sep))
    capture = get_stats()
    baseline = capture.get("baseline_model", {"status": "not_configured"})
    statuses: dict[str, int] = {}
    for result in get_results(100):
        status = str(result.get("status", "UNASSESSED"))
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "status": "healthy",
        "edition": "community",
        "analysis_mode": (
            "baseline_and_signatures"
            if baseline.get("status") == "loaded"
            else "signatures_only"
        ),
        "uptime_seconds": round(time.monotonic() - _started, 1),
        "capture_active": _capture_active(),
        "capture_error": _capture_error,
        "components": {
            "api": {"status": "healthy"},
            "capture": {"status": "running" if _capture_active() else "stopped"},
            "signatures": {"status": "active"},
            "baseline_model": baseline,
        },
        "system": {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "ram_used_mb": round(memory.used / 1024**2, 1),
            "ram_total_mb": round(memory.total / 1024**2, 1),
            "ram_percent": memory.percent,
            "disk_used_gb": round(disk.used / 1024**3, 1),
            "disk_total_gb": round(disk.total / 1024**3, 1),
            "disk_percent": disk.percent,
        },
        "capture": capture,
        "status_distribution": statuses,
    }


@limiter.limit("60/minute")
@router.get("/interfaces")
async def list_interfaces(request: Request):
    return {"interfaces": _interfaces()}


@limiter.limit("10/minute")
@router.post("/capture")
async def toggle_capture(request: Request, body: dict[str, Any]):
    global _capture_error, _sniffer
    action = str(body.get("action", "")).lower()
    if action not in {"start", "stop"}:
        return JSONResponse(status_code=400, content={"error": "action must be start or stop"})

    with _capture_lock:
        if action == "stop":
            if _sniffer is not None:
                try:
                    _sniffer.stop()
                except Exception as exc:
                    _capture_error = sanitize_error(exc)
                    return JSONResponse(status_code=500, content={"error": _capture_error})
                finally:
                    _sniffer = None
            flush_tracker()
            return {"status": "stopped"}

        if _capture_active():
            return {"status": "running"}
        interface = str(body.get("interface", "")).strip()
        available = _interfaces()
        if interface and interface not in available:
            return JSONResponse(status_code=400, content={"error": "Unknown interface"})
        try:
            from scapy.all import AsyncSniffer

            _sniffer = AsyncSniffer(
                iface=interface or None,
                prn=packet_callback,
                store=False,
            )
            _sniffer.start()
            time.sleep(0.05)
            if not _capture_active():
                raise RuntimeError("capture backend did not start")
            _capture_error = None
            return {"status": "running", "interface": interface or "default"}
        except Exception as exc:
            _sniffer = None
            _capture_error = sanitize_error(exc)
            return JSONResponse(status_code=503, content={"error": _capture_error})


@limiter.limit("120/minute")
@router.get("/services")
async def system_services(request: Request):
    return {
        "capture": "available" if _interfaces() else "unavailable",
        "pattern_engine": "active",
        "baseline_model": get_stats().get(
            "baseline_model", {"status": "not_configured"}
        ),
        "automated_enforcement": "not_included",
    }
