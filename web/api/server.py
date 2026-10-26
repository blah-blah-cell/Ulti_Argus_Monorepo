"""Argus Community API.

The public runtime exposes local capture, flow observability, signatures, an
optional user-trained logistic baseline, and health endpoints.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

ROOT_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT_DIR / "Ulti_argus" / "src"))

dotenv_path = ROOT_DIR / ".env"
if dotenv_path.is_file():
    for line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip()

from web.api.deps import ALLOWED_ORIGINS, MAX_REQUEST_BODY_BYTES, limiter

app = FastAPI(
    title="Argus Community API",
    description=(
        "Local network observability and pluggable detection APIs. "
        "No trained weights, training data, or automated enforcement are bundled."
    ),
    version="2.1.0-community",
    docs_url="/docs",
    redoc_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(status_code=413, content={"error": "Payload too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "Invalid Content-Length"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://fastapi.tiangolo.com"
    )
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    max_age=600,
)

from web.api.routers.auth import router as auth_router
from web.api.routers.detect import router as detect_router
from web.api.routers.signatures import router as signatures_router
from web.api.routers.system import router as system_router

app.include_router(system_router)
app.include_router(auth_router)
app.include_router(detect_router)
app.include_router(signatures_router)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    return """
    <html><body style="background:#111827;color:#f8fafc;font-family:system-ui;padding:2rem">
      <h1>Argus Community API</h1>
      <p>Local observability with signatures and an optional user-trained baseline.</p>
      <p><a href="/docs" style="color:#38bdf8">Open API documentation</a></p>
    </body></html>
    """


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("ARGUS_API_HOST", "127.0.0.1"),
        port=int(os.getenv("ARGUS_API_PORT", "8000")),
    )
