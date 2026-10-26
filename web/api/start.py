#!/usr/bin/env python3
"""Start the Argus Community API and open its local dashboard."""

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "Ulti_argus" / "src"))

import os
import secrets
import threading
import time
import webbrowser

import uvicorn

# Generate session token
session_token = secrets.token_urlsafe(32)
os.environ["ARGUS_LOCAL_TOKEN"] = session_token

from web.api.server import app

print("=" * 60)
print("Argus Community API v2.1")
print("  Mode: bounded observation and deterministic signatures")
print("=" * 60)
print("[+] Auth initialized.")
print("=" * 60)

def open_browser():
    time.sleep(1.5)
    url = f"http://127.0.0.1:3000/index.html?token={session_token}"
    print("[*] Opening authenticated local dashboard")
    webbrowser.open(url)

threading.Thread(target=open_browser, daemon=True).start()

uvicorn.run(
    app,
    host=os.getenv("ARGUS_API_HOST", "127.0.0.1"),
    port=int(os.getenv("ARGUS_API_PORT", "8000")),
)
