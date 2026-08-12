#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

if [ -x "$REPO_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$REPO_DIR/.venv/bin/python"
elif [ -x "$REPO_DIR/venv/bin/python" ]; then
    PYTHON_BIN="$REPO_DIR/venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
else
    echo "Argus requires Python 3.11 or newer." >&2
    exit 1
fi

export PYTHONPATH="$REPO_DIR/Ulti_argus/src${PYTHONPATH:+:$PYTHONPATH}"
export ARGUS_API_HOST="${ARGUS_API_HOST:-127.0.0.1}"
export ARGUS_API_PORT="${ARGUS_API_PORT:-8000}"
export ARGUS_FRONTEND_PORT="${ARGUS_FRONTEND_PORT:-3000}"

if ! "$PYTHON_BIN" -c "import fastapi, uvicorn, scapy" >/dev/null 2>&1; then
    echo "Dependencies are missing. Follow the README installation steps first." >&2
    exit 1
fi

RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp}/argus-community-${UID}"
mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
BACKEND_LOG="$RUNTIME_DIR/backend.log"
FRONTEND_LOG="$RUNTIME_DIR/frontend.log"

cleanup() {
    local code=$?
    trap - EXIT INT TERM
    [ -z "${BACKEND_PID:-}" ] || kill "$BACKEND_PID" 2>/dev/null || true
    [ -z "${FRONTEND_PID:-}" ] || kill "$FRONTEND_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    exit "$code"
}
trap cleanup EXIT INT TERM

"$PYTHON_BIN" web/api/start.py >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
(
    cd web/public
    exec "$PYTHON_BIN" -m http.server "$ARGUS_FRONTEND_PORT" --bind 127.0.0.1
) >"$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!

sleep 2
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "Backend failed to start:" >&2
    tail -n 40 "$BACKEND_LOG" >&2
    exit 1
fi
if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    echo "Frontend failed to start:" >&2
    tail -n 40 "$FRONTEND_LOG" >&2
    exit 1
fi

echo "Argus Community is running locally."
echo "Dashboard: http://127.0.0.1:$ARGUS_FRONTEND_PORT"
echo "API:       http://127.0.0.1:$ARGUS_API_PORT"
echo "Logs:      $RUNTIME_DIR"
echo "Press Ctrl+C to stop both processes."

wait -n "$BACKEND_PID" "$FRONTEND_PID"
