#!/usr/bin/env python3
"""
mock_kronos_listener.py — Simulates the Kronos Python IPC listener.

Usage (Linux only, run as root or with appropriate sock permissions):
    python3 scripts/mock_kronos_listener.py [--socket PATH]

Reads newline-delimited JSON FlowFrame records from the Unix domain socket
published by DeepPacketSentinel's KronosSender and pretty-prints each one.

Socket protocol:
    One UTF-8 JSON object per line, \\n-terminated.
    Matches the FlowFrame struct in userspace/src/engine/kronos_sender.rs
"""

import argparse
import json
import os
import socket
import sys
import textwrap
from datetime import datetime

DEFAULT_SOCK = "/var/run/argus_v/dps_kronos.sock"

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"


def risk_colour(dst_port: int, protocol: str) -> str:
    """Heuristic colouring for demo purposes."""
    if dst_port in (6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889):
        return RED      # BitTorrent → high risk
    if dst_port == 22:
        return YELLOW   # SSH → suspicious
    if dst_port in (80, 443):
        return GREEN    # HTTP/HTTPS → benign
    return CYAN


def pretty_print(frame: dict, frame_no: int) -> None:
    ts   = datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
    port = frame.get("dst_port", "?")
    proto = frame.get("protocol", "?")
    colour = risk_colour(port, proto)

    print(f"{BOLD}[{ts}] Frame #{frame_no}{RESET}")
    print(f"  {colour}{frame.get('src_ip','?')}:{frame.get('src_port','?')}"
          f"  →  {frame.get('dst_ip','?')}:{port}  ({proto}){RESET}")
    if frame.get("payload"):
        print(f"  payload (b64, {len(frame['payload'])} chars): {frame['payload'][:40]}…")
    print(f"  bytes_in={frame.get('bytes_in',0)}")
    print()


def run(sock_path: str) -> None:
    # Ensure the socket directory exists
    sock_dir = os.path.dirname(sock_path)
    if sock_dir:
        os.makedirs(sock_dir, exist_ok=True)

    # Remove stale socket file
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)

    print(f"{BOLD}[mock-kronos] Listening on {sock_path}{RESET}")
    print("Waiting for DeepPacketSentinel to connect…\n")

    frame_no = 0

    try:
        while True:
            conn, _ = server.accept()
            print(f"{GREEN}[mock-kronos] DPS connected.{RESET}\n")
            with conn.makefile("r", encoding="utf-8") as f:
                for raw_line in f:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    frame_no += 1
                    try:
                        frame = json.loads(raw_line)
                        pretty_print(frame, frame_no)
                    except json.JSONDecodeError as exc:
                        print(f"{RED}[mock-kronos] Bad JSON (frame {frame_no}): {exc}{RESET}")
                        print(f"  raw: {textwrap.shorten(raw_line, 120)}\n")
            print(f"{YELLOW}[mock-kronos] DPS disconnected. Waiting for next connection…{RESET}\n")
    except KeyboardInterrupt:
        print(f"\n{BOLD}[mock-kronos] Shutting down.{RESET}")
    finally:
        server.close()
        try:
            os.unlink(sock_path)
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mock Kronos IPC listener for DeepPacketSentinel bridge testing."
    )
    parser.add_argument(
        "--socket",
        default=DEFAULT_SOCK,
        help=f"Unix socket path (default: {DEFAULT_SOCK})",
    )
    args = parser.parse_args()

    if sys.platform == "win32":
        print("ERROR: Unix domain sockets require Linux / WSL2.", file=sys.stderr)
        sys.exit(1)

    run(args.socket)


if __name__ == "__main__":
    main()
