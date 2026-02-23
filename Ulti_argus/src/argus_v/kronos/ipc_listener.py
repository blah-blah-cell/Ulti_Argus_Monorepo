"""Kronos IPC Listener — Receives flows from DeepPacketSentinel (Rust).

DeepPacketSentinel captures packets at kernel level via eBPF/XDP and
extracts flow metadata + payload bytes using a zero-copy ring buffer.
It communicates with Kronos over a Unix domain socket, sending one
JSON-lines frame per flow.

Expected frame format (UTF-8 JSON, newline-terminated):
{
  "src_ip":   "192.168.1.5",
  "dst_ip":   "8.8.8.8",
  "src_port": 52341,
  "dst_port": 53,
  "protocol": "UDP",
  "bytes_in": 64,
  "bytes_out": 0,
  "duration": 0.002,
  "payload":  "<base64-encoded bytes or null>"
}

The listener runs in a background thread, parses incoming frames, and
puts them onto a Python queue for the Kronos routing loop to consume.

NOTE: The Unix socket path must match the address configured in DPS's
Rust sender (see DeepPacketSentinel/src/ipc/mod.rs).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import queue
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..oracle_core.logging import log_event

logger = logging.getLogger(__name__)

_DEFAULT_SOCKET_PATH = "/var/run/argus_v/dps_kronos.sock"
_MAX_FRAME_BYTES = 8192       # Max JSON frame size from DPS
_QUEUE_MAX = 10_000           # Drop frames if consumer is too slow


@dataclass
class FlowFrame:
    """Parsed flow record received from DeepPacketSentinel."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_in: int
    bytes_out: int
    duration: float
    payload: Optional[bytes]  # None if DPS sent null or couldn't extract

    @classmethod
    def from_dict(cls, d: dict) -> "FlowFrame":
        raw_payload = d.get("payload")
        if raw_payload:
            try:
                payload_bytes = base64.b64decode(raw_payload)
            except Exception:
                payload_bytes = None
        else:
            payload_bytes = None

        return cls(
            src_ip=str(d.get("src_ip", "")),
            dst_ip=str(d.get("dst_ip", "")),
            src_port=int(d.get("src_port", 0)),
            dst_port=int(d.get("dst_port", 0)),
            protocol=str(d.get("protocol", "OTHER")).upper(),
            bytes_in=int(d.get("bytes_in", 0)),
            bytes_out=int(d.get("bytes_out", 0)),
            duration=float(d.get("duration", 0.0)),
            payload=payload_bytes,
        )


class IPCListener:
    """Unix socket server that receives flow frames from DPS (Rust).

    Args:
        socket_path: Path to the Unix domain socket file.
        queue_max:   Maximum frames to buffer before dropping oldest.
        secret_key:  Secret key for HMAC-SHA256 validation of frames.
    """

    def __init__(
        self,
        socket_path: str = _DEFAULT_SOCKET_PATH,
        queue_max: int = _QUEUE_MAX,
        secret_key: Optional[str] = None,
    ):
        self.socket_path = socket_path
        self._queue: queue.Queue[FlowFrame] = queue.Queue(maxsize=queue_max)
        self.secret_key = secret_key.encode("utf-8") if secret_key else None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._dropped = 0
        self._received = 0

        if not self.secret_key:
            log_event(
                logger,
                "ipc_listener_no_secret_key",
                level="warning",
                message="No secret key provided. All frames will be rejected.",
            )

        log_event(
            logger,
            "ipc_listener_initialized",
            level="info",
            socket_path=socket_path,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background listener thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._listen_loop,
            name="Kronos-IPC-Listener",
            daemon=True,
        )
        self._thread.start()
        log_event(logger, "ipc_listener_started", level="info")

    def stop(self) -> None:
        """Signal the listener to stop and clean up the socket file."""
        self._running = False
        # Remove socket so the accept() call unblocks
        try:
            Path(self.socket_path).unlink(missing_ok=True)
        except Exception:
            pass
        if self._thread:
            self._thread.join(timeout=5)
        log_event(
            logger,
            "ipc_listener_stopped",
            level="info",
            total_received=self._received,
            total_dropped=self._dropped,
        )

    # ------------------------------------------------------------------
    # Consumer API
    # ------------------------------------------------------------------

    def get_frame(self, timeout: float = 1.0) -> Optional[FlowFrame]:
        """Retrieve the next available FlowFrame from the queue.

        Returns None on timeout (allows callers to check stop conditions).
        """
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def qsize(self) -> int:
        return self._queue.qsize()

    def _validate_hmac(self, message: bytes, received_hmac: str) -> bool:
        """Validate HMAC-SHA256 signature of the message."""
        if not self.secret_key:
            return False

        try:
            computed_hmac = hmac.new(
                self.secret_key, message, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(computed_hmac, received_hmac)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _listen_loop(self) -> None:
        """Main socket accept loop. Handles one DPS connection at a time."""
        sock_path = Path(self.socket_path)
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        sock_path.unlink(missing_ok=True)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)
        server.settimeout(2.0)  # Allow periodic stop-checks

        log_event(
            logger,
            "ipc_listener_socket_bound",
            level="info",
            path=self.socket_path,
        )

        while self._running:
            try:
                conn, _ = server.accept()
                self._handle_connection(conn)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    log_event(
                        logger,
                        "ipc_listener_accept_error",
                        level="error",
                        error=str(e),
                    )

        server.close()

    def _handle_connection(self, conn: socket.socket) -> None:
        """Read newline-delimited JSON frames from a connected DPS client."""
        buffer = b""
        try:
            conn.settimeout(5.0)
            while self._running:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    if len(line) > _MAX_FRAME_BYTES:
                        log_event(
                            logger,
                            "ipc_frame_too_large",
                            level="warning",
                            size=len(line),
                        )
                        continue

                    # HMAC validation: expect <HMAC>:<PAYLOAD>
                    if b":" not in line:
                        log_event(logger, "ipc_frame_missing_hmac", level="warning")
                        continue

                    try:
                        hmac_part, payload_part = line.split(b":", 1)
                        hmac_str = hmac_part.decode("utf-8")

                        if not self._validate_hmac(payload_part, hmac_str):
                            log_event(
                                logger, "ipc_hmac_verification_failed", level="error"
                            )
                            continue

                        self._parse_and_enqueue(payload_part)
                    except Exception as e:
                        log_event(
                            logger,
                            "ipc_frame_processing_error",
                            level="error",
                            error=str(e),
                        )
        except Exception as e:
            if self._running:
                log_event(
                    logger,
                    "ipc_connection_error",
                    level="warning",
                    error=str(e),
                )
        finally:
            conn.close()

    def _parse_and_enqueue(self, raw: bytes) -> None:
        """Parse a JSON frame and add it to the queue."""
        try:
            data = json.loads(raw.decode("utf-8"))
            frame = FlowFrame.from_dict(data)
            self._received += 1

            try:
                self._queue.put_nowait(frame)
            except queue.Full:
                # Drop oldest frame to make room
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
                self._queue.put_nowait(frame)
                self._dropped += 1

        except Exception as e:
            log_event(
                logger,
                "ipc_frame_parse_error",
                level="debug",
                error=str(e),
            )
