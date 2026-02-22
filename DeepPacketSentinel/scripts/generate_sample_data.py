#!/usr/bin/env python3
"""
generate_sample_data.py — Generates synthetic FlowFrame training data.

Usage:
    python3 scripts/generate_sample_data.py [--count N] [--out PATH] [--seed S]

Output:
    Newline-delimited JSON (NDJSON) file where each line is one FlowFrame record.
    Schema matches FlowFrame in userspace/src/engine/kronos_sender.rs, with an
    extra top-level "label" field for supervised learning:

        label: "benign" | "bittorrent" | "ssh_bruteforce" | "malware_c2"

Run `python3 scripts/generate_sample_data.py --help` for options.
"""

import argparse
import base64
import json
import os
import random
import struct
import sys
from typing import Dict, Any


# ---------------------------------------------------------------------------
# FlowFrame schema (mirrors kronos_sender.rs FlowFrame)
# ---------------------------------------------------------------------------

def rand_ipv4(rng: random.Random) -> str:
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def rand_port(rng: random.Random, low: int = 1024, high: int = 65535) -> int:
    return rng.randint(low, high)


def make_payload(rng: random.Random, size: int, pattern: bytes = b"") -> str | None:
    """Return base64-encoded payload of `size` bytes, or None if size == 0."""
    if size == 0:
        return None
    data = bytearray(size)
    if pattern:
        data[: len(pattern)] = pattern[: size]
    for i in range(len(pattern), size):
        data[i] = rng.randint(0, 255)
    return base64.b64encode(bytes(data)).decode()


# ---------------------------------------------------------------------------
# Traffic generators per class
# ---------------------------------------------------------------------------

def gen_http(rng: random.Random) -> Dict[str, Any]:
    """HTTP GET — benign web browsing."""
    payload_bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    trimmed = payload_bytes[:32]
    return {
        "src_ip":   rand_ipv4(rng),
        "dst_ip":   rand_ipv4(rng),
        "src_port": rand_port(rng),
        "dst_port": 80,
        "protocol": "TCP",
        "bytes_in": len(trimmed),
        "bytes_out": rng.randint(200, 50000),
        "duration": round(rng.uniform(0.01, 2.0), 3),
        "payload":  make_payload(rng, len(trimmed), trimmed),
        "label":    "benign",
    }


def gen_https(rng: random.Random) -> Dict[str, Any]:
    """TLS ClientHello — benign HTTPS."""
    # TLS 1.2 ClientHello magic: 0x16 0x03 0x03
    tls_magic = bytes([0x16, 0x03, 0x03]) + bytes(rng.randint(0, 255) for _ in range(29))
    return {
        "src_ip":   rand_ipv4(rng),
        "dst_ip":   rand_ipv4(rng),
        "src_port": rand_port(rng),
        "dst_port": 443,
        "protocol": "TCP",
        "bytes_in": 32,
        "bytes_out": rng.randint(1000, 100000),
        "duration": round(rng.uniform(0.05, 5.0), 3),
        "payload":  make_payload(rng, 32, tls_magic),
        "label":    "benign",
    }


def gen_dns(rng: random.Random) -> Dict[str, Any]:
    """UDP DNS query — benign."""
    return {
        "src_ip":   rand_ipv4(rng),
        "dst_ip":   "8.8.8.8",
        "src_port": rand_port(rng),
        "dst_port": 53,
        "protocol": "UDP",
        "bytes_in": rng.randint(28, 60),
        "bytes_out": rng.randint(60, 512),
        "duration": round(rng.uniform(0.001, 0.05), 4),
        "payload":  None,
        "label":    "benign",
    }


def gen_bittorrent(rng: random.Random) -> Dict[str, Any]:
    """BitTorrent handshake — malicious (policy violation)."""
    # BitTorrent handshake begins with 0x13 followed by "BitTorrent protocol"
    bt_magic = b"\x13BitTorrent protocol"
    return {
        "src_ip":   rand_ipv4(rng),
        "dst_ip":   rand_ipv4(rng),
        "src_port": rng.randint(6881, 6889),
        "dst_port": rng.randint(6881, 6889),
        "protocol": "TCP",
        "bytes_in": 32,
        "bytes_out": 32,
        "duration": round(rng.uniform(0.1, 60.0), 2),
        "payload":  make_payload(rng, 32, bt_magic),
        "label":    "bittorrent",
    }


def gen_ssh_bruteforce(rng: random.Random) -> Dict[str, Any]:
    """Rapid SSH connection — brute-force pattern."""
    ssh_banner = b"SSH-2.0-OpenSSH_7.9"
    return {
        "src_ip":   rand_ipv4(rng),
        "dst_ip":   rand_ipv4(rng),
        "src_port": rand_port(rng),
        "dst_port": 22,
        "protocol": "TCP",
        "bytes_in": rng.randint(20, 40),
        "bytes_out": rng.randint(20, 40),
        # Very short duration = rapid reconnection
        "duration": round(rng.uniform(0.001, 0.3), 4),
        "payload":  make_payload(rng, 20, ssh_banner),
        "label":    "ssh_bruteforce",
    }


def gen_malware_c2(rng: random.Random) -> Dict[str, Any]:
    """Malware C2 beacon — random high port, unusual payload bytes."""
    # High-entropy random payload simulating encrypted C2
    size = rng.randint(16, 32)
    return {
        "src_ip":   rand_ipv4(rng),
        "dst_ip":   rand_ipv4(rng),
        "src_port": rand_port(rng, 1024, 65535),
        "dst_port": rng.choice([4444, 8080, 9001, 1337, 31337]),
        "protocol": rng.choice(["TCP", "UDP"]),
        "bytes_in": size,
        "bytes_out": size,
        "duration": round(rng.uniform(0.0, 0.5), 4),
        "payload":  make_payload(rng, size),
        "label":    "malware_c2",
    }


# ---------------------------------------------------------------------------
# Sampling weights
# ---------------------------------------------------------------------------

GENERATORS = [
    (gen_http,           0.30),
    (gen_https,          0.30),
    (gen_dns,            0.15),
    (gen_bittorrent,     0.10),
    (gen_ssh_bruteforce, 0.08),
    (gen_malware_c2,     0.07),
]


def generate(count: int, rng: random.Random):
    funcs   = [g[0] for g in GENERATORS]
    weights = [g[1] for g in GENERATORS]
    for _ in range(count):
        gen = rng.choices(funcs, weights=weights, k=1)[0]
        yield gen(rng)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic DeepPacketSentinel training data (NDJSON)."
    )
    parser.add_argument("--count", type=int, default=1000,
                        help="Number of records to generate (default: 1000)")
    parser.add_argument("--out",   default="data/sample_flows.ndjson",
                        help="Output NDJSON file path (default: data/sample_flows.ndjson)")
    parser.add_argument("--seed",  type=int, default=42,
                        help="Random seed for reproducibility (default: 42)")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    label_counts: Dict[str, int] = {}
    written = 0

    with open(args.out, "w", encoding="utf-8") as f:
        for record in generate(args.count, rng):
            f.write(json.dumps(record) + "\n")
            label_counts[record["label"]] = label_counts.get(record["label"], 0) + 1
            written += 1

    print(f"[generate_sample_data] Wrote {written} records -> {args.out}")
    print("[generate_sample_data] Class distribution:")
    for label, cnt in sorted(label_counts.items()):
        pct = cnt / written * 100
        print(f"  {label:<20} {cnt:>5} ({pct:.1f}%)")

    # Quick sanity check: parse every line back
    errors = 0
    with open(args.out, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"  ERROR on line {i}: {exc}", file=sys.stderr)
                errors += 1
    if errors == 0:
        print("[generate_sample_data] Sanity check PASSED — all records are valid JSON.")
    else:
        print(f"[generate_sample_data] Sanity check FAILED — {errors} bad records.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
