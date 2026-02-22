# Architecture V2: The Future State

## Overview
This document outlines the proposed architectural evolution of DeepPacketSentinel to support Phase 3 features (Federated Learning, eBPF, and Visualization).

## 1. Hybrid Dataplane (Rust + eBPF)

Currently, we capture packets in userspace using `libpnet`. To achieve 10Gbps+ performance, we must move the "drop" logic to the kernel.

**Proposed Flow:**
1.  **XDP (eXpress Data Path) Hook:** An eBPF program attaches to the network interface driver.
2.  **Fast Path:** Simple blacklisted IPs are dropped immediately in the kernel (nanoseconds).
3.  **Slow Path:** Complex packets are redirected to the userspace Rust application via `AF_XDP` sockets.
4.  **Verdict:** The AI model analyzes the packet. If malicious, it updates the eBPF map to drop future packets from this flow instantly.

## 2. Federated Learning Pipeline

To enable privacy-preserving collaboration:

1.  **Local Training:** The Rust engine collects feature vectors from local traffic.
2.  **Model Update:** A background thread computes gradients (weight updates) using `tch-rs`.
3.  **Aggregation:** Updates are encrypted and sent to the central `Aggregator Server`.
4.  **Distribution:** The server averages gradients and pushes the new global model back to all edges.

## 3. Visualization Interface (TUI)

We will use `ratatui` (Rust library) to build a terminal interface.

**Modules:**
- **Traffic Monitor:** Live sparkline of bandwidth usage.
- **Entropy Heatmap:** A grid showing the randomness of payload bytes (high entropy = potential encryption or packed malware).
- **Alert Log:** Real-time scrolling list of flagged packets with confidence scores.
