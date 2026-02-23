# Architecture Documentation

## System Overview

The **Ulti_Argus** ecosystem is a hybrid security platform that combines high-performance kernel-level packet filtering with AI-driven userspace analysis. It is designed for edge deployment (e.g., Raspberry Pi) to protect networks from malicious traffic with minimal latency.

The system is composed of two main subsystems:
1.  **DeepPacketSentinel (DPS)**: The "Muscle" - A Rust-based component handling Data Plane operations using eBPF/XDP.
2.  **Ulti_argus (Aegis)**: The "Brain" - A Python-based component handling Inference and Control Plane operations.

## Component Interactions

The following diagram illustrates the high-level interaction between the components:

```mermaid
graph TB
    subgraph Kernel Space
        XDP[XDP Program]
        BPF_Map[BLOCKLIST Map]
    end

    subgraph Userspace - Rust
        DPS[DeepPacketSentinel]
    end

    subgraph Userspace - Python
        Kronos[Kronos Router]
        PE[Prediction Engine]
        BLM[Blacklist Manager]
        KE[Kronos Enforcer]
        Mnemosyne[Deep Learning Model]
    end

    XDP -->|Flow Metadata| DPS
    DPS -->|IPC (Unix Socket)| Kronos
    Kronos -->|Flow Data| PE
    PE -->|Anomaly?| BLM
    BLM -->|Block Command| KE
    KE -->|bpftool update| BPF_Map
    BPF_Map -->|Read| XDP
    XDP -->|Drop| Malicious Traffic
```

### DeepPacketSentinel (Rust)
- **Role**: Captures network traffic directly from the NIC using AF_XDP or raw sockets.
- **Responsibility**: Parses packet headers, aggregates flow statistics, and filters noise before sending relevant metadata to the Python layer.
- **Technology**: Rust, Aya (eBPF framework).

### Kronos Router (Python)
- **Role**: The entry point for flow data into the Python ecosystem.
- **Responsibility**: Receives flow frames via IPC, performs initial triage, and routes flows to the appropriate analysis engine (Isolation Forest or CNN).

### Prediction Engine (Python)
- **Role**: The core analysis loop.
- **Responsibility**: Aggregates flows, runs the Isolation Forest model via `scikit-learn`, and orchestrates the decision-making process.

### Mnemosyne (Python)
- **Role**: Deep inspection engine.
- **Responsibility**: Uses PyTorch CNNs to inspect packet payloads for complex attack patterns when escalated by Kronos.

### Aegis & Enforcer (Python)
- **Role**: The enforcement arm.
- **Responsibility**: Manages the blacklist (SQLite/Firebase) and injects blocking rules into the kernel eBPF map via `bpftool`.

## Data Flow

### 1. Packet Capture & Parsing
Packets enter via the network interface. The XDP program intercepts them at the earliest point in the kernel driver. If the source IP is in the `BLOCKLIST` map, the packet is dropped immediately (XDP_DROP).

### 2. Metadata Extraction
Allowed packets are processed by DeepPacketSentinel in userspace (or via eBPF perf buffers). Key metadata (Src/Dst IP, Ports, Protocol, Size, Timing) is extracted.

### 3. IPC Transmission
Metadata is serialized (JSON/MsgPack) and sent over a Unix Domain Socket (`dps_kronos.sock`) to the Kronos Router.

### 4. Analysis & Scoring
Kronos routes the flow frame:
- **Fast Path**: Trusted flows are ignored.
- **Standard Path**: Sent to Prediction Engine for Isolation Forest scoring.
- **Escalation Path**: Suspicious flows with payloads are sent to Mnemosyne for CNN analysis.

### 5. Decision & Enforcement
If an anomaly score exceeds the threshold:
1.  **Blacklist Manager** adds the IP to the local database.
2.  **Kronos Enforcer** executes `bpftool map update` to add the IP to the kernel map.
3.  **Feedback Manager** (optional) allows for false-positive correction.

## Security Model

### Zero-Trust IPC
The communication between Rust (DPS) and Python (Aegis) relies on a local Unix Domain Socket.
- **Validation**: The Python listener validates the structure of every incoming frame before processing.
- **Isolation**: Components run in separate processes; a crash in the Python layer does not bring down the packet capture (though analysis stops).

### eBPF Enforcement
- **Mechanism**: We use eBPF Maps (Hash Map type) to store blacklisted IPs.
- **Performance**: XDP lookups are O(1), ensuring no performance degradation even with large blacklists.
- **Safety**: The eBPF verifier ensures that the kernel code is safe and cannot crash the system.

## AI Pipeline

### Isolation Forest (Layer 2)
- **Library**: `scikit-learn`
- **Features**: Flow duration, byte counts, packet counts, inter-arrival times.
- **Use Case**: Detecting statistical anomalies (DoS, scanning, unusual data exfiltration).
- **Training**: Unsupervised learning on "normal" traffic baselines.

### Payload Classifier (Layer 3)
- **Library**: `PyTorch`
- **Architecture**: 1D CNN (Convolutional Neural Network).
- **Features**: Raw payload bytes (first N bytes).
- **Use Case**: Detecting specific attack signatures (SQL injection, shellcode, malware patterns) that look statistically normal.

## Deployment Topology

### Edge Deployment (Primary)
- **Target**: Raspberry Pi 4/5 or generic Linux gateway.
- **Setup**: Single-node deployment where Capture, Analysis, and Enforcement happen on the same device.
- **Benefit**: Zero network latency for enforcement; data stays local (privacy-first).

### Distributed (Future)
- **Concept**: Multiple DPS sensors streaming to a central Aegis Brain.
- **Status**: Architecture supports it via TCP sockets instead of Unix Domain Sockets, but current implementation focuses on Unix Sockets for security and simplicity.

## Configuration Reference

The system is configured via `config.yaml` (default: `/etc/argus/aegis.yaml`).

```yaml
aegis:
  # Model Configuration
  model:
    model_local_path: "/opt/argus_v/models/model.pkl"
    scaler_local_path: "/opt/argus_v/models/scaler.pkl"

  # Prediction Settings
  prediction:
    anomaly_threshold: -0.6
    high_risk_threshold: -0.8

  # Polling / Input
  polling:
    csv_directory: "/opt/argus_v/data/input"  # Legacy CSV mode
    poll_interval_seconds: 1.0

  # Enforcement
  enforcement:
    dry_run_duration_days: 7
    blacklist_db_path: "/opt/argus_v/data/blacklist.db"
    iptables_chain_name: "ARGUS-BLOCK"
```
