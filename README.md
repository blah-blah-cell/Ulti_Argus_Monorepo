# Ulti_Argus Monorepo

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Rust](https://img.shields.io/badge/rust-nightly-orange)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

This repository is the central monorepo containing the **Ulti_Argus ecosystem**, a privacy-first, AI-powered cybersecurity platform designed for edge deployment (e.g., Raspberry Pi).

It is divided into two main sub-projects:

## 1. [Ulti_argus](./Ulti_argus/) (The Brain)
The primary threat intelligence, access control, and orchestration platform. This component handles the high-level security models, plugins, and AI-driven analysis (Isolation Forest, CNNs).

## 2. [DeepPacketSentinel](./DeepPacketSentinel/) (The Muscle)
A next-generation Deep Packet Inspection (DPI) security engine built in Rust. It utilizes eBPF/XDP for high-speed packet capture and filtering in the Linux kernel (Data Plane) and streams flow metadata to userspace for deep learning classification and policy enforcement (Inference Plane).

---

## 🚀 Quick Start Guide

To deploy the entire ecosystem (Rust DPS + Python Aegis) on a Linux machine (Debian/Ubuntu/Raspbian):

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/Ulti_Argus.git
    cd Ulti_Argus
    ```

2.  **Run the unified installer:**
    ```bash
    chmod +x install.sh
    sudo ./install.sh
    ```
    This script will:
    *   Install system dependencies (Rust, Python, bpftool, etc.).
    *   Build the eBPF kernel program and userspace loader.
    *   Set up the Python virtual environment and install dependencies.
    *   Train/Compile initial AI models.
    *   Install and start systemd services (`argus-sentinel`, `argus-brain`).

3.  **Monitor the system:**
    ```bash
    # View live dashboard
    source /opt/argus_v/venv/bin/activate
    argus-tui
    ```

---

## 🏛️ Architecture Overview

The system operates on a 4-layer pipeline:

1.  **Data Plane (Layer 0)**: **DeepPacketSentinel** (Rust/eBPF) captures packets in the kernel. Malicious IPs are dropped instantly via XDP.
2.  **Meta-Router (Layer 1)**: **Kronos** (Python) receives flow metadata via Unix Domain Sockets and triages traffic.
3.  **Anomaly Detection (Layer 2)**: **Prediction Engine** scores flows using an Isolation Forest model.
4.  **Deep Inspection (Layer 3)**: **Mnemosyne** uses a CNN to inspect payloads of suspicious flows.

**Enforcement**: Decisions are enforced by injecting blocking rules directly into the eBPF map using `bpftool`, ensuring zero-latency drops for future packets.

> For detailed architecture, see [**docs/ARCHITECTURE.md**](./docs/ARCHITECTURE.md).

---

## 📚 Documentation

*   [**Architecture Guide**](./docs/ARCHITECTURE.md): Detailed system design, component interactions, and security model.
*   [**API Reference**](./docs/API_REFERENCE.md): Python class documentation for AegisDaemon, PredictionEngine, and more.
*   [**Ulti_argus README**](./Ulti_argus/README.md): Specifics for the Python subsystem.
*   [**DeepPacketSentinel README**](./DeepPacketSentinel/README.md): Specifics for the Rust subsystem.

---

### Setup & Development
Each sub-project maintains its own dependencies and build instructions. Please refer to their respective README files for detailed documentation.
