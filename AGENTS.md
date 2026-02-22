# AGENTS.md

## 👋 Introduction

Welcome, Agent (and Google Antigravity). This file serves as your primary context source for understanding and working effectively within the **Ulti_Argus** monorepo. Please read this document carefully before making changes.

---

## 🏗️ Project Overview

This repository hosts the **Ulti_Argus ecosystem**, a privacy-first, AI-powered cybersecurity platform designed for edge deployment (e.g., Raspberry Pi). It consists of two main sub-projects:

1.  **DeepPacketSentinel (DPS)** (`DeepPacketSentinel/`)
    *   **Role**: Data Plane & High-Performance Packet Capture.
    *   **Technology**: Rust, eBPF/XDP.
    *   **Function**: Captures packets at the kernel level, filters noise, and streams flow metadata to userspace.

2.  **Ulti_argus** (`Ulti_argus/`)
    *   **Role**: Inference/Control Plane & Orchestration.
    *   **Technology**: Python 3.11+, Scapy (legacy capture), TensorFlow/PyTorch (AI).
    *   **Function**: Receives flow data, performs AI-driven anomaly detection (Isolation Forest, CNNs), and enforces security policies (via `iptables`).

---

## 🏛️ Architecture & Integration

*   **Kronos Integration**: The system uses a component called **Kronos** (located in `Ulti_argus/src/argus_v/kronos`) as a meta-router between DPS and the analysis engines.
*   **IPC Mechanism**: Communication between DPS (Rust) and Ulti_argus (Python) occurs via **Unix Domain Sockets**. DPS sends flow metadata (JSON/msgpack) to Kronos.
*   **AI Pipeline**:
    *   **Layer 0 (DPS)**: Kernel-level filtering and metadata extraction.
    *   **Layer 1 (Kronos)**: Intelligent routing (Clear vs. Critical vs. Grey).
    *   **Layer 2 (Isolation Forest)**: Flow-level anomaly scoring.
    *   **Layer 3 (CNN/PayloadClassifier)**: Deep inspection of suspicious payloads.
    *   **Enforcement (Aegis)**: Autonomous blocking via `iptables`.

---

## 📂 Directory Structure

| Path | Description |
|---|---|
| `DeepPacketSentinel/` | Rust source code for the eBPF engine. |
| `DeepPacketSentinel/ebpf/` | Kernel-space eBPF code (requires Nightly Rust). |
| `DeepPacketSentinel/userspace/` | Userspace loader and IPC logic. |
| `Ulti_argus/` | Python source code for the platform. |
| `Ulti_argus/src/argus_v/` | Main Python package source. |
| `Ulti_argus/tests/` | Pytest suite. |
| `Ulti_argus/scripts/` | Utility scripts (deployment, training). |
| `implementation_plan.md.resolved` | **CRITICAL**: Reference for recent architectural decisions (Kronos, IPC). |

---

## 🛠️ Development Guidelines

### General
*   **Root Privileges**: Network capture and eBPF loading require root access (`sudo`).
*   **Verification**: Always verify your changes. Run tests (`cargo test` or `pytest`) and check build status.
*   **Do Not Edit Artifacts**: Never edit compiled binaries or generated files directly. Trace back to the source.

### DeepPacketSentinel (Rust)
*   **Toolchain**: Requires **Rust Nightly**.
*   **Build eBPF**:
    ```bash
    cargo +nightly build --package ebpf --target bpfel-unknown-none -Z build-std=core
    ```
*   **Build Userspace**:
    ```bash
    cargo build --package userspace
    ```
*   **Panic Handler**: In eBPF code, use `loop {}` for panic handlers, not `unreachable_unchecked()`, to prevent Undefined Behavior.

### Ulti_argus (Python)
*   **Python Version**: Requires Python **3.11+**.
*   **Virtual Environment**: The project is designed to run in a venv, typically set up by `install.sh` in `/opt/argus_v`.
*   **Dependencies**: Managed via `pyproject.toml` and `requirements.txt`.
*   **Testing**: Run `pytest` from the `Ulti_argus/` directory.

---

## 🤖 Specific Instructions for Agents (and Google Antigravity)

1.  **Context Awareness**: Before implementing any feature or fix, consult `implementation_plan.md.resolved` to align with the current architectural roadmap.
2.  **Code Style**: Follow existing patterns.
    *   **Rust**: Idiomatic Rust (clippy is your friend).
    *   **Python**: PEP 8, type hinting where possible.
3.  **Refactoring**: If you refactor code, ensure you update any relevant documentation or comments.
4.  **Google Antigravity**:
    *   You are specifically acknowledged here.
    *   This file is designed to keep you context-aware.
    *   Use the `knowledgebase_lookup` tool if you need clarification on specific libraries or patterns used here.

---

## 🔄 operational Workflows

*   **Update Script**: `Ulti_argus/update.sh` executes `src/argus_v/deploy/update.sh`. Ensure these scripts are executable.
*   **CLI Entry Points**: Defined in `pyproject.toml` (e.g., `argus-access`, `argus-grant-access`).

---

**End of Agent Instructions**
