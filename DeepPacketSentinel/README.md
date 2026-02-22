# DeepPacketSentinel

**DeepPacketSentinel** is a next-generation Deep Packet Inspection (DPI) security engine. Unlike traditional firewalls that rely on header metadata and static signatures, DeepPacketSentinel inspects the actual packet payload using Deep Learning models to detect malicious patterns in real-time.

## Project Vision

See [FOUNDERS_LOG.md](FOUNDERS_LOG.md) for the project narrative, architectural decisions, and roadmap.

## Architecture

*   **Data Plane:** Rust (high-performance packet capture and filtering using eBPF/XDP).
*   **Inference Plane:** Deep Learning (CNN/Transformer based classification).

## Getting Started

### Prerequisites

*   **Rust:** Latest stable version + Nightly toolchain (for eBPF).
*   **Linux:** Required for raw socket access (Windows/Mac support is experimental via `libpnet`).
*   **Root Privileges:** Required to capture network traffic.
*   **eBPF Tools:** `bpf-linker` and `cargo-generate`.

### Build and Run

1.  **Build the eBPF Kernel Program:**
    ```bash
    cargo +nightly build --package ebpf --target bpfel-unknown-none -Z build-std=core
    ```

2.  **Build the Userspace Loader:**
    ```bash
    cargo build --package userspace
    ```

3.  **Run the sniffer (requires root):**
    ```bash
    sudo ./target/debug/userspace --iface <YOUR_INTERFACE>
    ```

## Roadmap

### Phase 1: The Core Engine (Current)
*   [x] Project Initialization & Architecture Design
*   [x] eBPF/XDP Kernel Bypass (Initial Implementation)
*   [x] Real-time Packet Capture (eBPF/XDP)
*   [x] Zero-Copy Ring Buffer implementation
*   [x] Payload Extraction (Headers only due to verifier limits) & Normalization

### Phase 2: The Brain (AI Integration)
*   [ ] CNN/Transformer Model Integration (`tch-rs` or `onnxruntime`)
*   [ ] MalConv-based Malware Classification
*   [ ] Encrypted Traffic Analysis (ETA) - *Reach Goal*

### Phase 3: The Future (Innovation)
*   [ ] **Few-Shot Learning:** Zero-day detection with minimal training samples.
*   [ ] **Federated Learning:** Collaborative defense without data sharing.
*   [ ] **Neural Visualization:** Real-time TUI/Web dashboard of network entropy.
*   [ ] **eBPF Integration:** Kernel-level packet dropping for extreme performance.

## License

MIT License
