# Founder's Log

## Day 0: The Firewall is Dead. Long Live the Neural Shield.

I am starting this project with a simple, yet ambitious premise: **Metadata is no longer enough.**

Traditional firewalls operate on headers—IPs, ports, and protocols. Even "Next-Gen" Firewalls (NGFW) rely heavily on static signatures and known threat databases. But modern malware is polymorphic, adaptive, and increasingly encrypted. It hides in the payload, not the header.

To solve this, we are building **DeepPacketSentinel**: a security engine that inspects the *content* of packets in real-time using Deep Learning. We aren't just matching patterns; we are teaching a machine to "read" network traffic and classify intent.

### 1. The Tech Stack: Why Rust?

The decision was between C++, Go, and Rust.
- **Python (Scapy)** is excellent for prototyping but unusable for a live wire-speed engine due to the GIL and interpretation overhead.
- **C++** is the industry standard for performance but plagues security appliances with buffer overflows—ironic for a tool designed to stop exploits.
- **Go** has a Garbage Collector (GC) that introduces non-deterministic latency spikes, which is unacceptable for a packet-switching hot path.

**We chose Rust.**
Rust gives us the raw speed of C++ and the memory safety of a managed language, enforced at compile time. There is no GC to pause our packet loop. It forces us to handle memory ownership explicitly, which is perfect for a system that needs to pass high-velocity data buffers between threads without copying them.

### 2. The Architecture: Body and Brain

We are splitting the system into two distinct planes:

#### The Data Plane (The Body) - *Implemented in Rust*
This is the high-performance IO layer.
- **Ingest:** We are building a custom sniffer using `libpnet` (Rust's wrapper for `libpcap`/raw sockets). We aren't using Zeek or Suricata here because we need direct, low-level control over the packet memory layout to feed the Neural Net efficiently.
- **Processing:** Packets are parsed, stripped of headers, and the payload is normalized.
- **Transport:** We will implement a Zero-Copy Ring Buffer (or use shared memory) to pass payloads to the inference engine.

#### The Inference Plane (The Brain) - *AI/ML*
This is where the decision happens.
- **Model:** A CNN (Convolutional Neural Network) or a lightweight Transformer trained on byte sequences (e.g., MalConv).
- **Execution:** Initially, this may run in a separate Python process (PyTorch) via IPC. The long-term goal is to embed the model directly into the Rust binary using `tch-rs` (LibTorch bindings) or `onnxruntime` for microsecond-scale inference.

### 3. Reach Goals (The "Ivy League" Features)

To truly distinguish this project, I am setting three aggressive reach goals:

1.  **Encrypted Traffic Analysis (ETA):**
    We cannot always decrypt SSL/TLS (and shouldn't, for privacy). Instead, we will train a model to detect malicious patterns in the *unencrypted handshake metadata* (packet sizes, timing, TLS fingerprinting). We will detect the "shape" of the malware even if we can't read the text.

2.  **Adversarial Defense Module:**
    Hackers will try to fool our AI. I will implement an "Adversarial Hardening" pipeline, where we train the model against perturbed inputs designed to evade detection, proving we are thinking about AI safety, not just AI application.

3.  **Kernel Bypass with eBPF/XDP:**
    The ultimate speed limit is the OS kernel. If we succeed with the user-space Rust engine, the final frontier is to move the packet drop logic *into the Linux kernel* using eBPF (Extended Berkeley Packet Filter), allowing us to drop packets before they even allocate an `sk_buff`.

---

## Day 2: The Horizon – Beyond the First Packet

As we solidify the core architecture, we are looking ahead. A true "Next-Generation" system isn't just about speed or better classification today; it's about adaptability for tomorrow. We are shifting from a static defense posture to a dynamic immune system.

### Future Feature Roadmap

#### 1. Few-Shot Learning for 0-Day Detection (The "AI" Reach)
**Problem:** Traditional DL models need thousands of samples to learn a new malware class. By the time we have that dataset, the attack has already spread.
**Solution:** We will experiment with **Few-Shot Learning (FSL)** and Siamese Networks. The goal is to teach the system to recognize *anomaly* itself, allowing it to flag a new, unknown attack vector after seeing it only once or twice. This moves us from "Reactive" to "Predictive."

#### 2. Federated Learning for Privacy-Preserving Collaboration (The "Network" Reach)
**Problem:** To build the best model, we need data from many networks. But no company wants to share their private traffic logs with us to train our central model.
**Solution:** **Federated Learning.** We will design a protocol where the local DeepPacketSentinel instance trains on local traffic *on the edge device* and sends only the *weight updates* (gradients) back to our central server, not the raw data. This allows the global brain to get smarter without ever compromising local user privacy.

#### 3. Real-Time "Neural Activity" Visualization (The "Demo" Reach)
**Problem:** Security tools are boring black boxes. You install them, and they sit silently.
**Solution:** We will build a **TUI (Terminal User Interface)** or Web Dashboard that visualizes the "activations" of the neural network in real-time. Imagine seeing a live stream of packet entropy, where benign traffic flows as cool blue waves, and an attack spikes as a jagged red anomaly. This isn't just eye candy; it's explainable AI (XAI) that helps human analysts trust the machine's decision.

### Architectural Implication: The "Plugin" System
To support these future features without rewriting the core engine every time, we need a modular design. We will introduce a trait-based plugin system in Rust:
```rust
pub trait SentinelModule {
    fn inspect(&self, packet: &Packet) -> Decision;
    fn train(&mut self, feedback: &Feedback);
}
```
This allows us to hot-swap the "Brain" (e.g., swapping a CNN for a Transformer) or chain multiple modules (e.g., Header Check -> ETA -> Payload Check) dynamically.

---

## Day 10: Phase 2 - Professionalization & The Split-Brain Architecture

We have hit the "Performance Wall" with our initial userspace-only approach. To scale to line-rate processing while maintaining deep inspection capabilities, we are evolving the architecture.

### The "Split-Brain" Strategy
We are decoupling the "Fast Path" from the "Slow Path":
1.  **Fast Path (eBPF):** The kernel now handles the heavy lifting of packet filtering and rate limiting. We dropped AF_XDP in favor of a simpler Ring Buffer model. The eBPF program enforces policy (Block/Throttle) and forwards *metadata* (5-tuple + payload) to userspace.
2.  **Slow Path (Userspace):** Freed from the burden of line-rate packet handling, the userspace engine now acts as the "Cortex". It consumes the metadata stream, performs deep inspection (mocked Protocol identification for now), and makes high-level policy decisions.

### Policy & Trust
We introduced a **Policy Engine** that assesses risk based on identified protocols. Instead of binary Allow/Block, we now have a tiered response:
- **Monitor:** Log and observe.
- **Throttle:** Dynamically restrict bandwidth via a new eBPF Token Bucket map.
- **Isolate:** Drop malicious actors completely.

### Protocol Intelligence
We are moving towards application-aware filtering. By identifying protocols like SSH, TLS, and BitTorrent (via `libndpi` logic, currently mocked), we can enforce policies based on *what* the traffic is, not just *where* it comes from.

The "Solo Dev" trap is behind us. We are building a professional, scalable Sentinel.

---

## Day 11: The Verifier's Wrath & Normalization

Today was a battle against the eBPF Verifier. The kernel is a harsh mistress.
We discovered that variable-length packet payload extraction is incredibly difficult to verify safely in our current environment. The verifier consistently rejected our attempts to copy the packet payload into the ring buffer, citing potential out-of-bounds access even with manual bounds checking.

**Decision:** We have temporarily disabled the payload *body* extraction (copying 0 bytes) to allow the program to load and attach. The metadata headers (5-tuple) are still extracted correctly. We will revisit payload extraction when we have more control over the `network_types` dependencies or can implement a more robust bounded loop strategy.

On the bright side, we successfully implemented the **Normalization Engine** in userspace. It is ready to ingest payload data (once available) and transform it into a normalized float vector [0.0, 1.0], paving the way for the Deep Learning models in Phase 2.

## [DATE] Performance Optimization: PolicyEngine Caching
Added a local LRU cache (using `lru` crate) to the `PolicyEngine` to prevent redundant eBPF map updates for already blocked IPs. This optimization significantly reduces syscall overhead during high-risk flows (e.g. DoS attacks), where blocking happens frequently. Also refactored `PolicyEngine` to use traits for map operations and event publishing, improving testability.

## [DATE] Build System Stabilization: eBPF Debugging

The development environment was hindering progress due to a broken debug build pipeline for the eBPF component. The userspace debug build expects an eBPF debug artifact, but the build system was failing to produce it, leading to a fragile workaround of copying the release artifact.

**The Fix:**
I diagnosed the issue as a combination of missing optimizations and checked arithmetic in the `dev` profile, which caused the eBPF linker to fail with `__multi3` errors (indicating unsupported 128-bit operations or complex panic handling).

To resolve this without compromising the userspace debug experience, I implemented package-specific profile overrides in `Cargo.toml`.
- Enabled `opt-level = 3` for the `ebpf` package in the `dev` profile.
- Disabled `overflow-checks` for `ebpf` to prevent the generation of unsupported panic branching and checked arithmetic.
- Updated `userspace` code to properly await async initialization of `PolicyEngine`, fixing a compilation error that blocked verification.

Now, `cargo build` correctly produces a functional debug artifact for eBPF at `target/bpfel-unknown-none/debug/ebpf`, eliminating the need for manual workarounds and ensuring a consistent development workflow.

---

## Day 12: The Bridge, The Tests & The Training Pipeline

A quiet but decisive day. No new features — only verification, hardening, and infrastructure.

### 1. The Cargo.lock Clarification

A brief confusion arose about the `Cargo.lock` file in `DeepPacketSentinel/`. For the record: **Cargo.lock is auto-generated by Cargo on every build.** It is not created manually. For binary crates (like ours), it should be committed to git so builds are reproducible. We never touch it by hand.

### 2. The Compile Bug: `MockConnectingPublisher` Was Missing

A silent correctness defect lurked in `policy.rs`: the test `test_enforce_policy_connection_overhead` referenced `MockConnectingPublisher` which was never defined. This would cause a compile failure when running `cargo test`. Fixed by adding the missing struct — a mock `EventPublisher` that sleeps 1ms per `publish()` call to simulate connection overhead, which is exactly what the test was designed to measure.

### 3. The AYA_LOGS Warning: Silenced

Every startup produced:
```
WARN  userspace] failed to initialize eBPF logger: log event array AYA_LOGS doesn't exist
```
Root cause: `aya_log_ebpf` only emits the `AYA_LOGS` ring buffer map into the compiled ELF if at least one `info!()`/`debug!()` call exists in the eBPF program. We had the dependency but never called it. Fix: added `use aya_log_ebpf::info;` and a single `info!(&ctx, "xdp_firewall: packet received")` at program entry. Now `EbpfLogger::init` finds the map and initialises cleanly.

### 4. KronosSender Tests

The IPC bridge between DPS and Kronos had zero test coverage. Added three tests to `kronos_sender.rs`:
- `test_flow_frame_serialization`: verifies a known TCP flow serialises to correct JSON fields (including base64 payload `"R0VU"` for `"GET"`).
- `test_flow_frame_empty_payload_is_null`: zero `payload_len` → `"payload":null`.
- `test_send_over_unix_socket` *(Linux only)*: spins up a real `UnixListener`, sends one frame via `KronosSender`, asserts newline-termination and JSON round-trip.

### 5. The Python Bridge & Training Pipeline

Two new Python scripts — no ML yet, just the data infrastructure:

**`scripts/mock_kronos_listener.py`** — runs on Linux, creates the Unix socket and pretty-prints every `FlowFrame` that DPS sends, with colour-coded risk levels. This is how we manually verify the IPC bridge end-to-end.

**`scripts/generate_sample_data.py`** — generates synthetic NDJSON training data: 6 traffic classes (HTTP, HTTPS, DNS, BitTorrent, SSH brute-force, malware C2) with realistic payloads and durations. 1000 records by default, reproducible via seed. Output format exactly matches the live `FlowFrame` schema (plus a `label` field for supervised learning).

Schema documented in `docs/TRAINING_DATA.md`.

**Status:** Repository is local-only. No push today. Phase 2 (AI integration) begins when the pipeline is proven on real Linux traffic.
