<div align="center">

<img src="https://img.shields.io/badge/ARGUS_AI-v0.1.0-blueviolet?style=for-the-badge&logo=shield&logoColor=white"/>
<img src="https://img.shields.io/badge/Platform-Raspberry_Pi_|_Linux-green?style=for-the-badge&logo=linux&logoColor=white"/>
<img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Status-Private_Build-red?style=for-the-badge"/>

# 🛡️ ARGUS AI

**Privacy-first · AI-powered · Edge-deployed Cybersecurity**

*Real-time network threat detection and autonomous response — running on a Raspberry Pi.*

</div>

---

## ✨ What Is ARGUS?

ARGUS is a self-contained cybersecurity platform built for environments where **cloud connectivity is unreliable, untrusted, or unavailable** — such as NGOs, field operations, and air-gapped networks. It captures raw network traffic, learns what "normal" looks like using on-device AI, and autonomously blocks anomalies — all without sending a single packet to the cloud.

| Capability | Detail |
|---|---|
| 🧠 **On-Device AI** | 1D CNN + Isolation Forest trained on your live traffic |
| 👁️ **Deep Packet Inspection** | Scapy-based real-time packet capture at kernel level |
| 🚫 **Autonomous Blocking** | `iptables` enforcement via the Aegis engine |
| 🔒 **Zero Cloud Dependency** | Fully offline — optional Firebase sync available |
| 🔌 **Plugin Architecture** | Drop-in security modules for advanced threat hunting |
| 🍓 **Edge-Native** | Runs on Raspberry Pi 4 (8GB) or any Debian-based system |

---

## 🏗️ Architecture

ARGUS is composed of **five core subsystems** and a **plugin layer**:

```
┌─────────────────────────────────────────────────────────┐
│                        ARGUS AI                         │
│                                                         │
│  ┌──────────┐   ┌────────────┐   ┌──────────────────┐  │
│  │  RETINA  │──▶│  MNEMOSYNE │──▶│      AEGIS       │  │
│  │  (Eyes)  │   │  (Memory)  │   │     (Shield)     │  │
│  │  Packet  │   │  AI Train  │   │  Threat Enforce  │  │
│  │  Capture │   │  Pipeline  │   │  (iptables/XAI)  │  │
│  └──────────┘   └────────────┘   └──────────────────┘  │
│                                                         │
│  ┌──────────┐   ┌────────────┐   ┌──────────────────┐  │
│  │  ORACLE  │   │   HERMES   │   │     PLUGINS      │  │
│  │  (Core)  │   │ (Uploader) │   │  (Extensible)    │  │
│  │  Config  │   │  Firebase  │   │  Threat Modules  │  │
│  │  + Auth  │   │   Sync     │   │  (see below)     │  │
│  └──────────┘   └────────────┘   └──────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Module Breakdown

| Module | Role |
|---|---|
| **`retina`** | High-performance packet capture, flow aggregation, IP anonymization |
| **`mnemosyne`** | AI training pipeline — 1D CNN & Isolation Forest on live flow data |
| **`aegis`** | Real-time prediction engine + autonomous `iptables` enforcement + XAI |
| **`oracle_core`** | System configuration, schema validation, anonymized logging |
| **`hermes`** | Optional Firebase uploader for remote model/alert sync |
| **`licensing`** | License verification and PDF document generation |
| **`access_control`** | GitHub-integrated branch-level access management |
| **`nyx`** | Stealth subsystem (dark traffic analysis) |
| **`athena`** | Intelligence aggregation layer |

---

## 🔌 Plugin System

ARGUS ships with **9 threat-hunting plugins**, each a self-contained module:

| Plugin | Description |
|---|---|
| 🕵️ **`jitter_hunter`** | Detects C2 beacons via timing jitter analysis |
| 🩺 **`dicom_inspector`** | Prevents medical imaging data (DICOM) leaks |
| 🍯 **`honey_mesh`** | Active deception honeypot network |
| 👻 **`ghost_service`** | Runs invisible decoy services to trap attackers |
| 🔐 **`pqc_scout`** | Detects post-quantum cryptography downgrade attacks |
| 🔍 **`auto_pentest`** | Automated internal penetration testing module |
| 🎭 **`chimera_deception`** | Multi-layer deception and adversarial traffic injection |
| ⚖️ **`gdpr_auditor`** | Real-time GDPR compliance scanning of network traffic |
| 🧩 **`manager`** | Plugin lifecycle orchestrator |

---

## 🚀 Quick Start

### Requirements
- Raspberry Pi 4 (8GB RAM) or any Debian 11/12 / Ubuntu 22.04+ system
- Python 3.11+
- Root / sudo access
- Network interface in promiscuous mode

### Installation

```bash
# Clone the repo
git clone https://github.com/blah-blah-cell/Ulti_argus.git
cd Ulti_argus

# Run the automated installer
sudo ./install.sh
```

The installer handles:
- Python venv creation and dependency install
- Network interface selection
- systemd service registration
- Optional Firebase credential setup

### Verify Services Are Running

```bash
sudo systemctl status argus-retina argus-aegis

# Stream live logs
sudo journalctl -u argus-* -f
```

**✅ Success:** You'll see `Capturing packets on [interface]` in Retina logs.

---

## ⚙️ Configuration

All config lives in `/etc/argus_v/` with `chmod 600` permissions.

| File | Controls |
|---|---|
| `retina.yaml` | Capture interface, IP salt, flow window |
| `mnemosyne.yaml` | Training schedule, contamination threshold, model params |
| `aegis.yaml` | Enforcement rules, dry-run period, XAI verbosity |

```yaml
# Example: aegis.yaml snippet
dry_run_days: 7          # Safety period before live blocking
block_threshold: 0.85    # Anomaly confidence to trigger block
xai_enabled: true        # Explainability for each block decision
```

---

## 🔒 Security Design

- **Least Privilege** — Services run as a dedicated non-root `argus` user
- **Ambient Capabilities** — `CAP_NET_RAW` / `CAP_NET_ADMIN` only; no full root shell
- **IP Anonymization** — All IPs are HMAC-SHA256 hashed with a per-device salt
- **7-Day Dry-Run** — Aegis logs anomalies without blocking during the learning phase
- **Offline-First** — Zero data egress by default; Firebase is strictly opt-in
- **Config Hardening** — All secrets stored with `mode 600`; no plaintext credentials

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run full test suite
pytest tests/ -v

# Run specific module tests
pytest tests/aegis/ -v
pytest tests/retina/ -v
pytest tests/mnemosyne/ -v
```

See [`TESTING.md`](TESTING.md) for integration test instructions and benchmark results.

---

## 📁 Repository Structure

```
Ulti_argus/
├── src/argus_v/
│   ├── retina/          # Packet capture & flow aggregation
│   ├── mnemosyne/       # AI training pipeline
│   ├── aegis/           # Threat enforcement engine
│   ├── plugins/         # Security plugin modules
│   ├── oracle_core/     # Core config & validation
│   ├── hermes/          # Firebase sync
│   ├── licensing/       # License management
│   └── access_control/  # GitHub access control
├── scripts/             # Deployment, training, diagnostic tools
├── tests/               # Full test suite (pytest)
├── docs/                # Deployment & networking guides
├── install.sh           # Automated installer
└── pyproject.toml       # Package configuration
```

---

## 🗺️ Roadmap

- [ ] **Web Dashboard** — Local real-time traffic visualization UI
- [ ] **Model Zoo** — Pre-trained baselines for common IoT / NGO hardware profiles
- [ ] **Multi-Site Aggregation** — HQ-level view across field deployments
- [ ] **DPI Module** — Full deep packet inspection for unencrypted traffic
- [ ] **eBPF Backend** — Kernel-level capture without Scapy overhead

---

## 📄 License

MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

**Built for the field. Runs on the edge. Trusts no cloud.**

*ARGUS AI — v0.1.0*

</div>
