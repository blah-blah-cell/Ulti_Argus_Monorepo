# 🛡️ Argus_V: AI-Powered Network Defense for NGOs

**Privacy-first, offline-capable, and autonomous cybersecurity for organizations that need enterprise-grade protection on a bootstrap budget.**

Argus_V is a specialized security stack designed specifically for NGOs operating in high-risk or low-bandwidth environments. It provides real-time threat detection and automated response without requiring cloud connectivity or expensive subscriptions.

| Feature | Benefit |
|---------|---------|
| **Offline-First** | No data ever leaves your network. Perfect for sensitive operations. |
| **AI-Powered** | Learns your network's unique "heartbeat" to spot sophisticated anomalies. |
| **Zero-Cost Hardware** | Runs on a Raspberry Pi 4 (8GB) or equivalent hardware. |
| **Automated Response** | Blocks threats in real-time using Aegis enforcement engine. |
| **NGO-Focused** | Simplified deployment and maintenance for non-technical staff. |

---

## 📋 Prerequisites

### Hardware Requirements
- **Raspberry Pi 4 Model B (8GB RAM recommended)** or equivalent ARM/x86_64 Debian-based system.
- **MicroSD Card (32GB+):** High-endurance (Class 10/UHS-1) recommended.
- **Power Supply:** Stable 5.1V 3A USB-C power.
- **Network Interface:** Ethernet recommended for primary monitoring.

### Network Requirements
- **Positioning:** Must be placed where it can see network traffic (e.g., as a gateway or via a SPAN/Mirror port).
- **Interface:** Network card must support promiscuous mode.

### OS & Software
- **OS:** Raspberry Pi OS Lite (64-bit) Bookworm/Bullseye, or Debian 11/12.
- **Python:** 3.11 or higher (automatically handled by installer).
- **Access:** Root/sudo privileges required for installation.

---

## 🚀 Quick Start (5 Minutes)

Deploy Argus_V to your device:

```bash
git clone https://github.com/Ojas-bb/Argus_V.git
cd Argus_V
sudo ./install.sh
```

### Verification Steps
After installation, check that all services are active:

```bash
# Check service status
sudo systemctl status argus-retina argus-mnemosyne argus-aegis

# Check for active packet capture
tail -f /var/log/argus_v/retina.log
```

**Success Indicator:** You should see "Capturing packets on [interface]" in the Retina logs.

---

## 🛠️ Detailed Installation

### 1. Prepare Your Environment
Ensure your system is up to date:
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Clone the Repository
Download the Argus_V source code:
```bash
git clone https://github.com/Ojas-bb/Argus_V.git
cd Argus_V
```

### 3. Firebase Integration (Optional)
Argus_V can sync models and alerts to Firebase for remote monitoring.
1. Create a project in the [Firebase Console](https://console.firebase.google.com/).
2. Enable **Realtime Database** and **Cloud Storage**.
3. Generate a **Service Account JSON key** (Project Settings -> Service Accounts).
4. Have this JSON content ready during installation.

### 4. Run the Installer
The interactive installer will guide you through:
- Network interface selection (e.g., `eth0`).
- Firebase credential input.
- Component activation (Retina, Mnemosyne, Aegis).

```bash
sudo ./install.sh
```

### 5. Service Management
All components run as systemd services:
- **Start All:** `sudo systemctl start argus-retina argus-aegis`
- **Stop All:** `sudo systemctl stop argus-retina argus-aegis`
- **View Combined Logs:** `sudo journalctl -u argus-* -f`

---

## 🏗️ Architecture Overview

Argus_V consists of three core modules that work in harmony:

1. **Retina (The Eyes) 👁️**
   - **Function:** High-performance packet capture and telemetry generation.
   - **Security:** Runs as a non-root `argus` user utilizing `AmbientCapabilities` (`CAP_NET_RAW`, `CAP_NET_ADMIN`).
   - **Output:** Aggregates raw traffic into anonymized flow features.

2. **Mnemosyne (The Memory) 🧠**
   - **Function:** AI training pipeline.
   - **Workflow:** Processes Retina data weekly (via cron) to update the network's behavioral baseline.
   - **Method:** Uses Isolation Forest algorithms to define "normal" vs. "anomalous".

3. **Aegis (The Shield) 🛡️**
   - **Function:** Real-time threat enforcement.
   - **Workflow:** Compares live Retina telemetry against Mnemosyne models.
   - **Enforcement:** Automatically drops malicious traffic via `iptables`.

---

## ⚙️ Configuration

Configuration files are located in `/etc/argus_v/`.

| File | Purpose |
|------|---------|
| `retina.yaml` | Packet capture settings, interface selection, and IP salt. |
| `mnemosyne.yaml` | Training schedules, contamination levels, and model parameters. |
| `aegis.yaml` | Enforcement rules, dry-run duration, and threshold settings. |

### Security & Permissions
- All configuration files are protected with **mode 600** (Read/Write for root only).
- Sensitive credentials (Firebase, IP salts) are never stored in plain text in world-readable locations.

---

## 🔒 Security Features

- **Least Privilege:** Services run as a dedicated `argus` user where possible.
- **AmbientCapabilities:** Retina captures raw packets without requiring full root shell access.
- **IP Anonymization:** Uses HMAC-SHA256 salted hashing for all internal IP tracking to protect user privacy.
- **Safety Period:** Aegis defaults to a **7-day dry-run mode**. During this time, it logs anomalies but does *not* block traffic, allowing you to tune the model and prevent false positives.

---

## ❓ Troubleshooting

### Service won't start
- **Check logs:** `sudo journalctl -u argus-retina -e`
- **Common Cause:** Another process (like `tcpdump`) is locking the interface.
- **Common Cause:** Invalid YAML syntax in `/etc/argus_v/`.

### No packets captured
- **Verify interface:** Run `ip link` to ensure the interface is `UP`.
- **Scapy Warning:** If you see `WARNING: No libpcap provider found`, ensure `libpcap-dev` is installed: `sudo apt install libpcap-dev`.

### Permission denied errors
- Ensure you are running commands with `sudo` where required.
- Check directory ownership: `sudo chown -R argus:argus /var/lib/argus_v`.

### Configuration errors
- Validate your config: `/opt/argus_v/venv/bin/python -m argus_v.retina.cli --config /etc/argus_v/retina.yaml validate`

---

## 🗑️ Uninstallation

To cleanly remove Argus_V:

```bash
sudo ./uninstall.sh
```

**Options:**
- `--purge`: Removes all configuration and historical data/logs.
- By default, uninstallation preserves your `/etc/argus_v` configurations and `/var/lib/argus_v` data.

---

## 🗺️ What's Next / v1 Roadmap

- **Model Zoo:** Pre-trained models for common NGO hardware (IoT cameras, VoIP phones).
- **Multi-Site Dashboard:** Aggregated view for HQ to monitor multiple field offices.
- **Local Web UI:** Light-weight local dashboard for real-time traffic visualization.
- **DPI Integration:** Optional Deep Packet Inspection for non-encrypted traffic analysis.

---

**Built with ❤️ for the NGO community. Stay safe out there.**
