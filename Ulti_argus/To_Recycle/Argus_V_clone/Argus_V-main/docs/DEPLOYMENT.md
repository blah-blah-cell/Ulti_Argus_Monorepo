# ARGUS v0 Raspberry Pi Deployment Guide

This guide walks you through deploying ARGUS v0 on a Raspberry Pi for network security monitoring. The process takes approximately 30-45 minutes.

## Overview

ARGUS v0 is a network security system that:
- **Captures** network traffic and identifies unusual patterns
- **Detects** potential security threats using machine learning
- **Alerts** you when suspicious activity is detected

The Raspberry Pi sits on your network and monitors all traffic passing through it.

---

## Hardware Requirements

### Required Equipment

| Item | Specification | Notes |
|------|---------------|-------|
| **Raspberry Pi 4** | 8GB RAM model recommended | The 4GB model works but may struggle with heavy traffic |
| **MicroSD Card** | 32GB minimum, Class 10 or faster | Samsung EVO+ or SanDisk Ultra recommended |
| **Power Supply** | Official Raspberry Pi 15W USB-C | Must provide stable 5V/3A |
| **Ethernet Cable** | Cat 5e or Cat 6 | To connect Pi to your network |
| **Cooling** | Heat sinks + fan recommended | Pi can get hot during continuous operation |

### Recommended Setup

```
┌─────────────────────────────────────┐
│  Raspberry Pi 4 with case + fan    │
│  ┌─────────────────────────────┐   │
│  │  ●●●●●●  (status LEDs)      │   │
│  │  ─────────────────────────  │   │
│  │  eth0 ←────→ your network   │   │
│  └─────────────────────────────┘   │
│        │              │            │
│        ▼              ▼            │
│   Ethernet         Power          │
│   to router        (USB-C)        │
└─────────────────────────────────────┘
```

### Storage Considerations

- **32GB minimum** for basic monitoring (captures ~1 week of data)
- **64GB or more** recommended for high-traffic networks
- Use a high-quality microSD card—cheap cards fail and cause data loss
- Consider adding a USB SSD for heavy usage (more reliable than microSD)

---

## Network Prerequisites

### Understanding Your Network Setup

ARGUS works best when placed in a "monitoring" position on your network. There are two common setups:

**Option A: Pi Between Router and LAN (Inline Monitoring)**
```
Internet ←→ Router ←→ Pi ←→ Your Computers/Devices
```

**Option B: Port Mirroring (Passive Monitoring)**
```
Internet ←→ Router/Switch ←→ Pi (monitors all traffic)
          ↑
          └── Copies of all traffic go to Pi
```

Option B is recommended because:
- Pi doesn't slow down your network
- If Pi fails, your network keeps working
- Easier to maintain

### What You Need From Your Network

1. **One available Ethernet port** on your router or switch
2. **Internet access** for the Pi (to download updates and sync data)
3. **Admin access** to your router or switch (for port mirroring setup)

---

## Step-by-Step Installation

### Step 1: Prepare the Raspberry Pi

**Flash Raspberry Pi OS to your microSD card:**

1. Download [Raspberry Pi Imager](https://www.raspberrypi.com/software/)
2. Launch the imager and choose:
   - **Operating System**: Raspberry Pi OS Lite (64-bit)
   - **Storage**: Your microSD card
3. Click **Advanced Options** (gear icon) and enable:
   - ✅ Set hostname: `argus-pi`
   - ✅ Enable SSH with password authentication
   - ✅ Set username and password (remember these!)
   - ✅ Configure wireless LAN (if using WiFi, but Ethernet is recommended)
4. Click **Write** and wait for completion

**Insert the microSD card and power on the Pi.**

### Step 2: Connect to the Pi

Open a terminal on your computer and connect via SSH:

```bash
ssh your-username@argus-pi.local
```

If that doesn't work, find the Pi's IP address from your router and use:

```bash
ssh your-username@192.168.x.x
```

**Default password:** Enter the password you set during flashing.

### Step 3: Update the Pi

Run these commands to update your system:

```bash
sudo apt update && sudo apt upgrade -y
```

This takes 5-10 minutes depending on your internet speed.

### Step 4: Install ARGUS

**Download the latest release:**

```bash
cd /tmp
curl -LO https://github.com/Ojas-bb/Argus_V/releases/latest/download/argus_v-v0.1.0.tar.gz
```

**Verify the download (recommended):**

```bash
curl -LO https://github.com/Ojas-bb/Argus_V/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
```

You should see "argus_v-v0.1.0.tar.gz: OK"

**Extract and install:**

```bash
tar xzf argus_v-v0.1.0.tar.gz
cd argus_v-v0.1.0
sudo ./install.sh
```

### Step 5: Follow the Interactive Prompts

The installer will ask you several questions:

```
ARGUS v0 Installer
==================

Step 1: Network Interface Selection
------------------------------------
Which network interface should ARGUS monitor?
  [1] eth0  (primary ethernet)
  [2] wlan0 (wireless)
  [3] eth1  (usb ethernet adapter)

Enter number (1-3): 1

Step 2: Component Selection
---------------------------
Enable Retina (packet capture)? [Y/n]: Y
Enable Mnemosyne (model training)? [Y/n]: n
Enable Aegis (threat blocking)? [Y/n]: Y

Step 3: Firebase Configuration
------------------------------
Do you have Firebase credentials? [y/N]: N

Step 4: Dry-Run Mode
--------------------
Aegis will run in DRY-RUN mode for 7 days.
This means it will log threats but NOT block them.
After 7 days, you can choose to enable blocking.
Enable dry-run mode? [Y/n]: Y

Installation complete!
```

---

## Initial Configuration

### Firebase Credentials Setup (Optional)

If you want cloud features (model updates, centralized logging):

1. Create a Firebase project at https://console.firebase.google.com
2. Enable **Cloud Storage** in your project
3. Download your service account JSON key file
4. Copy the key to the Pi:

```bash
scp your-service-account.json pi@argus-pi.local:/tmp/
ssh pi@argus-pi.local
sudo mv /tmp/service-account.json /etc/argus_v/firebase-key.json
sudo chmod 600 /etc/argus_v/firebase-key.json
```

5. Edit the configuration:

```bash
sudo nano /etc/argus_v/aegis.yaml
```

Find and update these sections:

```yaml
interfaces:
  firebase:
    enabled: true

firebase:
  project_id: "your-project-id"
  storage_bucket: "your-project.appspot.com"
  service_account_path: "/etc/argus_v/firebase-key.json"
```

### Network Interface Selection

ARGUS needs to know which network interface to monitor. To see available interfaces:

```bash
ip link show
```

Common interface names:
- `eth0` - Primary Ethernet port (most common)
- `wlan0` - WiFi interface
- `eth1` - USB Ethernet adapter

Update the interface in Retina configuration:

```bash
sudo nano /etc/argus_v/retina.yaml
```

```yaml
retina:
  enabled: true
  
  capture:
    interface: "eth0"        # Change this to match your interface
    promiscuous: true        # Must be true for monitoring
```

### Understanding Dry-Run Mode

**What is dry-run mode?**

When you first install ARGUS, it runs in "dry-run" mode for 7 days. This means:

- ✅ ARGUS **detects** and **logs** suspicious activity
- ❌ ARGUS **does NOT block** any traffic
- ✅ You can review logs and adjust sensitivity

**Why is this important?**

- Lets you see what ARGUS considers "suspicious"
- Prevents false positives from blocking legitimate traffic
- Gives you time to tune the system

**After 7 days:**

You can enable active blocking by editing the configuration:

```bash
sudo nano /etc/argus_v/aegis.yaml
```

Change:

```yaml
enforcement:
  dry_run_duration_days: 7
  enforce_after_dry_run: true  # Change from false to true
```

---

## Verification Checklist

After installation, run through this checklist to verify everything works.

### Check 1: Services Are Running

```bash
# Check Retina service
sudo systemctl status argus-retina

# Check Aegis service
sudo systemctl status argus-aegis

# Check both services
sudo systemctl status "argus-*"
```

You should see "active (running)" for each service.

### Check 2: Model Is Loaded

```bash
# Check model loading
sudo journalctl -u argus-aegis | grep -i "model"
```

Look for messages like:
```
Model loaded successfully from /var/lib/argus_v/models/
```

### Check 3: First Flows Are Captured

```bash
# Check for captured data
ls -la /var/lib/argus_v/retina/
```

You should see CSV files being created:
```
-rw-r--r-- 1 root argus  12345 Dec 31 10:00 flows_20241231_100000.csv
```

### Check 4: Verify Network Interface

```bash
# Verify interface is in promiscuous mode
ip link show eth0 | grep PROMISC
```

You should see "PROMISC" in the output.

### Check 5: Test Detection

Generate some test traffic (optional):

```bash
# From another computer on the network
ping -c 10 8.8.8.8
curl https://example.com
```

Check the logs:

```bash
sudo journalctl -u argus-retina -f
```

You should see network flows being captured and logged.

---

## Common Issues and Troubleshooting

### Issue: "Pi Cannot Reach Firebase"

**Symptoms:**
- Model updates fail
- Error messages about network connection

**Troubleshooting Steps:**

**Step 1: Check internet connectivity**

```bash
ping -c 4 8.8.8.8
```

If this fails, check your Ethernet cable and router.

**Step 2: Check DNS resolution**

```bash
# Try resolving a domain name
nslookup google.com
```

If this fails, your DNS settings may be wrong. Check `/etc/resolv.conf`:

```bash
cat /etc/resolv.conf
```

Should contain nameservers like:
```
nameserver 8.8.8.8
nameserver 8.8.4.4
```

**Step 3: Check firewall rules**

```bash
# See if outbound HTTPS is blocked
sudo iptables -L OUTPUT -n
```

If you see rules blocking port 443, you'll need to adjust your firewall.

**Step 4: Verify Firebase endpoint**

```bash
# Test connection to Firebase
curl -I https://firebasestorage.googleapis.com
```

**Solutions:**

1. If behind a proxy, configure proxy settings:
   ```bash
   export http_proxy="http://proxy.yourorg.com:8080"
   export https_proxy="http://proxy.yourorg.com:8080"
   ```

2. If DNS is broken, add Google DNS:
   ```bash
   sudo sh -c 'echo "nameserver 8.8.8.8" >> /etc/resolv.conf'
   ```

---

### Issue: "Model Fails to Load"

**Symptoms:**
- Aegis service fails to start
- Error messages about model corruption or missing files

**Troubleshooting Steps:**

**Step 1: Check available disk space**

```bash
df -h
```

If any partition shows >90% usage, free up space:
- Delete old log files: `sudo rm /var/log/argus_v/*.log.*`
- Clear old CSV files: `sudo rm /var/lib/argus_v/retina/*.csv`

**Step 2: Check file permissions**

```bash
# Model directory should be readable
ls -la /var/lib/argus_v/models/
ls -la /var/lib/argus_v/scalers/
```

If you see "permission denied," fix permissions:
```bash
sudo chown -R argus:argus /var/lib/argus_v/
```

**Step 3: Check for corrupted files**

```bash
# Look for incomplete downloads
ls -la /var/lib/argus_v/models/ | grep.part
# If any .part files exist, delete them
sudo rm /var/lib/argus_v/models/*.part
```

**Step 4: Re-download the model**

```bash
# Stop Aegis
sudo systemctl stop argus-aegis

# Clear model cache
sudo rm -rf /var/lib/argus_v/models/*
sudo rm -rf /var/lib/argus_v/scalers/*

# Restart Aegis
sudo systemctl start argus-aegis
```

---

### Issue: "No Packets Captured"

**Symptoms:**
- CSV files are not being created
- Logs show no network flows
- Capture engine appears to run but captures nothing

**Troubleshooting Steps:**

**Step 1: Verify interface name**

```bash
# List all interfaces
ip link show

# Common names: eth0, enxb827eb..., wlan0
```

Update your config if the interface name is different:
```bash
sudo nano /etc/argus_v/retina.yaml
```

**Step 2: Check promiscuous mode**

```bash
# Manually enable promiscuous mode
sudo ip link set eth0 promisc on

# Verify it's enabled
ip link show eth0
```

**Step 3: Test with tcpdump**

```bash
# Try capturing with tcpdump (5 packets is enough)
sudo tcpdump -i eth0 -c 5
```

If tcpdump works but ARGUS doesn't, there's a configuration issue.

If tcpdump also captures nothing:
- Interface may be wrong
- Traffic may not be passing through this interface
- Network switch may need port mirroring configured

**Step 4: Check if another process is capturing**

```bash
# See what processes are using the network interface
sudo lsof -i eth0
```

**Step 5: Verify Retina is actually capturing**

```bash
# Manually run a short capture test
sudo systemctl stop argus-retina
sudo timeout 30 /opt/argus_v/venv/bin/python -m argus_v.retina.cli \
  --config /etc/argus_v/retina.yaml test
sudo systemctl start argus-retina
```

---

### Issue: "High False Positive Rate"

**Symptoms:**
- Too many alerts for normal activity
- Legitimate traffic being flagged as suspicious

**Understanding the Problem:**

False positives happen when the model doesn't understand your "normal" network traffic patterns. This is common when:
- You first install ARGUS (it hasn't learned your patterns yet)
- Your network has unique traffic patterns
- The sensitivity threshold is set too low

**Solutions:**

**Step 1: Extend the dry-run period**

```bash
sudo nano /etc/argus_v/aegis.yaml
```

```yaml
enforcement:
  dry_run_duration_days: 14  # Extend from 7 to 14 days
  enforce_after_dry_run: false
```

The longer ARGUS runs in monitoring mode, the better it learns your network.

**Step 2: Adjust the anomaly threshold**

```bash
sudo nano /etc/argus_v/aegis.yaml
```

```yaml
prediction:
  anomaly_threshold: 0.75   # Increase from 0.70 (more lenient)
  high_risk_threshold: 0.95 # Increase from 0.90
```

Higher values = fewer false positives, but may miss some threats.

**Step 3: Review flagged traffic**

```bash
# Look at what's being flagged
grep -r "anomaly" /var/log/argus_v/aegis.log | head -20
```

Identify patterns in false positives and adjust network behavior or thresholds.

**Step 4: Retrain the model**

If you have Mnemosyne enabled:

```bash
# Trigger a model retrain
sudo systemctl start argus-mnemosyne.service
```

**Step 5: Contact Support**

If false positives persist after 2 weeks, gather logs and contact the support team for assistance tuning your configuration.

---

## Daily Operations

### Starting ARGUS

```bash
sudo systemctl start argus-retina
sudo systemctl start argus-aegis
```

### Stopping ARGUS

```bash
sudo systemctl stop argus-retina
sudo systemctl stop argus-aegis
```

### Viewing Logs in Real-Time

```bash
# Watch Retina logs
sudo journalctl -u argus-retina -f

# Watch Aegis logs
sudo journalctl -u argus-aegis -f

# Watch both (in separate terminals)
```

### Checking Service Status

```bash
# Quick status check
sudo systemctl status "argus-*"

# Detailed status
sudo systemctl status argus-retina
sudo systemctl status argus-aegis
```

---

## Emergency Procedures

### Emergency Stop (Immediate)

If ARGUS is blocking legitimate traffic:

```bash
sudo touch /var/run/argus_v/aegis.emergency
```

This immediately stops all blocking. Remove the file to resume:

```bash
sudo rm /var/run/argus_v/aegis.emergency
sudo systemctl restart argus-aegis
```

### Complete Shutdown

```bash
# Stop all services
sudo systemctl stop argus-retina argus-aegis

# Disable services (prevents auto-start)
sudo systemctl disable argus-retina argus-aegis

# Power off the Pi safely
sudo shutdown now
```

---

## Next Steps

After successful deployment:

1. **Week 1**: Monitor logs daily, adjust thresholds as needed
2. **Week 2**: Review flagged traffic patterns
3. **Week 3-4**: Decide whether to enable active blocking
4. **Monthly**: Check disk space, review logs, update if new version available

For networking configuration details, see [NETWORKING.md](NETWORKING.md).

For support information, see [SUPPORT.md](SUPPORT.md).
