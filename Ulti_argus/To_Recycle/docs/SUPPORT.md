# ARGUS Support Guide

This guide helps you troubleshoot issues, collect debug information, and contact support when needed.

---

## How to Report Issues

### Before You Report

Try these quick fixes first:

1. **Restart the services:**
   ```bash
   sudo systemctl restart argus-retina argus-aegis
   ```

2. **Check if services are running:**
   ```bash
   sudo systemctl status argus-retina argus-aegis
   ```

3. **Review recent logs:**
   ```bash
   sudo journalctl -p err -n 50 --no-pager
   ```

### What to Include in Your Report

When you contact support, include this information:

**1. Basic Information**
```
- ARGUS version: (check with) cat /opt/argus_v/VERSION
- Raspberry Pi model: Pi 4 8GB / Pi 4 4GB / Pi 3B+
- Operating system: Raspberry Pi OS X.X
- Date of installation: [when you installed ARGUS]
```

**2. Problem Description**
```
- What were you trying to do?
- What happened? (exact error messages)
- When did it start happening?
- What changed recently? (updates, config changes, network changes)
```

**3. System Information**
```bash
# Copy the output of these commands:
cat /etc/os-release
free -h
df -h
ip addr show | grep inet
```

**4. Logs**
```bash
# Save all logs to a file
sudo journalctl -u argus-retina -u argus-aegis --since "2 days ago" > ~/argus-logs.txt
```

**5. Configuration Files**
```bash
# Copy configuration (remove sensitive data first)
cat /etc/argus_v/retina.yaml
cat /etc/argus_v/aegis.yaml
```

### Example Support Request

```
SUBJECT: ARGUS not capturing packets on Pi 4

DESCRIPTION:
After installation, no traffic is being captured. The services appear to run
but no CSV files are created.

STEPS TAKEN:
1. Restarted services - same issue
2. Checked disk space - 40% available
3. Ran tcpdump - captures traffic fine

ENVIRONMENT:
- Raspberry Pi 4 8GB
- Raspberry Pi OS 64-bit (Bullseye)
- ARGUS v0.1.0
- Network: eth0, inline deployment

ATTACHED FILES:
- argus-logs.txt (from journalctl)
- retina.yaml (configuration)
```

---

## Log File Locations

### Main Log Directory

```
/var/log/argus_v/
├── retina.log         # Packet capture logs
├── retina.log.1       # Previous log file
├── retina.log.*.gz    # Compressed old logs
├── aegis.log          # Enforcement logs
├── aegis.log.1
├── aegis.log.*.gz
├── mnemosyne.log      # Model training logs (if enabled)
└── mnemosyne.log.*.gz
```

### Viewing Logs

**View Retina logs:**
```bash
# Show all Retina logs
sudo cat /var/log/argus_v/retina.log

# View with pagination
sudo less /var/log/argus_v/retina.log

# Show last 100 lines
sudo tail -100 /var/log/argus_v/retina.log
```

**View Aegis logs:**
```bash
sudo cat /var/log/argus_v/aegis.log
sudo tail -f /var/log/argus_v/aegis.log  # Real-time view
```

### Systemd Journal Logs

ARGUS services log to systemd's journal, which provides additional features.

**View all ARGUS logs:**
```bash
# All services, all entries
sudo journalctl -u argus-retina -u argus-aegis

# Real-time view
sudo journalctl -u argus-aegis -f

# Last 50 entries, errors only
sudo journalctl -u argus-retina -p err -n 50

# Since a specific time
sudo journalctl -u argus-aegis --since "2024-01-15 10:00:00"

# Since last boot
sudo journalctl -u argus-retina --boot=-1
```

**Export logs for support:**
```bash
# All ARGUS logs from the last 7 days
sudo journalctl -u argus-retina -u argus-aegis --since "7 days ago" > ~/argus-support-logs.txt

# Compress for email
gzip -c ~/argus-support-logs.txt > ~/argus-support-logs.txt.gz
```

### Service-Specific Logs

**Retina (packet capture):**
```bash
sudo journalctl -u argus-retina -f
```
Look for: capture started, packets captured, CSV file creation

**Aegis (enforcement):**
```bash
sudo journalctl -u argus-aegis -f
```
Look for: model loaded, anomalies detected, enforcement actions

**Mnemosyne (training):**
```bash
sudo journalctl -u argus-mnemosyne -f
```
Look for: training started, model saved, upload complete

---

## Collecting Debug Information

### Quick Debug Script

Run this script to collect all necessary information for troubleshooting:

```bash
#!/bin/bash
# Save as debug-argus.sh and run with: sudo bash debug-argus.sh

OUTPUT="argus-debug-$(date +%Y%m%d-%H%M%S).tar.gz"

echo "Collecting ARGUS debug information..."

# Create temporary directory
DEBUG_DIR=$(mktemp -d)
cd "$DEBUG_DIR"

# System information
echo "=== System Information ===" > system-info.txt
uname -a >> system-info.txt
cat /etc/os-release >> system-info.txt
free -h >> system-info.txt
df -h >> system-info.txt

# Network information
echo "=== Network Information ===" > network-info.txt
ip addr >> network-info.txt
ip route >> network-info.txt
ip link >> network-info.txt

# Service status
echo "=== Service Status ===" > service-status.txt
systemctl status argus-retina >> service-status.txt 2>&1
systemctl status argus-aegis >> service-status.txt 2>&1

# Logs
echo "=== Recent Logs (last 500 lines) ===" > logs.txt
journalctl -u argus-retina -u argus-aegis -n 500 >> logs.txt 2>&1

# Configuration
echo "=== Configuration Files ===" > configs
cp /etc/argus_v/retina.yaml configs/
cp /etc/argus_v/aegis.yaml configs/
if [ -f /etc/argus_v/mnemosyne.yaml ]; then
    cp /etc/argus_v/mnemosyne.yaml configs/
fi

# Data directories
echo "=== Data Directory Status ===" > data-status.txt
ls -la /var/lib/argus_v/retina/ >> data-status.txt 2>&1
ls -la /var/lib/argus_v/models/ >> data-status.txt 2>&1

# Performance stats
echo "=== Performance Stats ===" > perf-stats.txt
ps aux | grep argus >> perf-stats.txt
top -bn1 | head -20 >> perf-stats.txt

# Compress everything
tar -czf "$OUTPUT" .
echo "Debug files saved to: $OUTPUT"
echo "Please attach this file to your support request."
```

### Manual Debug Collection

If you prefer to collect information manually:

```bash
# Create a directory for debug files
mkdir ~/argus-debug
cd ~/argus-debug

# Save system info
uname -a > system-info.txt
cat /etc/os-release >> system-info.txt
free -h >> system-info.txt
df -h >> system-info.txt

# Save network info
ip addr > network-info.txt
ip route >> network-info.txt

# Save service status
systemctl status argus-retina > service-retina.txt 2>&1
systemctl status argus-aegis > service-aegis.txt 2>&1

# Save logs (last 1000 lines)
journalctl -u argus-retina -u argus-aegis -n 1000 > all-logs.txt

# Save configurations
cp /etc/argus_v/retina.yaml retina-config.yaml
cp /etc/argus_v/aegis.yaml aegis-config.yaml

# Save network stats
ip -s link > network-stats.txt

# Compress
tar -czf argus-debug-$(date +%Y%m%d).tar.gz .
```

### What to Send to Support

| Information | Why We Need It |
|-------------|----------------|
| System info | Identify hardware/OS compatibility issues |
| Logs | Understand what went wrong and when |
| Configuration | Check for misconfiguration |
| Network info | Verify network setup is correct |
| Error messages | Exact wording helps identify the problem |

**DO NOT SEND:**
- Passwords or API keys (redact from configs)
- Sensitive network data (internal IPs, hostnames are fine)
- Packet captures (they may contain sensitive data)

---

## Expected Performance Metrics

### Healthy System Metrics

**CPU Usage:**
| State | Expected Range | Notes |
|-------|----------------|-------|
| Idle | 2-5% | Normal when no traffic |
| Normal operation | 15-35% | With moderate traffic |
| High traffic | 40-60% | May approach 80% during analysis bursts |
| Problematic | >80% sustained | Indicates performance issues |

**Memory Usage:**
| State | Expected Range | Notes |
|-------|----------------|-------|
| Idle | 1.5-2.0 GB | After boot, no traffic |
| Normal | 2.5-4.0 GB | With active monitoring |
| Heavy load | 5-7 GB | High traffic, full analysis |
| Problematic | >7 GB or swap used | May cause crashes |

**Disk Usage:**
```
Filesystem      Size  Used Avail Use% Mounted on
/dev/root        58G   12G   44G  22% /
```

Expected growth:
- **Light traffic**: 10-20 MB per day
- **Medium traffic**: 50-100 MB per day
- **Heavy traffic**: 200-500 MB per day

**Network Throughput:**
- Captured traffic depends on your network volume
- Pi should handle up to 500 Mbps sustained
- Watch for packet drops at high speeds

### Checking Performance

**Quick health check:**
```bash
# One-liner summary
top -bn1 | head -5; free -h; df -h /

# Detailed CPU/memory
htop

# Disk I/O
iostat -x 1

# Network throughput
nload -u M
```

**Monitor over time:**
```bash
# Check every 5 minutes, 100 times
watch -n 300 'echo "=== CPU ===" && top -bn1 | head -3 && echo "=== Memory ===" && free -h && echo "=== Disk ===" && df -h /'
```

### Performance Thresholds

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| CPU | >60% | >80% for 10+ min | Reduce capture window, add cooling |
| Memory | >70% | >85% | Reduce batch size, add RAM |
| Disk | >70% | >85% | Delete old CSV/log files |
| Temperature | >70°C | >80°C | Add cooling, improve ventilation |
| Packet drops | >1% | >5% | Reduce traffic, faster SPAN port |

### Temperature Monitoring

```bash
# Check current temperature
vcgencmd measure_temp

# Check throttling
vcgencmd get_throttled
```

Temperature reference:
- 40-50°C: Excellent
- 50-65°C: Good
- 65-75°C: Acceptable, monitor closely
- 75-85°C: Add cooling
- 85°C+: Throttling active, performance degraded

---

## Support Contact Information

### Before Contacting Support

1. Check this documentation (you are here!)
- Review [DEPLOYMENT.md](DEPLOYMENT.md) for installation issues
- Review [NETWORKING.md](NETWORKING.md) for network problems

2. Check common issues in the troubleshooting sections above

3. Collect debug information as described above

4. Search existing issues (if applicable)

### How to Contact

**Email Support:**
```
Email: support@argus-security.example
Response time: 24-48 business hours
Include: See "What to Include in Your Report" above
```

**Emergency Support:**
```
For critical production issues:
Email: emergency@argus-security.example
Phone: [Your emergency number]
Available: 24/7 for production outages
```

### What to Expect

| Issue Type | First Response | Resolution |
|------------|----------------|------------|
| Installation problems | 24 hours | 1-3 business days |
| Configuration help | 24 hours | 1-2 business days |
| Performance issues | 24 hours | 2-5 business days |
| Suspected bugs | 24 hours | 1-2 weeks |
| Security vulnerabilities | Immediate | 24-48 hours |

### Information to Have Ready

When contacting support, please have:

- [ ] ARGUS version number
- [ ] Raspberry Pi model and RAM size
- [ ] Operating system version
- [ ] Network setup type (inline/SPAN)
- [ ] Error messages (exact text)
- [ ] Debug archive (see above)
- [ ] Steps to reproduce the issue
- [ ] What you have already tried

---

## Common Questions

### Q: How do I know if ARGUS is working?

**A:** Check these indicators:

1. Services running:
   ```bash
   sudo systemctl status argus-retina
   sudo systemctl status argus-aegis
   ```

2. CSV files being created:
   ```bash
   ls -la /var/lib/argus_v/retina/
   ```

3. Logs showing activity:
   ```bash
   sudo tail -f /var/log/argus_v/retina.log
   ```

### Q: How much data will ARGUS collect?

**A:** Depends on your network traffic:

| Network Type | Daily Data | Weekly Storage |
|--------------|------------|----------------|
| Home (5-10 devices) | 10-50 MB | 70-350 MB |
| Small office (25-50 devices) | 100-500 MB | 700 MB - 3.5 GB |
| Large office (100+ devices) | 500 MB - 2 GB | 3.5 - 14 GB |

### Q: Can I run ARGUS without internet?

**A:** Yes, but with limitations:

- ✅ Captures and analyzes traffic locally
- ✅ Blocks threats based on downloaded models
- ✅ Logs all activity
- ❌ Cannot download model updates
- ❌ Cannot sync with Firebase
- ❌ Cannot receive rule updates

### Q: How often should I update ARGUS?

**A:** Check for updates monthly:

```bash
# Check current version
cat /opt/argus_v/VERSION

# Check for updates
cd /path/to/argus_v
git fetch
git status
```

### Q: What happens if the SD card fails?

**A:** If your SD card fails:
- Configuration in `/etc/argus_v/` is lost
- Historical data in `/var/lib/argus_v/` is lost
- Models need to be re-downloaded

**Best practice:** Backup configuration regularly:
```bash
sudo tar -czf /tmp/argus-config-backup-$(date +%Y%m%d).tar.gz /etc/argus_v/
```

---

## Emergency Procedures

### Immediate Stop (Emergency Kill Switch)

If ARGUS is causing network problems:

```bash
# Stop all blocking immediately
sudo touch /var/run/argus_v/aegis.emergency

# Verify emergency mode is active
systemctl status argus-aegis
```

The emergency file immediately:
- Stops all iptables blocking rules
- Prevents new blocks
- Logs continue running

To resume normal operation:
```bash
sudo rm /var/run/argus_v/aegis.emergency
sudo systemctl restart argus-aegis
```

### Complete Shutdown

If you need to stop ARGUS completely:

```bash
# Stop services
sudo systemctl stop argus-retina argus-aegis

# Disable auto-start
sudo systemctl disable argus-retina argus-aegis

# Power off Pi (if safe to do so)
sudo shutdown now
```

### Rollback Installation

If you need to revert to a previous version:

```bash
# Backup configuration
sudo tar -czf /tmp/argus-config-backup.tar.gz /etc/argus_v/

# Run uninstall
sudo ./uninstall.sh

# Download previous version
curl -LO https://github.com/Ojas-bb/Argus_V/releases/download/vX.X.X/argus_v-vX.X.X.tar.gz

# Install previous version
tar xzf argus_v-vX.X.X.tar.gz
cd argus_v-vX.X.X
sudo ./install.sh

# Restore configuration
sudo tar -xzf /tmp/argus-config-backup.tar.gz -C /
```

---

## Quick Reference

### Essential Commands

```bash
# Service management
sudo systemctl start argus-retina argus-aegis
sudo systemctl stop argus-retina argus-aegis
sudo systemctl restart argus-retina argus-aegis
sudo systemctl status argus-retina argus-aegis

# Log viewing
sudo journalctl -u argus-retina -f
sudo journalctl -u argus-aegis -f
sudo journalctl -p err -n 50

# Health checks
sudo /opt/argus_v/venv/bin/python -m argus_v.retina.cli --config /etc/argus_v/retina.yaml validate
sudo /opt/argus_v/venv/bin/python -m argus_v.aegis.cli --config /etc/argus_v/aegis.yaml validate

# Emergency stop
sudo touch /var/run/argus_v/aegis.emergency

# Debug collection
sudo journalctl -u argus-retina -u argus-aegis --since "7 days ago" > ~/argus-logs.txt
```

### File Locations

| Purpose | Location |
|---------|----------|
| Configuration | `/etc/argus_v/*.yaml` |
| Runtime data | `/var/lib/argus_v/` |
| Logs | `/var/log/argus_v/` |
| Installation | `/opt/argus_v/` |
| Emergency stop file | `/var/run/argus_v/aegis.emergency` |

### Ports in Use

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | For remote access (your choice) |
| 8080 | Health check | Local only, not exposed |
| 443 | HTTPS | Outbound to Firebase/GitHub |

---

For installation instructions, see [DEPLOYMENT.md](DEPLOYMENT.md).

For network configuration, see [NETWORKING.md](NETWORKING.md).
