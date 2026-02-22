# ARGUS_V Installation Guide

This guide covers installation of ARGUS_V on Raspberry Pi and other Debian-based Linux systems.

## Quick Start

```bash
# Download the latest release
curl -LO https://github.com/Ojas-bb/Argus_V/releases/latest/download/argus_v-v0.1.0.tar.gz

# Verify checksums (recommended)
curl -LO https://github.com/Ojas-bb/Argus_V/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS

# Extract
tar xzf argus_v-v0.1.0.tar.gz
cd argus_v-v0.1.0

# Run installer
sudo ./install.sh
```

## Prerequisites

### Hardware Requirements

- **Raspberry Pi 3B+ or later** (or equivalent ARM/x86_64 system)
- **2GB RAM minimum** (4GB recommended for Mnemosyne training)
- **8GB storage minimum** (depends on capture volume)
- **Network interface** for packet capture

### Software Requirements

- **Operating System**: Raspberry Pi OS (Bullseye or later), Debian 11+, or Ubuntu 20.04+
- **Python**: 3.11+ (3.8+ supported with limited functionality)
- **Root access**: Required for packet capture and iptables management

### Network Requirements

- **Network interface** with promiscuous mode support (for Retina)
- **Internet access** for package installation (optional: Firebase/GitHub integration)

### License file (NGO deployments)

For managed NGO deployments, place a license file at:

- `/opt/argus/license.txt`

During installation, the installer will:

- verify the license locally (expiry + integrity)
- attempt HTTPS verification if the license includes a verification endpoint
- fall back to **DEMO mode** if the verification endpoint is unreachable (offline install)

## Installation Methods

### Method 1: Interactive Installation (Recommended)

The interactive installer guides you through configuration:

```bash
sudo ./install.sh
```

You'll be prompted for:
- Network interface to monitor
- Which components to enable (Retina, Mnemosyne, Aegis)
- Firebase configuration (if needed)
- IP anonymization salt (auto-generated if not provided)

### Method 2: Non-Interactive Installation

For automated deployments, use non-interactive mode with defaults:

```bash
sudo ./install.sh --non-interactive
```

Default configuration:
- Interface: `eth0`
- Retina: **Enabled**
- Mnemosyne: Disabled
- Aegis: Disabled
- Firebase: Disabled

### Method 3: Custom Installation with Environment Variables

Override defaults using environment variables:

```bash
# Custom repository location (for development)
export ARGUS_REPO_URL="https://github.com/yourusername/Argus_V.git"
export ARGUS_REPO_REF="develop"

sudo -E ./install.sh --non-interactive
```

## Installation Options

### Command-Line Flags

```
--non-interactive     Use default values without prompts
--skip-dependencies   Skip system package installation
--skip-services       Skip systemd service creation
--uninstall           Uninstall ARGUS_V
--help                Show help message
```

### Examples

```bash
# Install with custom interface (interactive)
sudo ./install.sh
# Then enter 'wlan0' when prompted

# Minimal install (no services)
sudo ./install.sh --skip-services

# Development install (skip dependencies)
sudo ./install.sh --skip-dependencies
```

## Component Overview

### Retina - Packet Capture Service

**Purpose**: Captures and aggregates network traffic into CSV files

**Requirements**:
- Root privileges (raw socket access)
- Network interface with promiscuous mode

**Configuration**: `/etc/argus_v/retina.yaml`

**Service**: `argus-retina.service`

**Data Output**: `/var/lib/argus_v/retina/*.csv`

### Mnemosyne - Model Training Pipeline

**Purpose**: Trains anomaly detection models from captured traffic

**Requirements**:
- Firebase integration (for distributed training)
- Sufficient training data (1000+ samples)

**Configuration**: `/etc/argus_v/mnemosyne.yaml`

**Service**: `argus-mnemosyne.service` (triggered weekly via timer)

**Model Output**: Uploaded to Firebase Storage

### Aegis - Enforcement Runtime

**Purpose**: Applies anomaly detection models and enforces blacklist rules

**Requirements**:
- Root privileges (iptables management)
- Retina service running
- Trained models (from Mnemosyne)

**Configuration**: `/etc/argus_v/aegis.yaml`

**Service**: `argus-aegis.service`

**Enforcement**: iptables DROP rules (7-day dry-run by default)

## Post-Installation

### Verify Installation

Check service status:

```bash
# Check all ARGUS services
sudo systemctl status argus-retina
sudo systemctl status argus-aegis
sudo systemctl list-timers argus-*

# View logs
sudo journalctl -u argus-retina -f
sudo journalctl -u argus-aegis -f
```

### Test Retina Capture

```bash
# Test packet capture for 30 seconds
sudo systemctl stop argus-retina
sudo /opt/argus_v/venv/bin/python -m argus_v.retina.cli \
  --config /etc/argus_v/retina.yaml test --duration 30
sudo systemctl start argus-retina
```

### Validate Configurations

```bash
# Validate Retina config
sudo /opt/argus_v/venv/bin/python -m argus_v.retina.cli \
  --config /etc/argus_v/retina.yaml validate

# Validate Mnemosyne setup
sudo /opt/argus_v/venv/bin/python -m argus_v.mnemosyne.cli \
  --config /etc/argus_v/mnemosyne.yaml validate

# Validate Aegis config
sudo /opt/argus_v/venv/bin/python -m argus_v.aegis.cli \
  --config /etc/argus_v/aegis.yaml validate
```

### Enable Additional Components

If you installed with defaults, you can manually enable additional components:

```bash
# Enable Aegis after testing Retina
sudo vi /etc/argus_v/aegis.yaml
# Update configuration as needed

sudo systemctl enable argus-aegis
sudo systemctl start argus-aegis

# Enable Mnemosyne weekly training
sudo systemctl enable argus-mnemosyne.timer
sudo systemctl start argus-mnemosyne.timer
```

## Directory Structure

After installation:

```
/opt/argus_v/              # Installation directory
  ├── venv/                # Python virtual environment
  └── src/                 # Source code (if installed from source)

/etc/argus_v/              # Configuration files
  ├── retina.yaml
  ├── mnemosyne.yaml
  └── aegis.yaml

/var/lib/argus_v/          # Data directory
  ├── retina/              # CSV output from packet capture
  ├── models/              # Downloaded models (Aegis)
  ├── scalers/             # Downloaded scalers (Aegis)
  └── aegis/               # Aegis state and blacklist DB

/var/log/argus_v/          # Log files
  ├── retina.log
  ├── mnemosyne.log
  └── aegis.log

/var/run/argus_v/          # Runtime files (PIDs, sockets)
```

## Configuration

### Retina Configuration

Edit `/etc/argus_v/retina.yaml`:

```yaml
retina:
  enabled: true
  
  capture:
    interface: "eth0"        # Your network interface
    snaplen: 65535
    promiscuous: true
    use_scapy: true
  
  aggregation:
    window_seconds: 5        # Aggregation window
    output_dir: "/var/lib/argus_v/retina"
    max_rows_per_file: 10000
  
  # IMPORTANT: Keep this secret!
  ip_salt: "your-random-salt-here"
```

Restart after changes:
```bash
sudo systemctl restart argus-retina
```

### Firebase Integration

1. Create a Firebase project at https://console.firebase.google.com
2. Enable Firebase Storage
3. Download service account JSON key
4. Update configurations:

```yaml
# In aegis.yaml and mnemosyne.yaml
interfaces:
  firebase:
    enabled: true

firebase:
  project_id: "your-project-id"
  storage_bucket: "your-project.appspot.com"
  service_account_path: "/path/to/service-account.json"
```

### Network Interface Selection

List available interfaces:

```bash
ip link show
# or
sudo /opt/argus_v/venv/bin/python -m argus_v.retina.cli interfaces
```

Update Retina config with chosen interface.

## Security Considerations

### Permissions

- **Retina**: Runs as root (requires raw socket access)
- **Aegis**: Runs as root (requires iptables management)
- **Mnemosyne**: Runs as `argus` user (no special privileges)

### Data Protection

- **IP Anonymization**: All IP addresses are hashed with configurable salt
- **Configuration Security**: Config files contain sensitive data (Firebase keys, IP salt)
  - Keep `/etc/argus_v/` restricted to root
  - Never commit actual config files to version control

### Dry-Run Mode

Aegis enforces a **7-day mandatory dry-run period** before enforcement:
- All anomalies are logged but not blocked
- Review logs before enabling enforcement
- Set `enforce_after_dry_run: true` in `/etc/argus_v/aegis.yaml` to enable after dry-run

### Emergency Stop

Create emergency stop file to immediately disable Aegis enforcement:

```bash
sudo touch /var/run/argus_v/aegis.emergency
```

Remove file and restart to re-enable:

```bash
sudo rm /var/run/argus_v/aegis.emergency
sudo systemctl restart argus-aegis
```

## Troubleshooting

### Installation Issues

**Python version too old:**
```bash
# Install Python 3.11 on Raspberry Pi OS
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev
# Re-run installer
```

**Permission denied:**
```bash
# Ensure you're running with sudo
sudo ./install.sh
```

**Dependency installation fails:**
```bash
# Update package lists first
sudo apt update
sudo apt upgrade
# Try again
sudo ./install.sh
```

### Runtime Issues

**Retina fails to start:**
```bash
# Check interface name
ip link show

# Test interface access
sudo tcpdump -i eth0 -c 10

# Check permissions
sudo journalctl -u argus-retina -n 50
```

**Aegis can't download models:**
```bash
# Verify Firebase configuration
sudo /opt/argus_v/venv/bin/python -m argus_v.aegis.cli \
  --config /etc/argus_v/aegis.yaml validate

# Check service account permissions
# Ensure service account has Storage Object Viewer role
```

**High memory usage:**
```bash
# Reduce capture window or batch size in retina.yaml
aggregation:
  window_seconds: 5        # Reduce if needed
  max_rows_per_file: 5000  # Reduce if needed

# Restart service
sudo systemctl restart argus-retina
```

### Log Analysis

View real-time logs:
```bash
sudo journalctl -u argus-retina -f
sudo journalctl -u argus-aegis -f
sudo journalctl -u argus-mnemosyne -f
```

View recent errors:
```bash
sudo journalctl -u argus-retina -p err -n 50
```

## Uninstallation

### Interactive Uninstall

```bash
cd /path/to/argus_v
sudo ./uninstall.sh
```

You'll be prompted to remove:
- Configuration files
- Data directories
- Log files

### Complete Removal

Remove everything including data:

```bash
sudo ./uninstall.sh --purge
```

### Preserve Data

Uninstall but keep configuration and data:

```bash
sudo ./uninstall.sh --yes
```

## Upgrading

To upgrade ARGUS_V:

1. Stop services:
   ```bash
   sudo systemctl stop argus-retina argus-aegis
   sudo systemctl stop argus-mnemosyne.timer
   ```

2. Backup configuration:
   ```bash
   sudo tar -czf /tmp/argus_config_backup.tar.gz /etc/argus_v/
   ```

3. Download new release and extract

4. Run installer:
   ```bash
   sudo ./install.sh --skip-services
   ```

5. Restore configuration (if needed), then restart:
   ```bash
   sudo systemctl start argus-retina argus-aegis
   ```

## Development Installation

For development work:

```bash
# Clone repository
git clone https://github.com/Ojas-bb/Argus_V.git
cd Argus_V

# Install in development mode
python3 -m venv venv
source venv/bin/activate
pip install -e .

# Run tests
pytest

# Run directly without installation
python -m argus_v.retina.cli --help
```

## Support and Documentation

- **Main README**: `README.md`
- **Component Documentation**: `README.Docs/`
- **Compliance**: `README.COMPLIANCE.md`
- **GitHub Issues**: https://github.com/Ojas-bb/Argus_V/issues

## License

ARGUS_V is licensed under the MIT License. See `LICENSE` file for details.
