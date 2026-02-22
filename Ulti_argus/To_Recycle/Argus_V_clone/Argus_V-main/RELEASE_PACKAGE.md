# ARGUS_V Release Package Documentation

This document describes the complete release package for ARGUS_V, including installation scripts, workflows, and testing procedures.

## Package Contents

### Installation Scripts

#### `install.sh`
Comprehensive shell installer for Raspberry Pi and Debian-based systems.

**Features:**
- ✓ OS detection and compatibility checks
- ✓ Python 3.11+ detection and installation
- ✓ System dependency installation (libpcap, build tools, etc.)
- ✓ Interactive and non-interactive modes
- ✓ Network interface detection
- ✓ Firebase integration configuration
- ✓ User and directory creation
- ✓ Virtual environment setup
- ✓ Configuration file generation (Retina, Mnemosyne, Aegis)
- ✓ Systemd service creation (retina, mnemosyne timer, aegis)
- ✓ Log rotation setup
- ✓ Service enablement and startup

**Usage:**
```bash
# Interactive installation
sudo ./install.sh

# Non-interactive with defaults
sudo ./install.sh --non-interactive

# Custom repository
sudo ./install.sh --repo https://github.com/custom/fork.git --ref develop

# Skip dependency installation
sudo ./install.sh --skip-dependencies

# Skip service creation (manual service management)
sudo ./install.sh --skip-services
```

**Installation Paths:**
- Installation: `/opt/argus_v/`
- Configuration: `/etc/argus_v/`
- Data: `/var/lib/argus_v/`
- Logs: `/var/log/argus_v/`
- Runtime: `/var/run/argus_v/`

#### `uninstall.sh`
Clean removal of ARGUS_V with optional data preservation.

**Features:**
- ✓ Service stopping and disabling
- ✓ Systemd service file removal
- ✓ Optional configuration preservation
- ✓ Optional data preservation
- ✓ Configuration backup option
- ✓ iptables rule cleanup
- ✓ Complete purge mode

**Usage:**
```bash
# Interactive uninstall (prompts for data removal)
sudo ./uninstall.sh

# Quick uninstall (preserve data)
sudo ./uninstall.sh --yes

# Complete removal including all data
sudo ./uninstall.sh --purge
```

### Dependencies

#### `requirements.txt`
Pinned production dependencies compatible with Raspberry Pi.

**Core Dependencies:**
- PyYAML==6.0.2
- scapy==2.6.1
- pcapy-ng==1.0.9
- pytz==2025.2
- firebase-admin==6.6.0
- pandas==2.2.3
- numpy==2.1.3
- scikit-learn==1.5.2
- joblib==1.4.2

### Configuration Examples

#### `example-retina-config.yaml`
Template for Retina packet capture service.

**Key Settings:**
- Network interface selection
- Capture parameters (snaplen, promiscuous mode)
- Aggregation window and output directory
- Health monitoring thresholds
- IP anonymization salt

#### `mnemosyne-config.example.yaml`
Template for Mnemosyne model training pipeline.

**Key Settings:**
- Firebase storage configuration
- Preprocessing parameters (log transforms, normalization)
- Training hyperparameters (n_estimators, contamination)
- Cross-validation settings

#### `aegis-config.example.yaml`
Template for Aegis enforcement runtime.

**Key Settings:**
- Model management (download paths, timeouts)
- Retina CSV polling configuration
- Prediction thresholds (anomaly, high-risk)
- Enforcement settings (dry-run, iptables)
- Emergency stop controls

### Documentation

#### `INSTALL.md`
Comprehensive installation guide covering:
- Prerequisites and requirements
- Installation methods (interactive, non-interactive, custom)
- Component overview (Retina, Mnemosyne, Aegis)
- Post-installation verification
- Configuration details
- Troubleshooting

#### `TESTING.md`
Testing procedures including:
- Package validation
- Test release creation
- Installation testing
- Service verification
- Raspberry Pi testing
- Acceptance criteria
- Performance testing

#### `LICENSE`
MIT License for open-source distribution.

#### `README.md`
Main project documentation and quick start.

### GitHub Actions Workflow

#### `.github/workflows/release.yml`
Automated release workflow triggered on git tags.

**Workflow Steps:**
1. **Checkout** - Clone repository at tag
2. **Setup Python** - Install Python 3.11
3. **Validate requirements.txt** - Ensure pinned dependencies exist
4. **Build tarball** - Create release package with all necessary files
5. **Generate checksums** - SHA256 checksums for verification
6. **Create Release** - GitHub Release with artifacts and notes

**Trigger:**
```bash
git tag v0.1.0
git push origin v0.1.0
```

**Artifacts:**
- `argus_v-v0.1.0.tar.gz` - Release tarball
- `SHA256SUMS` - Checksum file

### Testing Scripts

#### `test_install_package.sh`
Validation script that checks:
- Required files present
- Script permissions and syntax
- Python package structure
- Configuration YAML validity
- GitHub Actions workflow validity
- CLI entry points
- Tarball creation simulation

#### `scripts/create_release.sh`
Manual release tarball creation for local testing.

**Usage:**
```bash
./scripts/create_release.sh v0.1.0-test
```

**Output:**
- `dist/argus_v-v0.1.0-test.tar.gz`
- `dist/SHA256SUMS`

## Package Structure

```
argus_v-v0.1.0/
├── install.sh                          # Main installer
├── uninstall.sh                        # Uninstaller
├── requirements.txt                    # Pinned dependencies
├── pyproject.toml                      # Python package metadata
├── LICENSE                             # MIT License
├── README.md                           # Project documentation
├── INSTALL.md                          # Installation guide
├── README.COMPLIANCE.md                # Compliance documentation
├── README.Docs/                        # Additional documentation
│   ├── Configuration.md
│   ├── Logging.md
│   ├── Retina.md
│   ├── Mnemosyne.md
│   ├── Aegis.md
│   ├── Anonymization.md
│   └── ...
├── example-retina-config.yaml          # Retina config template
├── mnemosyne-config.example.yaml       # Mnemosyne config template
├── aegis-config.example.yaml           # Aegis config template
├── configs/                            # Additional config examples
│   └── sample_free_tier.yaml
├── run_train.sh                        # Training helper script
├── run_trainer.py                      # Training entry point
└── src/                                # Python source code
    └── argus_v/
        ├── __init__.py
        ├── oracle_core/                # Core utilities
        │   ├── config.py
        │   ├── logging.py
        │   ├── validation.py
        │   ├── anonymize.py
        │   └── ...
        ├── retina/                     # Packet capture
        │   ├── cli.py
        │   ├── config.py
        │   ├── collector.py
        │   ├── daemon.py
        │   └── ...
        ├── mnemosyne/                  # Model training
        │   ├── cli.py
        │   ├── config.py
        │   ├── pipeline.py
        │   ├── trainer.py
        │   └── ...
        ├── aegis/                      # Enforcement
        │   ├── cli.py
        │   ├── config.py
        │   ├── daemon.py
        │   ├── model_manager.py
        │   ├── prediction_engine.py
        │   ├── blacklist_manager.py
        │   └── ...
        ├── athena/                     # Future: Analytics
        ├── hermes/                     # Future: Integrations
        └── nyx/                        # Future: Scheduling
```

## Installation Flow

```
1. Check Prerequisites
   ├── Root privileges
   ├── OS detection (Debian-based)
   └── Python 3.11+ (install if missing)

2. Install Dependencies
   ├── System packages (libpcap, build-essential, etc.)
   └── Python packages (from requirements.txt)

3. Create System Resources
   ├── User: argus
   ├── Directories: /opt, /etc, /var/lib, /var/log, /var/run
   └── Permissions

4. Install Python Package
   ├── Create virtual environment
   ├── Install ARGUS_V package
   └── Install additional dependencies

5. Generate Configurations
   ├── Retina config (interface, salt)
   ├── Mnemosyne config (Firebase, training)
   └── Aegis config (models, enforcement)

6. Create systemd Services
   ├── argus-retina.service (packet capture daemon)
   ├── argus-mnemosyne.service (one-shot training)
   ├── argus-mnemosyne.timer (weekly trigger)
   └── argus-aegis.service (enforcement daemon)

7. Setup Log Rotation
   └── /etc/logrotate.d/argus_v

8. Enable and Start Services
   ├── Start argus-retina (if enabled)
   ├── Start argus-mnemosyne timer (if enabled)
   └── Start argus-aegis (if enabled)

9. Verify Installation
   └── Show service status
```

## Systemd Services

### argus-retina.service
**Purpose:** Network packet capture and aggregation

**Type:** simple (long-running daemon)

**User:** root (requires raw sockets)

**Command:** `python -m argus_v.retina.cli --config /etc/argus_v/retina.yaml daemon`

**Restart:** always (restarts on failure)

**Dependencies:** network.target

### argus-mnemosyne.service
**Purpose:** Model training pipeline execution

**Type:** oneshot (runs once per invocation)

**User:** argus

**Command:** `python -m argus_v.mnemosyne.cli --config /etc/argus_v/mnemosyne.yaml train`

**Trigger:** argus-mnemosyne.timer (weekly on Sunday 2 AM)

### argus-aegis.service
**Purpose:** Anomaly detection and enforcement

**Type:** simple (long-running daemon)

**User:** root (requires iptables management)

**Command:** `python -m argus_v.aegis.cli --config /etc/argus_v/aegis.yaml start`

**Restart:** always (restarts on failure)

**Dependencies:** network.target, argus-retina.service

## Security Considerations

### Installation Security
- Runs with root privileges (required for raw sockets and iptables)
- Virtual environment isolates dependencies
- Configuration files restricted to root (600 permissions)
- Service accounts use minimal privileges where possible

### Data Protection
- IP addresses anonymized with configurable salt
- Salt stored in config (keep secret!)
- Firebase credentials use environment variables
- No plaintext secrets in logs

### Enforcement Safety
- **7-day mandatory dry-run period** before enforcement
- Emergency stop file mechanism (`/var/run/argus_v/aegis.emergency`)
- Manual override controls
- Enforcement can be disabled without stopping service

## Upgrade Procedure

To upgrade an existing installation:

```bash
# 1. Stop services
sudo systemctl stop argus-retina argus-aegis
sudo systemctl stop argus-mnemosyne.timer

# 2. Backup configuration
sudo tar -czf /tmp/argus_config_backup.tar.gz /etc/argus_v/

# 3. Extract new release
tar xzf argus_v-v0.2.0.tar.gz
cd argus_v-v0.2.0

# 4. Run installer (skip services to preserve configs)
sudo ./install.sh --skip-services

# 5. Review and merge configuration changes
sudo diff -u /tmp/old_config.yaml /etc/argus_v/new_config.yaml

# 6. Restart services
sudo systemctl daemon-reload
sudo systemctl start argus-retina argus-aegis
```

## Troubleshooting

### Installation Fails

**Issue:** Python 3.11 not available
```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev
```

**Issue:** Permission denied
```bash
# Ensure running with sudo
sudo ./install.sh
```

**Issue:** Network interface not found
```bash
# List available interfaces
ip link show

# Use interactive install to select interface
sudo ./install.sh
```

### Service Failures

**Issue:** argus-retina fails to start
```bash
# Check logs
sudo journalctl -u argus-retina -n 50

# Test manually
sudo /opt/argus_v/venv/bin/python -m argus_v.retina.cli \
  --config /etc/argus_v/retina.yaml test
```

**Issue:** Permission errors
```bash
# Check directory ownership
sudo chown -R argus:argus /var/lib/argus_v
sudo chown -R root:root /etc/argus_v
```

## Support

- **Documentation:** `INSTALL.md`, `TESTING.md`, `README.Docs/`
- **Issues:** https://github.com/Ojas-bb/Argus_V/issues
- **Logs:** `sudo journalctl -u argus-*`

## License

ARGUS_V is released under the MIT License. See `LICENSE` file for details.

## Version History

- **v0.1.0** - Initial release
  - Complete installation system
  - Retina packet capture
  - Mnemosyne training pipeline
  - Aegis enforcement runtime
  - Raspberry Pi support
