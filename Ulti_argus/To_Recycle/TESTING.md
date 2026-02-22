# ARGUS_V Testing Guide

This document describes how to test the ARGUS_V installation package and scripts.

## Pre-Release Testing

### 1. Package Validation

Run the package validation script:

```bash
./test_install_package.sh
```

**Note**: This script requires `PyYAML` to be installed on the host system:
```bash
pip install PyYAML
```

This validates:
- ✓ All required files are present
- ✓ Scripts are executable and have valid syntax
- ✓ Python package structure is correct
- ✓ Configuration examples are valid YAML
- ✓ GitHub Actions workflow is valid
- ✓ CLI entry points exist
- ✓ Tarball can be created successfully

### 2. Create Test Release

Create a test release tarball:

```bash
./scripts/create_release.sh v0.1.0-test
```

This creates:
- `dist/argus_v-v0.1.0-test.tar.gz` - Release tarball
- `dist/SHA256SUMS` - Checksums file

### 3. Test Installation (Requires Root)

**WARNING**: Only test on a disposable VM or container!

Extract and install:

```bash
cd /tmp
tar xzf /path/to/argus_v-v0.1.0-test.tar.gz
cd argus_v-v0.1.0-test

# Test non-interactive installation
sudo ./install.sh --non-interactive
```

### 4. Verify Services

After installation, verify services are running:

```bash
# Check Retina service
sudo systemctl status argus-retina

# Check logs
sudo journalctl -u argus-retina -n 50

# Test packet capture (requires network traffic)
sudo /opt/argus_v/venv/bin/python -m argus_v.retina.cli \
  --config /etc/argus_v/retina.yaml test --duration 10
```

### 5. Test Uninstallation

Test the uninstall script:

```bash
cd /path/to/extracted/argus_v-v0.1.0-test
sudo ./uninstall.sh --purge
```

Verify cleanup:
```bash
# These should not exist
ls /opt/argus_v          # Should fail (not found)
ls /etc/argus_v          # Should fail (not found)
ls /var/lib/argus_v      # Should fail (not found)

# Services should be gone
systemctl status argus-retina  # Should fail (not found)
```

## Raspberry Pi Testing

### Test Environment Setup

**Recommended**: Use Raspberry Pi OS (64-bit) Bullseye or later

1. **Hardware**: Raspberry Pi 3B+ or 4
2. **OS**: Fresh Raspberry Pi OS installation
3. **Network**: Connected via Ethernet (eth0)

### Installation Test

```bash
# Download release
wget https://github.com/Ojas-bb/Argus_V/releases/download/v0.1.0/argus_v-v0.1.0.tar.gz

# Verify checksums
wget https://github.com/Ojas-bb/Argus_V/releases/download/v0.1.0/SHA256SUMS
sha256sum -c SHA256SUMS

# Extract
tar xzf argus_v-v0.1.0.tar.gz
cd argus_v-v0.1.0

# Install
sudo ./install.sh
```

### Acceptance Criteria

The installation is successful if:

1. **Install script runs without errors**
   ```bash
   # Exit code should be 0
   echo $?  # Should print: 0
   ```

2. **Services start successfully**
   ```bash
   sudo systemctl is-active argus-retina
   # Should print: active
   ```

3. **Configuration files exist**
   ```bash
   ls /etc/argus_v/retina.yaml
   ls /etc/argus_v/mnemosyne.yaml
   ls /etc/argus_v/aegis.yaml
   ```

4. **Data directories created**
   ```bash
   ls -ld /var/lib/argus_v/retina
   ls -ld /var/lib/argus_v/models
   ls -ld /var/lib/argus_v/scalers
   ```

5. **Retina captures packets**
   ```bash
   # Generate some traffic
   ping -c 10 8.8.8.8 &
   
   # Check for CSV output after 10 seconds
   sleep 10
   ls -lh /var/lib/argus_v/retina/*.csv
   
   # Should see CSV files with flow data
   ```

6. **Logs are written**
   ```bash
   sudo journalctl -u argus-retina -n 20
   # Should see startup logs and packet capture activity
   ```

7. **Uninstall cleans up properly**
   ```bash
   cd /path/to/argus_v-v0.1.0
   sudo ./uninstall.sh --yes
   
   # Services should stop
   sudo systemctl status argus-retina  # Should be inactive/not found
   
   # Config preserved (unless --purge)
   ls /etc/argus_v/  # Should still exist
   
   # Installation removed
   ls /opt/argus_v/  # Should not exist
   ```

## Automated Testing

### Docker Test (Optional)

Test installation in a Docker container:

```bash
# Create test Dockerfile
cat > Dockerfile.test << 'EOF'
FROM debian:bullseye

RUN apt-get update && apt-get install -y \
    sudo \
    systemctl \
    python3.11 \
    python3.11-dev \
    python3.11-venv \
    build-essential \
    libpcap-dev \
    git \
    curl

COPY dist/argus_v-*.tar.gz /tmp/
WORKDIR /tmp
RUN tar xzf argus_v-*.tar.gz
WORKDIR /tmp/argus_v-*

# Test non-interactive install
RUN ./install.sh --non-interactive --skip-services

CMD ["/bin/bash"]
EOF

# Build and test
docker build -f Dockerfile.test -t argus-test .
docker run --rm -it argus-test
```

## GitHub Actions Testing

The release workflow (`.github/workflows/release.yml`) runs automatically on git tags:

```bash
# Tag a release
git tag v0.1.0
git push origin v0.1.0

# GitHub Actions will:
# 1. Build the release tarball
# 2. Generate SHA256 checksums
# 3. Create a GitHub Release
# 4. Upload artifacts
```

### Manual Workflow Test

Test the workflow locally using `act`:

```bash
# Install act (GitHub Actions local runner)
# https://github.com/nektos/act

# Test release workflow
act -j build-and-release --secret GITHUB_TOKEN=fake -P ubuntu-latest=catthehacker/ubuntu:full-latest
```

## Common Issues and Solutions

### Python Version Too Old

**Problem**: System has Python 3.9 or older

**Solution**: The install script will attempt to install Python 3.11 automatically. If that fails:

```bash
# Manually install Python 3.11
sudo apt update
sudo apt install python3.11 python3.11-venv python3.11-dev
sudo ./install.sh
```

### Permission Denied

**Problem**: Script fails with permission errors

**Solution**: Ensure you're running with sudo:
```bash
sudo ./install.sh
```

### Network Interface Not Found

**Problem**: `eth0` doesn't exist

**Solution**: Edit config or use interactive install:
```bash
# List interfaces
ip link show

# Interactive install (prompts for interface)
sudo ./install.sh
```

### Service Fails to Start

**Problem**: `argus-retina` service fails

**Solution**: Check logs for details:
```bash
sudo journalctl -u argus-retina -n 50
sudo systemctl status argus-retina
```

Common causes:
- Interface name incorrect
- Python dependencies missing
- Insufficient permissions

### Firebase Errors (If Enabled)

**Problem**: Firebase authentication fails

**Solution**: Verify Firebase configuration:
```bash
# Check service account file exists
ls -l /path/to/service-account.json

# Test Firebase connectivity
sudo /opt/argus_v/venv/bin/python -c "
import firebase_admin
from firebase_admin import credentials, storage
cred = credentials.Certificate('/path/to/service-account.json')
firebase_admin.initialize_app(cred)
print('Firebase connection OK')
"
```

## Performance Testing

### Retina Throughput

Test packet capture performance:

```bash
# Generate test traffic
sudo apt install iperf3
iperf3 -s &  # Server
iperf3 -c localhost -t 30  # Client (30 seconds)

# Check drop rate
sudo journalctl -u argus-retina | grep -i "drop"
```

Expected performance on Raspberry Pi 4:
- **Packet rate**: 1000-5000 pps
- **Drop rate**: < 1%
- **CPU usage**: 10-20%
- **Memory**: 100-200 MB

### Resource Monitoring

Monitor resource usage during capture:

```bash
# CPU and memory
top -p $(pgrep -f "argus_v.retina")

# Disk usage
du -sh /var/lib/argus_v/retina

# Network stats
sudo iftop -i eth0
```

## Release Checklist

Before releasing a new version:

- [ ] All tests in `test_install_package.sh` pass
- [ ] Install script works on fresh Raspberry Pi OS
- [ ] Services start without errors
- [ ] Packet capture works
- [ ] Uninstall script cleans up properly
- [ ] Documentation is up to date
- [ ] CHANGELOG updated
- [ ] Version bumped in pyproject.toml
- [ ] Git tag created
- [ ] GitHub Release created with artifacts

## Support

If you encounter issues during testing:

1. Check the logs: `sudo journalctl -u argus-*`
2. Review INSTALL.md for troubleshooting
3. Open an issue on GitHub with test environment details
