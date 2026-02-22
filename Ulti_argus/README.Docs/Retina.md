# Argus_V Retina Collector MVP

## Overview

The Argus_V Retina module provides a robust CLI/daemon system for network packet capture and analysis. It uses scapy with pcapy fallback to capture packets, aggregates them into 5-second windows, and writes rotating CSV files with mythological naming for subsequent Firebase upload.

## Features

- **Multi-engine packet capture**: Primary scapy support with pcapy fallback
- **Graceful interface handling**: Automatic detection and recovery from NIC issues
- **Window-based aggregation**: 5-second windows with packet/byte counting and rate computation
- **Anonymization**: IP address hashing using configurable salt
- **Rotating CSV storage**: Mythological naming scheme with automatic rotation
- **Health monitoring**: Drop rate tracking, queue monitoring, and alert system
- **Firebase staging**: Automated staging of CSVs for cloud upload
- **Raspberry Pi optimized**: Low overhead design suitable for embedded deployment

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Capture       │───▶│   Aggregator    │───▶│   CSV Rotator   │
│   Engine        │    │   (5s windows)  │    │   (mythological │
│   (scapy/pcapy) │    │                 │    │    naming)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Interface     │    │   Health        │    │   Firebase      │
│   Monitor       │    │   Monitor       │    │   Stager        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Installation

### Prerequisites

```bash
# Install system dependencies (Raspberry Pi)
sudo apt update
sudo apt install -y python3-dev libpcap-dev build-essential

# Install Python dependencies
pip install -e .
```

### Development Installation

```bash
# Clone and install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/retina/
```

## Configuration

### Basic Configuration

Create `/etc/argus-v/retina.yaml`:

```yaml
# Retina configuration
retina:
  enabled: true
  interface: "eth0"
  
  # Capture settings
  capture:
    interface: "eth0"
    snaplen: 65535
    promiscuous: true
    timeout_ms: 100
    buffer_size_mb: 10
    use_scapy: true
  
  # Aggregation settings
  aggregation:
    window_seconds: 5
    output_dir: "/var/lib/argus-v/retina"
    max_rows_per_file: 10000
    file_rotation_count: 10
  
  # Health monitoring
  health:
    max_drop_rate_percent: 1.0
    max_flow_queue_size: 1000
    alert_cooldown_seconds: 300
    enable_drop_monitoring: true
    enable_queue_monitoring: true
  
  # Anonymization
  ip_salt: "${RETINA_IP_SALT}"  # Use environment variable
```

### Environment Variables

Set required environment variables:

```bash
# Create environment file
sudo tee /etc/default/argus-v-retina << EOF
RETINA_IP_SALT="your_secure_random_salt_here"
LOG_LEVEL="INFO"
EOF

# Load environment
source /etc/default/argus-v-retina
```

## Usage

### Command Line Interface

```bash
# Run daemon
argus-v-retina --config /etc/argus-v/retina.yaml daemon

# Test configuration
argus-v-retina --config /etc/argus-v/retina.yaml test --duration 30

# List available interfaces
argus-v-retina interfaces

# Validate configuration
argus-v-retina --config /etc/argus-v/retina.yaml validate

# Check status
argus-v-retina --config /etc/argus-v/retina.yaml status
```

### Daemon Operation

#### Starting the Daemon

```bash
# Start as foreground process (for testing)
argus-v-retina --config /etc/argus-v/retina.yaml daemon

# Start as system service (recommended)
sudo systemctl start argus-v-retina
sudo systemctl enable argus-v-retina

# Check service status
sudo systemctl status argus-v-retina
```

#### Monitoring Operations

```bash
# View real-time logs
journalctl -u argus-v-retina -f

# Check capture statistics
argus-v-retina --config /etc/argus-v/retina.yaml stats

# View current status
argus-v-retina --config /etc/argus-v/retina.yaml status
```

## Raspberry Pi Deployment

### Systemd Service

Create `/etc/systemd/system/argus-v-retina.service`:

```ini
[Unit]
Description=Argus_V Retina Network Collector
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=argus-v
Group=argus-v
WorkingDirectory=/opt/argus-v
Environment=PYTHONPATH=/opt/argus-v/src
EnvironmentFile=-/etc/default/argus-v-retina
ExecStart=/opt/argus-v/venv/bin/argus-v-retina --config /etc/argus-v/retina.yaml daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=argus-v-retina

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/argus-v /var/log/argus-v

[Install]
WantedBy=multi-user.target
```

### Raspberry Pi Optimization

#### Memory Management

```bash
# Add to /etc/sysctl.conf
vm.swappiness=10
vm.vfs_cache_pressure=50

# Apply settings
sudo sysctl -p
```

#### CPU Governor

```bash
# Set performance governor for consistent packet processing
echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

#### Network Interface

```bash
# Optimize network interface for packet capture
sudo ethtool -K eth0 gro on gso on tso on
sudo ethtool -C eth0 rx-usecs 100 rx-frames 16
```

### Hardware Considerations

- **Network Interface**: Use USB 3.0 network adapters for higher throughput
- **Storage**: Use high-quality SD cards or USB SSD for better I/O performance  
- **Power**: Ensure stable power supply to prevent interface drops
- **Cooling**: Install heat sinks/fans to prevent thermal throttling

## Firebase Integration

### CSV Staging Process

1. **Packet Capture**: Packets are captured and aggregated into 5-second windows
2. **CSV Rotation**: Completed windows are written to rotating CSV files with mythological names
3. **File Aging**: Files older than 60 seconds are considered "complete" 
4. **Staging**: Complete files are moved to staging directory for upload
5. **Upload**: External process uploads staged files to Firebase
6. **Cleanup**: Uploaded files are moved to "uploaded" directory

### Firebase Storage Structure

```
retina-data/
├── staging/
│   ├── zeus_20231215_120000.csv
│   ├── hera_20231215_120500.csv
│   └── ...
└── uploaded/
    └── [processed files]
```

### Upload Process

Create a separate uploader service:

```python
#!/usr/bin/env python3
"""Firebase CSV Uploader Service."""

import firebase_admin
from firebase_admin import credentials, storage
import glob
import os

def upload_staged_files():
    """Upload staged CSV files to Firebase."""
    # Initialize Firebase
    cred = credentials.Certificate('/etc/argus-v/firebase-credentials.json')
    firebase_admin.initialize_app(cred, {
        'storageBucket': 'your-project-id.appspot.com'
    })
    
    bucket = storage.bucket()
    
    # Get staged files
    staging_dir = "/var/lib/argus-v/retina/staging"
    for csv_file in glob.glob(f"{staging_dir}/*.csv"):
        try:
            # Upload to Firebase Storage
            blob = bucket.blob(f"retina-data/{os.path.basename(csv_file)}")
            blob.upload_from_filename(csv_file)
            
            # Move to uploaded directory
            os.rename(csv_file, f"{staging_dir}/uploaded/{os.path.basename(csv_file)}")
            
        except Exception as e:
            print(f"Failed to upload {csv_file}: {e}")

if __name__ == "__main__":
    upload_staged_files()
```

### Cron-based Upload

```bash
# Add to crontab for regular uploads
*/5 * * * * /opt/argus-v/venv/bin/python /opt/argus-v/scripts/upload-to-firebase.py
```

## Data Format

### CSV Schema

Each CSV row contains:

- **Temporal**: `timestamp`, `window_start`, `window_end`, `duration_seconds`
- **Metrics**: `packet_count`, `byte_count`, `unique_flows`, `rate_pps`, `rate_bps`
- **Anonymized Network**: `src_ip_anon`, `dst_ip_anon`, `protocol`, `src_port`, `dst_port`
- **Flow Details**: `src_flow_packets`, `src_flow_bytes`, `dst_flow_packets`, `dst_flow_bytes`

### Example Row

```csv
timestamp,window_start,window_end,duration_seconds,packet_count,byte_count,unique_flows,rate_pps,rate_bps,src_ip_anon,dst_ip_anon,protocol,src_port,dst_port,src_flow_packets,src_flow_bytes,dst_flow_packets,dst_flow_bytes
2023-12-15T12:00:00Z,2023-12-15T12:00:00Z,2023-12-15T12:00:05Z,5.0,150,22500,3,30.0,36000.0,ip_abc123def456,ip_789ghi012jkl,TCP,443,54321,75,11250,75,11250
```

## Monitoring and Alerting

### Health Metrics

- **Packet Drop Rate**: Percentage of packets dropped vs captured
- **Flow Queue Size**: Number of flows waiting for processing  
- **Interface Availability**: Network interface operational status
- **CPU/Memory Usage**: System resource consumption
- **Disk Usage**: Storage utilization for CSV files

### Alert Thresholds

```yaml
health:
  max_drop_rate_percent: 1.0     # Alert if >1% packet loss
  max_flow_queue_size: 1000      # Alert if >1000 pending flows
  alert_cooldown_seconds: 300    # Minimum 5min between alerts
```

### Alert Handling

Alerts are logged and can trigger external notifications:

- **Critical**: Interface unavailable, high packet loss
- **Warning**: Queue overflow, high resource usage

## Troubleshooting

### Common Issues

#### Interface Not Available

```bash
# Check interface exists
ip link show eth0

# Test with manual capture
sudo tcpdump -i eth0 -c 10

# Check permissions
sudo usermod -a -G pcap argus-v
```

#### High Packet Loss

```bash
# Check system resources
htop
iostat 1

# Monitor interface statistics
cat /proc/net/dev
ethtool -S eth0
```

#### Permission Issues

```bash
# Ensure proper permissions
sudo chown -R argus-v:argus-v /var/lib/argus-v
sudo chmod 755 /var/lib/argus-v
sudo chmod 644 /etc/argus-v/retina.yaml
```

### Log Analysis

```bash
# View recent logs
journalctl -u argus-v-retina --since "1 hour ago"

# Search for errors
journalctl -u argus-v-retina | grep -i error

# Monitor in real-time
journalctl -u argus-v-retina -f
```

### Performance Tuning

#### Buffer Optimization

```yaml
capture:
  buffer_size_mb: 20        # Increase buffer for high-traffic interfaces
  snaplen: 65535           # Capture full packets
  timeout_ms: 100          # Balance responsiveness vs overhead
```

#### Aggregation Tuning

```yaml
aggregation:
  window_seconds: 5        # Increase for higher throughput
  max_rows_per_file: 50000 # Fewer, larger files
  file_rotation_count: 20  # Keep more history
```

## Security Considerations

### Network Access

- Daemon runs with minimal network privileges
- Only captures on specified interface
- No outbound network connections required

### Data Protection

- All IP addresses are anonymized with salted hashing
- No packet payload is stored
- CSV files contain only aggregated statistics

### System Security

- Runs as non-root user `argus-v`
- Uses systemd security features
- Limited file system access
- No shell access required

## API Reference

### Daemon Control

```python
from argus_v.retina import RetinaDaemon
from argus_v.retina.config import RetinaConfig

# Create and configure daemon
config = RetinaConfig.from_yaml("/etc/argus-v/retina.yaml")
daemon = RetinaDaemon(config)

# Control lifecycle
daemon.start()
daemon.stop()
status = daemon.get_status()
```

### Component Access

```python
# Access individual components
aggregator = daemon._aggregator
csv_rotator = daemon._csv_rotator
health_monitor = daemon._health_monitor

# Get real-time statistics
stats = aggregator.get_stats()
csv_stats = csv_rotator.get_stats()
health_summary = health_monitor.get_health_summary()
```

## Contributing

### Development Setup

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/retina/ -v

# Run specific test
pytest tests/retina/test_collector.py::TestCaptureEngineWithScapy -v
```

### Test Data

Test PCAP samples can be placed in `tests/data/` for integration testing.

## License

Proprietary - Argus_V Internal Use Only