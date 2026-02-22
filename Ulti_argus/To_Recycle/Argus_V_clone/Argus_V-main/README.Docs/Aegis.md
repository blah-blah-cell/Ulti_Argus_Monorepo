# Aegis Shield Runtime Service

The Aegis shield runtime service provides real-time network traffic analysis and automated threat blocking for Raspberry Pi deployments. It integrates with the Argus_V Retina data collection system and Mnemosyne machine learning models to detect and respond to anomalous network behavior.

## Overview

Aegis operates as a decentralized shield service that:

- **Polls Retina CSV outputs** every 5 seconds for network flow data
- **Loads latest Mnemosyne models** from Firebase Storage with local caching
- **Processes flows through ML models** to detect anomalies and threats
- **Maintains decentralized blacklist storage** in SQLite with JSON export
- **Enforces network policies** through iptables with 7-day mandatory dry-run
- **Synchronizes with Firebase** for cloud-based backup and coordination

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Retina CSV    │───▶│  Prediction     │───▶│  Blacklist      │
│   Polling       │    │  Engine         │    │  Manager        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Mnemosyne      │    │   iptables      │
                       │  Model Manager  │    │  Enforcement    │
                       └─────────────────┘    └─────────────────┘
```

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd argus-v

# Install dependencies
pip install -e .

# Create required directories
sudo mkdir -p /var/lib/argus/{aegis,models,scalers,retina/csv}
sudo mkdir -p /var/run/argus
```

### 2. Configuration

```bash
# Copy example configuration
sudo cp aegis-config.example.yaml /etc/aegis/config.yaml

# Edit configuration for your environment
sudo nano /etc/aegis/config.yaml
```

Key configuration sections:

- **model**: Mnemosyne model paths and loading settings
- **polling**: Retina CSV polling configuration (5-second intervals)
- **prediction**: ML thresholds and feature columns
- **enforcement**: Dry-run settings and iptables management
- **firebase**: Optional cloud sync configuration

### 3. Service Management

```bash
# Start service (foreground mode for testing)
sudo python -m argus_v.aegis.cli start --config /etc/aegis/config.yaml

# Run as daemon
sudo python -m argus_v.aegis.cli start --config /etc/aegis/config.yaml --daemon

# Check status
sudo python -m argus_v.aegis.cli status --config /etc/aegis/config.yaml

# View health
sudo python -m argus_v.aegis.cli health --config /etc/aegis/config.yaml

# Stop service
sudo python -m argus_v.aegis.cli stop --config /etc/aegis/config.yaml
```

## Core Components

### Model Manager

Manages Mnemosyne model loading and caching:

```python
from argus_v.aegis.model_manager import ModelManager

model_manager = ModelManager(config, anonymizer)
success = model_manager.load_latest_model()

if model_manager.is_model_available():
    predictions = model_manager.predict_flows(flows_df)
```

**Features:**
- Downloads latest models from Firebase Storage
- Validates model age and integrity
- Provides fallback model when external models unavailable
- Caches models locally for fast access
- Handles model versioning and cleanup

### Prediction Engine

Core processing engine that polls Retina and makes predictions:

```python
from argus_v.aegis.prediction_engine import PredictionEngine

engine = PredictionEngine(config, model_manager, blacklist_manager)
engine.start()

# Automatic polling and processing of new CSV files
# Manual processing for testing
engine.force_process_file(csv_file_path)
```

**Features:**
- Polls Retina CSV directory every 5 seconds
- Processes flows in configurable batch sizes
- Extracts features and runs ML predictions
- Makes enforcement decisions based on risk levels
- Handles missing models gracefully with fallback
- Tracks comprehensive statistics

### Blacklist Manager

Decentralized blacklist storage with enforcement:

```python
from argus_v.aegis.blacklist_manager import BlacklistManager

blacklist_manager = BlacklistManager(config, anonymizer)

# Check if IP is blacklisted
is_blocked = blacklist_manager.is_blacklisted("192.168.1.100")

# Add to blacklist
blacklist_manager.add_to_blacklist(
    ip_address="192.168.1.100",
    reason="Anomalous behavior detected",
    risk_level="high",
    ttl_hours=24
)
```

**Features:**
- SQLite database for persistent storage
- JSON export for backup and synchronization
- IP anonymization for privacy
- TTL-based expiration
- Firebase synchronization hooks
- Emergency stop functionality
- iptables integration

### Service Daemon

Main service orchestrator:

```python
from argus_v.aegis.daemon import AegisDaemon

daemon = AegisDaemon("/etc/aegis/config.yaml")
daemon.start()

# Monitor service
health = daemon.get_health_status()
status = daemon.get_status()

# Emergency controls
daemon.emergency_stop("Security incident detected")
daemon.emergency_restore("Investigation complete")
```

## Configuration Reference

### Model Configuration

```yaml
model:
  model_local_path: "/var/lib/argus/models"
  scaler_local_path: "/var/lib/argus/scalers"
  min_model_age_hours: 1
  max_model_age_days: 30
  use_fallback_model: true
  fallback_prediction_threshold: 0.7
```

### Polling Configuration

```yaml
polling:
  poll_interval_seconds: 5
  csv_directory: "/var/lib/argus/retina/csv"
  batch_size: 100
  max_poll_errors: 5
```

### Prediction Configuration

```yaml
prediction:
  feature_columns:
    - bytes_in
    - bytes_out
    - packets_in
    - packets_out
    - duration
    - src_port
    - dst_port
    - protocol
  anomaly_threshold: 0.7
  high_risk_threshold: 0.9
  max_flows_per_batch: 1000
```

### Enforcement Configuration

```yaml
enforcement:
  dry_run_duration_days: 7
  enforce_after_dry_run: false
  iptables_chain_name: "AEGIS-DROP"
  blacklist_default_ttl_hours: 24
  emergency_stop_file: "/var/run/argus/aegis.emergency"
```

## Dry Run Mode

Aegis operates in **mandatory 7-day dry-run mode** by default:

- **Days 1-7**: All violations are logged but not enforced
- **Day 8+**: Enforcement remains disabled unless explicitly enabled
- **Emergency Stop**: Immediate cessation of all enforcement actions

To enable enforcement after dry run:

```yaml
enforcement:
  dry_run_duration_days: 7
  enforce_after_dry_run: true  # Enable after testing period
```

## Monitoring and Health Checks

### Health Status

```bash
# Check overall health
sudo python -m argus_v.aegis.cli health --config /etc/aegis/config.yaml

# Detailed status
sudo python -m argus_v.aegis.cli status --config /etc/aegis/config.yaml

# JSON output for monitoring
sudo python -m argus_v.aegis.cli health --config /etc/aegis/config.yaml --json
```

### Statistics

Statistics are continuously updated to `/var/lib/argus/aegis/stats.json`:

```json
{
  "daemon_stats": {
    "service_start_time": "2023-12-01T10:00:00",
    "health_checks_passed": 120,
    "dry_run_remaining_days": 5.2
  },
  "component_stats": {
    "model_manager": {
      "model_available": true,
      "model_type": "IsolationForest",
      "last_load_time": "2023-12-01T09:30:00"
    },
    "prediction_engine": {
      "total_flows_processed": 15420,
      "anomalies_detected": 23,
      "enforcement_actions": 0
    },
    "blacklist_manager": {
      "active_entries": 5,
      "sync_operations": 2
    }
  }
}
```

## Blacklist Management

### Manual Blacklist Operations

```bash
# List current blacklist entries
sudo python -m argus_v.aegis.cli blacklist list --config /etc/aegis/config.yaml

# Add IP to blacklist
sudo python -m argus_v.aegis.cli blacklist add 192.168.1.100 \
  --reason "Manual block" \
  --risk-level high \
  --ttl-hours 24

# Remove from blacklist
sudo python -m argus_v.aegis.cli blacklist remove 192.168.1.100
```

### Emergency Controls

```bash
# Emergency stop (immediate halt of enforcement)
sudo python -m argus_v.aegis.cli emergency-stop \
  --reason "Security incident" \
  --config /etc/aegis/config.yaml

# Restore normal operations
sudo python -m argus_v.aegis.cli emergency-restore \
  --reason "Investigation complete" \
  --config /etc/aegis/config.yaml
```

## Firebase Integration

### Model Storage

Aegis automatically downloads the latest Mnemosyne models from Firebase Storage:

```yaml
# Enable Firebase in configuration
interfaces:
  firebase:
    enabled: true

firebase:
  project_id: "your-project-id"
  storage_bucket: "your-project.appspot.com"
  service_account_path: "~/.config/gcloud/service-account.json"
  model_output_path: "models"
```

### Blacklist Synchronization

Blacklist entries are periodically synchronized to Firebase:

- **Frequency**: Every hour (configurable)
- **Format**: JSON export with metadata
- **Fallback**: Local operation when Firebase unavailable
- **Privacy**: IP addresses anonymized in cloud storage

## Testing

### Component Testing

```bash
# Test model loading
sudo python -m argus_v.aegis.cli test \
  --config /etc/aegis/config.yaml \
  --model-load

# Test blacklist operations
sudo python -m argus_v.aegis.cli test \
  --config /etc/aegis/config.yaml \
  --blacklist

# Test CSV prediction
sudo python -m argus_v.aegis.cli test \
  --config /etc/aegis/config.yaml \
  --csv /path/to/test_flows.csv
```

### Unit Tests

```bash
# Run prediction flow tests
python -m pytest tests/aegis/test_aegis_prediction_flow.py -v

# Run integration tests
python -m pytest tests/aegis/test_aegis_integration.py -v

# Run all Aegis tests
python -m pytest tests/aegis/ -v
```

## Troubleshooting

### Common Issues

**1. Model Loading Failures**
```bash
# Check model paths and permissions
ls -la /var/lib/argus/models/
ls -la /var/lib/argus/scalers/

# Test model loading manually
sudo python -m argus_v.aegis.cli test --model-load --config /etc/aegis/config.yaml
```

**2. CSV Polling Issues**
```bash
# Verify Retina is generating CSV files
ls -la /var/lib/argus/retina/csv/

# Check polling configuration
sudo python -m argus_v.aegis.cli validate --config /etc/aegis/config.yaml
```

**3. Permission Issues**
```bash
# Ensure proper permissions
sudo chown -R argus:argus /var/lib/argus/
sudo chown -R argus:argus /var/run/argus/

# Check iptables access (must run as root)
sudo iptables -L AEGIS-DROP
```

**4. Health Check Failures**
```bash
# Get detailed health report
sudo python -m argus_v.aegis.cli health --json --config /etc/aegis/config.yaml

# Check component status
sudo python -m argus_v.aegis.cli status --json --config /etc/aegis/config.yaml
```

### Log Analysis

Logs are written to syslog and can be viewed with:

```bash
# View recent logs
sudo journalctl -u argus-aegis -n 100 -f

# Filter for specific components
sudo journalctl -u argus-aegis | grep "prediction_engine"
sudo journalctl -u argus-aegis | grep "blacklist_manager"
```

### Emergency Recovery

If service becomes unresponsive:

```bash
# Force stop
sudo python -m argus_v.aegis.cli stop --force --config /etc/aegis/config.yaml

# Remove emergency stop file
sudo rm -f /var/run/argus/aegis.emergency

# Restart service
sudo python -m argus_v.aegis.cli start --config /etc/aegis/config.yaml
```

## Performance Optimization

### Raspberry Pi Considerations

- **Memory**: Minimum 2GB RAM recommended
- **Storage**: Use fast SD card or USB SSD for database operations
- **Network**: Ensure stable connection for Firebase sync
- **CPU**: Model predictions run on CPU by default

### Tuning Parameters

```yaml
# Optimize for resource-constrained environments
prediction:
  max_flows_per_batch: 500  # Reduce batch size
  max_workers: 2            # Limit worker threads

polling:
  poll_interval_seconds: 10 # Increase polling interval
  batch_size: 50           # Process smaller batches

enforcement:
  blacklist_cleanup_interval: 7200  # Less frequent cleanup (2 hours)
```

## Security Considerations

### Privilege Requirements

- **Root Access**: Required for iptables management
- **File Permissions**: Service requires write access to `/var/lib/argus/`
- **Network Access**: Outbound HTTPS for Firebase sync

### Data Privacy

- **IP Anonymization**: All IP addresses hashed for local storage
- **Log Sanitization**: Sensitive data filtered from logs
- **Local Storage**: Blacklist data stored locally by default
- **Cloud Sync**: Optional Firebase synchronization with anonymized data

### Emergency Controls

- **Emergency Stop File**: Immediate halt of enforcement
- **Manual Override**: CLI commands work even if daemon is problematic
- **Dry Run Mode**: Default non-enforcement for safe operation

## Deployment

### Systemd Service

Create `/etc/systemd/system/argus-aegis.service`:

```ini
[Unit]
Description=Argus Aegis Shield Runtime
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python -m argus_v.aegis.cli start --daemon --config /etc/aegis/config.yaml
ExecStop=/usr/bin/python -m argus_v.aegis.cli stop --config /etc/aegis/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable argus-aegis
sudo systemctl start argus-aegis
sudo systemctl status argus-aegis
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy service
COPY src/argus_v/ /opt/argus_v/
WORKDIR /opt

# Run as root for iptables access
CMD ["python", "-m", "argus_v.aegis.cli", "start", "--daemon", "--config", "/etc/aegis/config.yaml"]
```

## API Reference

### Daemon Methods

```python
# Service lifecycle
daemon.start() -> bool
daemon.stop(timeout=30) -> bool

# Health and status
daemon.get_health_status() -> dict
daemon.get_status() -> dict

# Emergency controls
daemon.emergency_stop(reason) -> bool
daemon.emergency_restore(reason) -> bool
```

### Model Manager Methods

```python
# Model loading
model_manager.load_latest_model() -> bool
model_manager.is_model_available() -> bool

# Predictions
model_manager.predict_flows(flows_df) -> pd.DataFrame

# Information
model_manager.get_model_info() -> dict
```

### Blacklist Manager Methods

```python
# Blacklist operations
blacklist_manager.add_to_blacklist(ip, reason, **kwargs) -> bool
blacklist_manager.remove_from_blacklist(ip) -> bool
blacklist_manager.is_blacklisted(ip) -> bool

# Management
blacklist_manager.get_blacklist_entries(**filters) -> list
blacklist_manager.cleanup_expired_entries() -> int

# Sync
blacklist_manager.sync_with_firebase() -> bool

# Emergency controls
blacklist_manager.emergency_stop(reason) -> bool
blacklist_manager.emergency_restore(reason) -> bool
```

## Contributing

When contributing to Aegis:

1. **Follow Code Style**: Use existing patterns and conventions
2. **Add Tests**: Include unit tests for new functionality
3. **Update Documentation**: Keep README and API docs current
4. **Security Review**: Consider security implications of changes
5. **Performance Impact**: Test on resource-constrained hardware

## License

This project is part of the Argus_V network security framework. See LICENSE file for details.