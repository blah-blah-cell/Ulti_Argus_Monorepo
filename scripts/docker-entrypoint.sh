#!/bin/bash
set -e

# Default configuration path
CONFIG_FILE=${ARGUS_CONFIG_FILE:-/etc/argus/aegis.yaml}
EXAMPLE_CONFIG=/etc/argus/aegis.example.yaml

echo "Initializing Aegis Brain..."

# Check if config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Warning: Configuration file not found at $CONFIG_FILE"
    if [ -f "$EXAMPLE_CONFIG" ]; then
        echo "Copying example configuration to $CONFIG_FILE"
        cp "$EXAMPLE_CONFIG" "$CONFIG_FILE"
    else
        echo "Error: Example configuration not found at $EXAMPLE_CONFIG"
    fi
fi

# Ensure directories exist
mkdir -p /var/lib/argus/models \
         /var/lib/argus/scalers \
         /var/lib/argus/retina/csv \
         /var/lib/argus/aegis \
         /var/run/argus

# Attempt to validate config before starting
echo "Validating configuration..."
python3 -m argus_v.aegis.cli validate --config "$CONFIG_FILE" || echo "Config validation warning (continuing anyway)..."

# Start API
# exec replaces the shell process so uvicorn receives signals directly
echo "Starting Aegis Brain API on port 8081..."
exec uvicorn argus_v.aegis.api:app --host 0.0.0.0 --port 8081 --log-level info
