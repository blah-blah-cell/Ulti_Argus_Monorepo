#!/usr/bin/env bash
set -e

# Deployment variables
INSTANCE_NAME="argus-server"
ZONE="us-central1-a"
MACHINE_TYPE="e2-standard-4"
IMAGE_FAMILY="ubuntu-2204-lts"
IMAGE_PROJECT="ubuntu-os-cloud"
DISK_SIZE="50GB"
TAGS="argus-server"

# Path to cloud-init script
CLOUD_INIT_FILE="$(dirname "$0")/gcp-cloud-init.yaml"

if [ ! -f "$CLOUD_INIT_FILE" ]; then
    echo "Error: Cloud-init file not found at $CLOUD_INIT_FILE"
    exit 1
fi

echo "Deploying GCP Instance: $INSTANCE_NAME..."
gcloud compute instances create "$INSTANCE_NAME" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$DISK_SIZE" \
    --boot-disk-type="pd-ssd" \
    --tags="$TAGS" \
    --metadata-from-file user-data="$CLOUD_INIT_FILE"

echo "Creating Firewall Rules..."
# Check if firewall rule already exists to avoid error
if ! gcloud compute firewall-rules list --filter="name=allow-argus" --format="value(name)" | grep -q "allow-argus"; then
    gcloud compute firewall-rules create allow-argus \
        --allow tcp:8081,tcp:9090 \
        --target-tags="$TAGS" \
        --description="Allow Argus API and Prometheus ports"
else
    echo "Firewall rule 'allow-argus' already exists."
fi

echo "Deployment Initiated!"
echo "Instance IP Address:"
gcloud compute instances describe "$INSTANCE_NAME" --zone="$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
