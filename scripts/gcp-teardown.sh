#!/usr/bin/env bash
set -e

INSTANCE_NAME="argus-server"
ZONE="us-central1-a"

echo "Destroying GCP Instance: $INSTANCE_NAME..."
gcloud compute instances delete "$INSTANCE_NAME" --zone="$ZONE" --quiet

echo "Deleting Firewall Rules..."
if gcloud compute firewall-rules list --filter="name=allow-argus" --format="value(name)" | grep -q "allow-argus"; then
    gcloud compute firewall-rules delete allow-argus --quiet
else
    echo "Firewall rule 'allow-argus' not found."
fi

echo "Teardown Complete!"
