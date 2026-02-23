# Deployment Guide

This document outlines the deployment workflow for Ulti_Argus_Monorepo on Google Cloud Platform (GCP).

## Prerequisites

1.  **GCP Account**: An active Google Cloud Platform account with a project.
2.  **gcloud CLI**: Installed and configured on your local machine.
    *   [Install gcloud CLI](https://cloud.google.com/sdk/docs/install)
    *   Run `gcloud init` to authenticate and set your project.
3.  **Permissions**: Ensure your account has permissions to create Compute Engine instances and firewall rules.

## Automated Deployment (GCP)

We provide scripts to automate the deployment process using a cloud-init bootstrap script.

### 1. Configure Repository URL

The `scripts/gcp-cloud-init.yaml` script clones the repository during the boot process. By default, it uses a placeholder URL.
**You must update this URL to your actual repository location before deploying.**

Edit `scripts/gcp-cloud-init.yaml`:
```yaml
# ...
  # Clone the repository
  # NOTE: Replace the URL below with your actual repository URL
  - git clone https://github.com/UltiArgus/Ulti_Argus_Monorepo.git /opt/Ulti_Argus_Monorepo
# ...
```

### 2. Run Deployment Script

Execute the deployment script to provision the instance and configure the firewall:

```bash
./scripts/gcp-deploy.sh
```

This script will:
*   Create a Compute Engine instance named `argus-server`.
*   Use Ubuntu 22.04 LTS, e2-standard-4 machine type, and 50GB SSD.
*   Pass `scripts/gcp-cloud-init.yaml` as the startup script.
*   Create a firewall rule `allow-argus` opening ports 8081 (API) and 9090 (Prometheus).

The script outputs the external IP address of the instance upon completion.

### 3. Verify Deployment

The installation runs in the background via cloud-init. It may take several minutes (10-15 mins) to complete (installing dependencies, compiling Rust components, training models).

To check the progress, SSH into the instance:

```bash
gcloud compute ssh argus-server
```

Tail the cloud-init output log:

```bash
tail -f /var/log/cloud-init-output.log
```

Once completed, you should see "Installation Complete!".

Verify the services are running:

```bash
systemctl status argus-sentinel
systemctl status argus-brain
```

### 4. Access the Application

*   **API**: `http://<INSTANCE_IP>:8081`
*   **Prometheus**: `http://<INSTANCE_IP>:9090`

## Teardown

To destroy the instance and remove firewall rules, run:

```bash
./scripts/gcp-teardown.sh
```

This will permanently delete the `argus-server` instance and the `allow-argus` firewall rule.
