#!/bin/bash
# Argus AI - Raspberry Pi Installer
# Usage: sudo ./install.sh

set -e

echo "[*] Starting Argus AI Installation..."

# 1. Update System & Install Dependencies
echo "[*] Installing System Dependencies (BCC, Python, Build Tools)..."
apt-get update
# bpfcc-tools and python3-bpfcc are critical for eBPF
apt-get install -y python3-pip python3-bpfcc bpfcc-tools linux-headers-$(uname -r) build-essential git

# 2. Python Dependencies
echo "[*] Installing Python Dependencies..."
# We use --break-system-packages on newer Debian/RPi OS versions if pip complains, 
# or we settle for a venv. For a dedicated appliances (RPi), installing system-wide is often preferred 
# for service simplicity, but let's try to be safe.
# Actually, for an embedded appliance like this, let's use a venv to avoid messing with system python.
if [ ! -d "/opt/argus_env" ]; then
    python3 -m venv /opt/argus_env
fi
source /opt/argus_env/bin/activate

pip install --upgrade pip
# Install project requirements
# Assuming we are running this from the project root or cloned repo
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "[!] requirements.txt not found! Please run this from the project root."
    exit 1
fi

# 3. Directory Setup
echo "[*] Setting up directories..."
mkdir -p /etc/argus
mkdir -p /var/log/argus
mkdir -p /var/lib/argus/certs

# Copy source code to /opt/argus if not already there (Deployment logic)
# For dev/test, we assume code is in place or this script is run inside the repo.
# In a real "production" install, we'd copy `src` to `/opt/argus/src`.

# 4. Permissions
echo "[*] Setting permissions..."
chmod +x src/aegis/core/loader.py
chmod +x src/aegis/proxy/interceptor.py

echo "[*] Installation Complete."
echo "    Activate env: source /opt/argus_env/bin/activate"
echo "    Run Proxy:    mitmdump -s src/aegis/proxy/interceptor.py --mode transparent"
echo "    Run Kernel:   python src/aegis/core/loader.py -i <interface>"
