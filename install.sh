#!/usr/bin/env bash
set -e

echo "================================================="
echo "   Ulti_Argus & DeepPacketSentinel Installer     "
echo "================================================="

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (sudo ./install.sh)"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "1. Installing system dependencies..."
apt-get update
apt-get install -y \
    clang llvm libelf-dev libpcap-dev gcc-multilib build-essential \
    python3 python3-pip python3-venv \
    curl git pkg-config

echo "2. Installing Rust..."
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

echo "3. Installing bpf-linker..."
cargo install bpf-linker

echo "4. Building DeepPacketSentinel (Kernel & Userspace)..."
cd "$(dirname "$0")/DeepPacketSentinel"
cargo +nightly build --package ebpf --target bpfel-unknown-none -Z build-std=core
cargo build --package userspace --release

echo "5. Installing Ulti_argus (Python AI)..."
# Create deployment directory
mkdir -p /opt/argus_v
# Copy the compiled Rust artifact location
cp -r "$(dirname "$0")/../DeepPacketSentinel" /opt/argus_v/DeepPacketSentinel

cd "$(dirname "$0")/../Ulti_argus"
python3 -m venv /opt/argus_v/venv
/opt/argus_v/venv/bin/pip install -U pip wheel
/opt/argus_v/venv/bin/pip install -e .

echo "6. Configuring OS Services..."
# The systemd templates
cp "$(dirname "$0")/../systemd/argus-sentinel.service" /etc/systemd/system/
cp "$(dirname "$0")/../systemd/argus-brain.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable argus-sentinel
systemctl enable argus-brain

echo "================================================="
echo "   Installation Complete!                        "
echo "                                                 "
echo "To start the full 4-Layer pipeline:              "
echo "  sudo systemctl start argus-sentinel            "
echo "  sudo systemctl start argus-brain               "
echo "                                                 "
echo "View Python AI logs:                             "
echo "  /opt/argus_v/venv/bin/argus-cli logs           "
echo "================================================="
