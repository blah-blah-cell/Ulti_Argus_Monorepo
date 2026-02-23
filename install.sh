#!/usr/bin/env bash
set -e

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "================================================="
echo "   Ulti_Argus & DeepPacketSentinel Installer     "
echo "================================================="

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (sudo ./install.sh)"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
PYTHON_BIN=${PYTHON_BIN:-python3}

echo "Using Python binary: $PYTHON_BIN"

echo "1. Installing system dependencies..."
# Try to install the specific python version packages if they exist, otherwise fallback to python3 packages
# We use a loop or just attempt to install.
# For simplicity, we install python3-pip and the specific python venv/dev if available.
apt-get update
apt-get install -y \
    clang llvm libelf-dev libpcap-dev gcc-multilib build-essential \
    "$PYTHON_BIN" "$PYTHON_BIN-venv" "$PYTHON_BIN-dev" python3-pip \
    curl git pkg-config || {
        echo "Warning: Specific python packages for $PYTHON_BIN might be missing. Proceeding with python3-pip..."
        apt-get install -y "$PYTHON_BIN" python3-pip
    }

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
cd "$SCRIPT_DIR/DeepPacketSentinel"
cargo +nightly build --package ebpf --target bpfel-unknown-none -Z build-std=core
cargo build --package userspace --release

echo "5. Installing Ulti_argus (Python AI)..."
# Create deployment directory
mkdir -p /opt/argus_v
# Copy the compiled Rust artifact location
cp -r "$SCRIPT_DIR/DeepPacketSentinel" /opt/argus_v/DeepPacketSentinel

cd "$SCRIPT_DIR/Ulti_argus"
"$PYTHON_BIN" -m venv /opt/argus_v/venv
/opt/argus_v/venv/bin/pip install -U pip wheel
/opt/argus_v/venv/bin/pip install -e .

echo "6. Training Initial AI Models..."
# Create model directories expected by Aegis
mkdir -p /opt/argus_v/models
# Run the training script using our synthetic flow datset
/opt/argus_v/venv/bin/python3 "$SCRIPT_DIR/scripts/train_models.py"

echo "7. Configuring OS Services..."
# The systemd templates
cp "$SCRIPT_DIR/systemd/argus-sentinel.service" /etc/systemd/system/
cp "$SCRIPT_DIR/systemd/argus-brain.service" /etc/systemd/system/

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
