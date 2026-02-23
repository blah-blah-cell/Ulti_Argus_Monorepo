#!/usr/bin/env bash
#
# Ulti_Argus & DeepPacketSentinel Installer
# Hardened for production deployment on Ubuntu/Debian.

set -euo pipefail

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "================================================="
echo "   Ulti_Argus & DeepPacketSentinel Installer     "
echo "================================================="

# --- Configuration ---
INSTALL_DIR="/opt/argus_v"
BACKUP_DIR="/tmp/argus_backup_$(date +%s)"
DRY_RUN=false
PYTHON_BIN=${PYTHON_BIN:-python3}

# --- Colors ---
RED=""
GREEN=""
YELLOW=""
BLUE=""
NC=""

if command -v tput >/dev/null 2>&1; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    BLUE=$(tput setaf 4)
    NC=$(tput sgr0)
fi

# --- Logging ---
log_info() { echo "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo "${YELLOW}[WARN]${NC} $1"; }
log_success() { echo "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo "${RED}[ERROR]${NC} $1"; }

# --- Error Handling ---
cleanup() {
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        log_error "Installation failed with exit code $EXIT_CODE."
        restore_state
    fi
}
trap cleanup EXIT ERR

# --- Helper Functions ---
run_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo "${YELLOW}[DRY RUN]${NC} $*"
    else
        "$@"
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root (sudo ./install.sh)"
        exit 1
    fi
}

check_os() {
    log_info "Checking OS compatibility..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu)
                if [[ "$VERSION_ID" != "22.04" && "$VERSION_ID" != "24.04" ]]; then
                    log_error "Unsupported Ubuntu version: $VERSION_ID. Requires 22.04 or 24.04."
                    exit 1
                fi
                if [[ "$VERSION_ID" == "22.04" ]]; then
                    log_warn "Ubuntu 22.04 detected. Note: Default Python 3.10 may fail Python 3.11+ check."
                fi
                ;;
            debian)
                if [[ "$VERSION_ID" != "12" ]]; then
                    log_error "Unsupported Debian version: $VERSION_ID. Requires 12."
                    exit 1
                fi
                ;;
            *)
                log_error "Unsupported OS: $ID. Requires Ubuntu 22.04/24.04 or Debian 12."
                exit 1
                ;;
        esac
        log_success "OS $ID $VERSION_ID is supported."
    else
        log_error "Cannot determine OS. /etc/os-release not found."
        exit 1
    fi
}

check_kernel() {
    log_info "Checking kernel version..."
    local KERNEL_VER=$(uname -r | cut -d. -f1,2)
    local REQUIRED_VER="5.15"

    # Sort version strings. If required is first, then kernel >= required.
    if [ "$(printf '%s\n%s' "$REQUIRED_VER" "$KERNEL_VER" | sort -V | head -n1)" != "$REQUIRED_VER" ]; then
         log_error "Kernel 5.15+ is required for eBPF. Found $(uname -r)."
         exit 1
    fi
    log_success "Kernel $(uname -r) is supported."
}

check_python() {
    log_info "Checking Python version using binary: $PYTHON_BIN..."
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        log_error "Python binary '$PYTHON_BIN' is not installed."
        exit 1
    fi

    if ! "$PYTHON_BIN" -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)"; then
        log_error "Python 3.11+ is required. Found $("$PYTHON_BIN" --version 2>&1)."
        log_error "Please upgrade Python or use Ubuntu 24.04 / Debian 12."
        exit 1
    fi
    log_success "Python 3.11+ found."
}

backup_state() {
    if [ "$DRY_RUN" = true ]; then return; fi

    log_info "Backing up existing installation..."
    mkdir -p "$BACKUP_DIR"

    if [ -d "$INSTALL_DIR" ]; then
        cp -r "$INSTALL_DIR" "$BACKUP_DIR/"
    fi

    if [ -f "/etc/systemd/system/argus-sentinel.service" ]; then
        cp "/etc/systemd/system/argus-sentinel.service" "$BACKUP_DIR/"
    fi

    if [ -f "/etc/systemd/system/argus-brain.service" ]; then
        cp "/etc/systemd/system/argus-brain.service" "$BACKUP_DIR/"
    fi
}

restore_state() {
    if [ "$DRY_RUN" = true ]; then return; fi

    if [ -d "$BACKUP_DIR" ] && [ "$(ls -A $BACKUP_DIR)" ]; then
        log_warn "Restoring from backup..."
        if [ -d "$BACKUP_DIR/$(basename $INSTALL_DIR)" ]; then
             rm -rf "$INSTALL_DIR"
             cp -r "$BACKUP_DIR/$(basename $INSTALL_DIR)" "$(dirname $INSTALL_DIR)/"
        fi

        if [ -f "$BACKUP_DIR/argus-sentinel.service" ]; then
            cp "$BACKUP_DIR/argus-sentinel.service" "/etc/systemd/system/"
        fi

        if [ -f "$BACKUP_DIR/argus-brain.service" ]; then
            cp "$BACKUP_DIR/argus-brain.service" "/etc/systemd/system/"
        fi

        systemctl daemon-reload
        log_success "Restoration complete."
    fi
    rm -rf "$BACKUP_DIR"
}

install_system_deps() {
    log_info "Installing system packages..."
    export DEBIAN_FRONTEND=noninteractive

    # Combining logic from main branch to support variable PYTHON_BIN
    run_cmd apt-get update
    if run_cmd apt-get install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential "$PYTHON_BIN" "$PYTHON_BIN-venv" "$PYTHON_BIN-dev" python3-pip curl git pkg-config; then
        log_success "System dependencies installed successfully."
    else
        log_warn "Specific python packages for $PYTHON_BIN might be missing. Proceeding with python3-pip fallback..."
        run_cmd apt-get install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential "$PYTHON_BIN" python3-pip curl git pkg-config
    fi
}

install_rust() {
    log_info "Setting up Rust environment..."
    if ! command -v cargo >/dev/null 2>&1; then
        run_cmd curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | run_cmd sh -s -- -y
        if [ -f "$HOME/.cargo/env" ]; then
            . "$HOME/.cargo/env"
        fi
    fi

    # Check toolchain
    if ! rustup toolchain list | grep -q "nightly"; then
        run_cmd rustup toolchain install nightly
    fi

    # Check component
    if ! rustup component list --toolchain nightly --installed | grep -q "rust-src"; then
        run_cmd rustup component add rust-src --toolchain nightly
    fi

    # Check bpf-linker
    if ! cargo install --list | grep -q "bpf-linker"; then
        log_info "Installing bpf-linker..."
        run_cmd cargo install bpf-linker
    else
        log_info "bpf-linker already installed."
    fi
}

build_dps() {
    log_info "Building DeepPacketSentinel..."
    local DPS_DIR="$SCRIPT_DIR/DeepPacketSentinel"

    if [ ! -d "$DPS_DIR" ]; then
        log_error "Directory not found: $DPS_DIR"
        exit 1
    fi

    cd "$DPS_DIR"

    local BINARY="target/release/userspace"
    local SHOULD_BUILD=true

    if [ -f "$BINARY" ]; then
        # Check timestamps - exclude target directory to avoid circular dependency
        local NEWEST_SRC=$(find . -type f -not -path "./target/*" -exec stat -c %Y {} + | sort -n | tail -1)
        local BIN_TIME=$(stat -c %Y "$BINARY")

        if [ "$BIN_TIME" -ge "$NEWEST_SRC" ]; then
             log_info "DeepPacketSentinel binary is up to date. Skipping build."
             SHOULD_BUILD=false
        fi
    fi

    if [ "$SHOULD_BUILD" = true ]; then
        run_cmd cargo +nightly build --package ebpf --target bpfel-unknown-none -Z build-std=core
        run_cmd cargo build --package userspace --release
    fi
}

install_argus() {
    log_info "Installing Ulti_argus Python AI..."
    local ARGUS_SRC="$SCRIPT_DIR/Ulti_argus"
    local DPS_SRC="$SCRIPT_DIR/DeepPacketSentinel"

    run_cmd mkdir -p "$INSTALL_DIR"

    # Copy DPS
    log_info "Copying DeepPacketSentinel..."
    run_cmd cp -r "$DPS_SRC" "$INSTALL_DIR/"

    # Python Venv
    if [ ! -d "$INSTALL_DIR/venv" ]; then
        log_info "Creating virtual environment using $PYTHON_BIN..."
        cd "$ARGUS_SRC"
        run_cmd "$PYTHON_BIN" -m venv "$INSTALL_DIR/venv"
        run_cmd "$INSTALL_DIR/venv/bin/pip" install -U pip wheel
    else
        log_info "Virtual environment exists. Skipping creation."
    fi

    # Install Package
    cd "$ARGUS_SRC"
    if [ -x "$INSTALL_DIR/venv/bin/pip" ] && "$INSTALL_DIR/venv/bin/pip" freeze | grep -q "argus-v"; then
         log_info "argus-v package already installed."
    else
         run_cmd "$INSTALL_DIR/venv/bin/pip" install -e .
    fi

    # Train Models
    log_info "Training AI models..."
    if [ -f "$INSTALL_DIR/models/payload_classifier.pth" ]; then
        log_info "Models already exist. Skipping training."
    else
        run_cmd mkdir -p "$INSTALL_DIR/models"
        # We need to ensure we run this with the venv python
        run_cmd "$INSTALL_DIR/venv/bin/python" "$SCRIPT_DIR/scripts/train_models.py"
    fi
}

setup_services() {
    log_info "Configuring systemd services..."

    run_cmd cp "$SCRIPT_DIR/systemd/argus-sentinel.service" "/etc/systemd/system/"
    run_cmd cp "$SCRIPT_DIR/systemd/argus-brain.service" "/etc/systemd/system/"

    run_cmd systemctl daemon-reload
    run_cmd systemctl enable argus-sentinel
    run_cmd systemctl enable argus-brain
}

main() {
    check_root

    for arg in "$@"; do
        if [ "$arg" == "--dry-run" ]; then
            DRY_RUN=true
            log_warn "Dry run enabled."
        fi
    done

    check_os
    check_kernel

    backup_state

    install_system_deps

    # Check Python AFTER install
    check_python

    install_rust
    build_dps
    install_argus
    setup_services

    log_success "Installation Complete!"
    echo ""
    echo "To start services:"
    echo "  sudo systemctl start argus-sentinel"
    echo "  sudo systemctl start argus-brain"
}

main "$@"
