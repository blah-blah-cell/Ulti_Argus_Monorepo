#!/usr/bin/env bash
#
# ARGUS_V Uninstallation Script
# Safely removes DeepPacketSentinel and Ulti_Argus components.

set -euo pipefail

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

# --- Variables ---
INSTALL_DIR="/opt/argus_v"
SYSTEMD_DIR="/etc/systemd/system"
RUN_DIR="/var/run/argus_v"
LOG_DIR="/var/log/argus_v"
SERVICES=("argus-brain.service" "argus-sentinel.service")
DRY_RUN=false

# --- Functions ---
log_info() { echo "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo "${YELLOW}[WARN]${NC} $1"; }
log_success() { echo "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo "${RED}[ERROR]${NC} $1"; }

run_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo "${YELLOW}[DRY RUN]${NC} $*"
    else
        "$@"
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root (sudo ./uninstall.sh)"
        exit 1
    fi
}

parse_args() {
    for arg in "$@"; do
        if [ "$arg" == "--dry-run" ]; then
            DRY_RUN=true
            log_warn "Dry run enabled. No changes will be made."
        fi
    done
}

stop_services() {
    log_info "Stopping services..."
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            run_cmd systemctl stop "$service"
            log_success "Stopped $service"
        else
            log_info "$service is not running."
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            run_cmd systemctl disable "$service"
            log_success "Disabled $service"
        fi
    done
}

remove_systemd_files() {
    log_info "Removing systemd service files..."
    local reload_needed=false
    for service in "${SERVICES[@]}"; do
        if [ -f "$SYSTEMD_DIR/$service" ]; then
            run_cmd rm -f "$SYSTEMD_DIR/$service"
            log_success "Removed $SYSTEMD_DIR/$service"
            reload_needed=true
        fi
    done

    if [ "$reload_needed" = true ]; then
        run_cmd systemctl daemon-reload
    fi
}

remove_files() {
    log_info "Removing installation files..."
    if [ -d "$INSTALL_DIR" ]; then
        run_cmd rm -rf "$INSTALL_DIR"
        log_success "Removed $INSTALL_DIR"
    else
        log_info "$INSTALL_DIR not found."
    fi

    if [ -d "$RUN_DIR" ]; then
        run_cmd rm -rf "$RUN_DIR"
        log_success "Removed $RUN_DIR"
    fi

    if [ -d "$LOG_DIR" ]; then
        run_cmd rm -rf "$LOG_DIR"
        log_success "Removed $LOG_DIR"
    fi
}

clean_iptables() {
    log_info "Checking for AEGIS-DROP iptables chain..."
    if command -v iptables >/dev/null 2>&1; then
        if iptables -L AEGIS-DROP -n >/dev/null 2>&1; then
            log_warn "Found AEGIS-DROP chain. Removing..."

            # Flush chain
            if [ "$DRY_RUN" = true ]; then
                echo "${YELLOW}[DRY RUN]${NC} iptables -F AEGIS-DROP"
            else
                iptables -F AEGIS-DROP 2>/dev/null || true
            fi

            # Remove references
            if [ "$DRY_RUN" = true ]; then
                 echo "${YELLOW}[DRY RUN]${NC} iptables -D INPUT -j AEGIS-DROP"
                 echo "${YELLOW}[DRY RUN]${NC} iptables -D FORWARD -j AEGIS-DROP"
            else
                iptables -D INPUT -j AEGIS-DROP 2>/dev/null || true
                iptables -D FORWARD -j AEGIS-DROP 2>/dev/null || true
            fi

            # Delete chain
            if [ "$DRY_RUN" = true ]; then
                echo "${YELLOW}[DRY RUN]${NC} iptables -X AEGIS-DROP"
            else
                iptables -X AEGIS-DROP 2>/dev/null || true
            fi

            log_success "Removed AEGIS-DROP chain."
        else
            log_info "No AEGIS-DROP chain found."
        fi
    else
        log_warn "iptables not found, skipping cleanup."
    fi
}

main() {
    check_root
    parse_args "$@"

    log_info "Starting uninstallation..."

    stop_services
    clean_iptables
    remove_systemd_files
    remove_files

    log_success "Uninstallation complete!"
}

main "$@"
