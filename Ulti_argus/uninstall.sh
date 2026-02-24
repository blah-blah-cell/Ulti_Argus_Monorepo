#!/usr/bin/env bash
#
# ARGUS_V Uninstallation Script
#
# This script safely removes ARGUS_V from the system, including:
# - Stopping and disabling all services
# - Removing systemd service files
# - Optionally removing configuration and data
#
# Usage:
#   sudo ./uninstall.sh                 # Interactive uninstall
#   sudo ./uninstall.sh --yes           # Non-interactive (preserve data)
#   sudo ./uninstall.sh --purge         # Remove everything including data
#

set -e
set -u

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/opt/argus_v"
CONFIG_DIR="/etc/argus_v"
DATA_DIR="/var/lib/argus_v"
LOG_DIR="/var/log/argus_v"
UPDATE_LOG_DIR="/var/log/argus"
RUN_DIR="/var/run/argus_v"
SYSTEMD_DIR="/etc/systemd/system"
CRON_ARGUS_UPDATE="/etc/cron.d/argus-v-update"

# Command line flags
AUTO_YES=false
PURGE=false

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

die() {
    error "$1"
    exit 1
}

print_banner() {
    cat << "EOF"
    ___    ____  ____________  _______   __
   /   |  / __ \/ ____/ / / / / ___/ | / /
  / /| | / /_/ / / __/ / / / /\__ \| |/ / 
 / ___ |/ _, _/ /_/ / /_/ /_____/ /|   /  
/_/  |_/_/ |_|\____/\____(_)____/_/ |_/   
                                           
Uninstallation Script
EOF
    echo ""
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --yes|-y)
                AUTO_YES=true
                shift
                ;;
            --purge)
                PURGE=true
                AUTO_YES=true
                shift
                ;;
            --help|-h)
                cat << EOF
ARGUS_V Uninstallation Script

Usage: sudo ./uninstall.sh [OPTIONS]

Options:
  --yes, -y       Non-interactive mode (preserve data)
  --purge         Remove everything including data and configuration
  --help, -h      Show this help message

Examples:
  # Interactive uninstall (prompts for data removal)
  sudo ./uninstall.sh

  # Quick uninstall (preserve data)
  sudo ./uninstall.sh --yes

  # Complete removal including all data
  sudo ./uninstall.sh --purge
EOF
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi
}

confirm() {
    local message="$1"
    
    if [[ "$AUTO_YES" == "true" ]]; then
        return 0
    fi
    
    read -p "$message (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

stop_services() {
    info "Stopping ARGUS_V services..."
    
    local services=(
        "argus-retina.service"
        "argus-aegis.service"
        "argus-mnemosyne.service"
        "argus-mnemosyne.timer"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            info "Stopping $service..."
            systemctl stop "$service" || warn "Failed to stop $service"
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            info "Disabling $service..."
            systemctl disable "$service" || warn "Failed to disable $service"
        fi
    done
    
    success "Services stopped and disabled"
}

remove_service_files() {
    info "Removing systemd service files..."
    
    local files=(
        "$SYSTEMD_DIR/argus-retina.service"
        "$SYSTEMD_DIR/argus-aegis.service"
        "$SYSTEMD_DIR/argus-mnemosyne.service"
        "$SYSTEMD_DIR/argus-mnemosyne.timer"
    )
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            info "Removed $file"
        fi
    done
    
    systemctl daemon-reload
    success "Service files removed"
}

remove_logrotate() {
    if [[ -f "/etc/logrotate.d/argus_v" ]]; then
        info "Removing logrotate configuration..."
        rm -f "/etc/logrotate.d/argus_v"
        success "Logrotate configuration removed"
    fi
}

remove_auto_update() {
    info "Removing automatic update infrastructure..."

    rm -f "$CRON_ARGUS_UPDATE" || true
    rm -f /usr/local/bin/argus-update /usr/local/bin/argus-rollback || true

    if [[ -d "$UPDATE_LOG_DIR" ]]; then
        if [[ "$PURGE" == "true" ]] || confirm "Remove update log directory ($UPDATE_LOG_DIR)?"; then
            rm -rf "$UPDATE_LOG_DIR"
            success "Update logs removed"
        else
            info "Update logs preserved: $UPDATE_LOG_DIR"
        fi
    fi
}

remove_installation() {
    if [[ -d "$INSTALL_DIR" ]]; then
        info "Removing installation directory: $INSTALL_DIR"
        rm -rf "$INSTALL_DIR"
        success "Installation directory removed"
    else
        info "Installation directory not found (already removed)"
    fi
}

remove_runtime() {
    if [[ -d "$RUN_DIR" ]]; then
        info "Removing runtime directory: $RUN_DIR"
        rm -rf "$RUN_DIR"
        success "Runtime directory removed"
    fi
}

remove_logs() {
    if [[ -d "$LOG_DIR" ]]; then
        if confirm "Remove log directory ($LOG_DIR)?"; then
            rm -rf "$LOG_DIR"
            success "Log directory removed"
        else
            info "Log directory preserved: $LOG_DIR"
        fi
    fi
}

remove_config() {
    if [[ -d "$CONFIG_DIR" ]]; then
        if [[ "$PURGE" == "true" ]] || confirm "Remove configuration directory ($CONFIG_DIR)?"; then
            # Backup sensitive configs before removal (if user wants)
            if [[ "$PURGE" != "true" ]] && confirm "Create backup of configuration files?"; then
                local backup_file="/tmp/argus_v_config_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                tar -czf "$backup_file" -C "$(dirname $CONFIG_DIR)" "$(basename $CONFIG_DIR)" 2>/dev/null || true
                if [[ -f "$backup_file" ]]; then
                    success "Configuration backed up to: $backup_file"
                fi
            fi
            
            rm -rf "$CONFIG_DIR"
            success "Configuration directory removed"
        else
            info "Configuration directory preserved: $CONFIG_DIR"
        fi
    fi
}

remove_data() {
    if [[ -d "$DATA_DIR" ]]; then
        if [[ "$PURGE" == "true" ]] || confirm "Remove data directory ($DATA_DIR)? This includes captured data, models, and databases."; then
            # Show size before removal
            local size=$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1 || echo "unknown")
            info "Data directory size: $size"
            
            if [[ "$PURGE" != "true" ]] && confirm "Are you absolutely sure? This cannot be undone."; then
                rm -rf "$DATA_DIR"
                success "Data directory removed"
            elif [[ "$PURGE" == "true" ]]; then
                rm -rf "$DATA_DIR"
                success "Data directory removed"
            else
                info "Data directory preserved: $DATA_DIR"
            fi
        else
            info "Data directory preserved: $DATA_DIR"
        fi
    fi
}

clean_iptables() {
    info "Checking for ARGUS_V iptables rules..."
    
    # Check if AEGIS-DROP chain exists
    if iptables -L AEGIS-DROP -n &>/dev/null; then
        warn "Found AEGIS-DROP iptables chain"
        
        if confirm "Remove AEGIS-DROP iptables chain and rules?"; then
            # Flush the chain
            iptables -F AEGIS-DROP 2>/dev/null || true
            
            # Remove references to the chain
            iptables -D INPUT -j AEGIS-DROP 2>/dev/null || true
            iptables -D FORWARD -j AEGIS-DROP 2>/dev/null || true
            
            # Delete the chain
            iptables -X AEGIS-DROP 2>/dev/null || true
            
            success "AEGIS-DROP iptables chain removed"
        else
            warn "iptables rules preserved - you may want to clean them manually"
        fi
    else
        info "No ARGUS_V iptables rules found"
    fi
}

show_summary() {
    echo ""
    info "============================================"
    success "ARGUS_V Uninstallation Complete"
    info "============================================"
    echo ""
    
    local remaining_items=()
    
    [[ -d "$CONFIG_DIR" ]] && remaining_items+=("Configuration: $CONFIG_DIR")
    [[ -d "$DATA_DIR" ]] && remaining_items+=("Data: $DATA_DIR")
    [[ -d "$LOG_DIR" ]] && remaining_items+=("Logs: $LOG_DIR")
    [[ -d "$UPDATE_LOG_DIR" ]] && remaining_items+=("Update logs: $UPDATE_LOG_DIR")
    
    if [[ ${#remaining_items[@]} -gt 0 ]]; then
        info "Preserved items:"
        for item in "${remaining_items[@]}"; do
            echo "  - $item"
        done
        echo ""
    else
        success "All ARGUS_V components removed from system"
    fi
}

main() {
    print_banner
    parse_args "$@"
    check_root
    
    warn "This will uninstall ARGUS_V from your system"
    echo ""
    
    if [[ "$AUTO_YES" != "true" ]]; then
        if ! confirm "Do you want to proceed with uninstallation?"; then
            info "Uninstallation cancelled"
            exit 0
        fi
    fi
    
    echo ""
    
    stop_services
    remove_service_files
    remove_logrotate
    remove_auto_update
    clean_iptables
    remove_installation
    remove_runtime
    remove_logs
    remove_config
    remove_data
    
    show_summary
}

main "$@"
