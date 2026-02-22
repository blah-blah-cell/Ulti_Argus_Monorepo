#!/usr/bin/env bash

set -euo pipefail

BASE_DIR="/opt/argus_v"
RELEASES_DIR="${BASE_DIR}/releases"
CURRENT_LINK="${BASE_DIR}/current"
VENV_LINK="${BASE_DIR}/venv"

CONFIG_FILE="/etc/argus_v/update.conf"
LOG_FILE="/var/log/argus/updates.log"
STATE_DIR="/var/lib/argus_v/update"
LAST_RUN_FILE="${STATE_DIR}/last_run"
LOCK_FILE="/var/run/argus_v/argus-update.lock"

DEFAULT_REPO="Ojas-bb/Argus_V"
DEFAULT_SCHEDULE="0 2 * * 0" # Sunday 02:00 UTC
DEFAULT_KEEP_VERSIONS="2"
DEFAULT_SERVICES="argus-retina argus-aegis"

CRON_MODE=false
FORCE_UPDATE=false

info() {
    log "INFO" "$*"
}

warn() {
    log "WARN" "$*"
}

error() {
    log "ERROR" "$*"
}

log() {
    local level="$1"
    shift

    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    mkdir -p "$(dirname "$LOG_FILE")" || true
    echo "${ts} [${level}] $*" | tee -a "$LOG_FILE" >&2
}

die() {
    error "$*"
    exit 1
}

require_root() {
    if [[ ${EUID:-0} -ne 0 ]]; then
        die "This command must be run as root"
    fi
}

load_config() {
    # Defaults
    ARGUS_UPDATE_REPO="$DEFAULT_REPO"
    ARGUS_UPDATE_SCHEDULE="$DEFAULT_SCHEDULE"
    ARGUS_UPDATE_KEEP_VERSIONS="$DEFAULT_KEEP_VERSIONS"
    ARGUS_UPDATE_SERVICES="$DEFAULT_SERVICES"
    ARGUS_UPDATE_ENABLED="true"

    if [[ -f "$CONFIG_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$CONFIG_FILE"
    fi
}

acquire_lock() {
    mkdir -p "$(dirname "$LOCK_FILE")" || true
    exec 9>"$LOCK_FILE"
    if ! flock -n 9; then
        warn "Another update is already in progress. Exiting."
        exit 0
    fi
}

strip_v() {
    echo "${1#v}"
}

is_newer_version() {
    # Returns 0 if $1 is newer than $2
    local a b
    a=$(strip_v "$1")
    b=$(strip_v "$2")

    if [[ -z "$b" ]]; then
        return 0
    fi

    if [[ "$a" == "$b" ]]; then
        return 1
    fi

    local newest
    newest=$(printf '%s\n' "$a" "$b" | sort -V | tail -n 1)
    [[ "$newest" == "$a" ]]
}

get_current_version() {
    if [[ -L "$CURRENT_LINK" && -f "$CURRENT_LINK/VERSION" ]]; then
        cat "$CURRENT_LINK/VERSION"
        return 0
    fi

    if [[ -x "$VENV_LINK/bin/python" ]]; then
        "$VENV_LINK/bin/python" -c 'import argus_v; print("v" + argus_v.__version__)' 2>/dev/null || true
        return 0
    fi

    echo ""
}

get_latest_tag() {
    local url effective
    url="https://github.com/${ARGUS_UPDATE_REPO}/releases/latest"

    if ! effective=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$url"); then
        return 1
    fi

    echo "${effective##*/}"
}

cron_field_matches() {
    # Supports: "*", "n", "a-b", "*/s", "a-b/s", and comma lists of those.
    local field="$1"
    local value="$2"
    local min="$3"
    local max="$4"

    local part
    IFS=',' read -ra parts <<<"$field"
    for part in "${parts[@]}"; do
        if [[ "$part" == "*" ]]; then
            return 0
        fi

        local step=""
        local base="$part"
        if [[ "$part" == */* ]]; then
            step="${part##*/}"
            base="${part%%/*}"
            [[ "$step" =~ ^[0-9]+$ ]] || continue
        fi

        local start end
        if [[ "$base" == "*" ]]; then
            start="$min"
            end="$max"
        elif [[ "$base" == *-* ]]; then
            start="${base%%-*}"
            end="${base##*-}"
        else
            start="$base"
            end="$base"
        fi

        [[ "$start" =~ ^[0-9]+$ ]] || continue
        [[ "$end" =~ ^[0-9]+$ ]] || continue

        if (( value < start || value > end )); then
            continue
        fi

        if [[ -n "$step" ]]; then
            if (( (value - start) % step == 0 )); then
                return 0
            fi
            continue
        fi

        return 0
    done

    return 1
}

cron_matches_now_utc() {
    local expr="$1"

    local minute hour dom month dow
    read -r minute hour dom month dow <<<"$expr"

    [[ -n "${dow:-}" ]] || return 1

    local now_min now_hour now_dom now_month now_dow
    now_min=$(date -u '+%M')
    now_hour=$(date -u '+%H')
    now_dom=$(date -u '+%d')
    now_month=$(date -u '+%m')
    now_dow=$(date -u '+%w')

    # shellcheck disable=SC2004
    cron_field_matches "$minute" "$((10#$now_min))" 0 59 || return 1
    cron_field_matches "$hour" "$((10#$now_hour))" 0 23 || return 1
    cron_field_matches "$dom" "$((10#$now_dom))" 1 31 || return 1
    cron_field_matches "$month" "$((10#$now_month))" 1 12 || return 1
    cron_field_matches "$dow" "$((10#$now_dow))" 0 6 || return 1

    return 0
}

already_ran_this_minute() {
    mkdir -p "$STATE_DIR" || true

    local stamp
    stamp=$(date -u '+%Y-%m-%dT%H:%M')

    if [[ -f "$LAST_RUN_FILE" ]] && [[ "$(cat "$LAST_RUN_FILE" 2>/dev/null || true)" == "$stamp" ]]; then
        return 0
    fi

    echo "$stamp" > "$LAST_RUN_FILE"
    return 1
}

download_with_retries() {
    local url="$1"
    local out="$2"

    curl -fL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 600 -o "$out" "$url"
}

ensure_layout() {
    mkdir -p "$RELEASES_DIR" "$STATE_DIR" || true

    if [[ ! -L "$VENV_LINK" ]] && [[ -d "$VENV_LINK" ]]; then
        warn "Detected legacy layout (venv is a directory at $VENV_LINK). Auto-updates require the symlink layout created by newer installers."
        warn "Please re-run the installer from a recent release to migrate." 
        return 1
    fi

    return 0
}

list_running_services() {
    local svc
    for svc in $ARGUS_UPDATE_SERVICES; do
        if systemctl is-active --quiet "${svc}.service" 2>/dev/null; then
            echo "$svc"
        fi
    done
}

restart_services() {
    local services=("$@")

    if [[ ${#services[@]} -eq 0 ]]; then
        warn "No running ARGUS services detected to restart"
        return 0
    fi

    local svc
    for svc in "${services[@]}"; do
        info "Restarting ${svc}.service"
        systemctl restart "${svc}.service"
    done
}

wait_for_service_active() {
    local svc="$1"
    local timeout_seconds="${2:-30}"

    local start
    start=$(date +%s)

    while true; do
        if systemctl is-active --quiet "${svc}.service" 2>/dev/null; then
            return 0
        fi

        if (( $(date +%s) - start >= timeout_seconds )); then
            return 1
        fi

        sleep 1
    done
}

health_check() {
    local services=("$@")

    if [[ ${#services[@]} -eq 0 ]]; then
        warn "No running ARGUS services detected for health check"
        return 0
    fi

    local svc
    for svc in "${services[@]}"; do
        if wait_for_service_active "$svc" 30; then
            info "Health check OK: ${svc}.service is active"
        else
            error "Health check FAILED: ${svc}.service is not active"
            return 1
        fi
    done

    return 0
}

install_tools_from_release() {
    local release_dir="$1"
    local src_update="${release_dir}/src/argus_v/deploy/update.sh"
    local src_rb="${release_dir}/src/argus_v/deploy/argus-rollback"

    if [[ -f "$src_update" ]]; then
        install -m 0755 "$src_update" /usr/local/bin/argus-update
    fi

    if [[ -f "$src_rb" ]]; then
        install -m 0755 "$src_rb" /usr/local/bin/argus-rollback
    fi
}

prune_old_releases() {
    local keep="$1"

    mapfile -t dirs < <(find "$RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | awk '{print $2}')

    local current_target=""
    if [[ -L "$CURRENT_LINK" ]]; then
        current_target=$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)
    fi

    local idx=0
    local dir
    for dir in "${dirs[@]}"; do
        ((idx++))

        if [[ "$idx" -le "$keep" ]]; then
            continue
        fi

        if [[ -n "$current_target" && "$(readlink -f "$dir" 2>/dev/null || true)" == "$current_target" ]]; then
            continue
        fi

        warn "Pruning old release: $dir"
        rm -rf "$dir" || true
    done
}

perform_update() {
    require_root
    load_config
    acquire_lock

    if [[ "${ARGUS_UPDATE_ENABLED}" != "true" ]]; then
        info "Automatic updates are disabled (ARGUS_UPDATE_ENABLED != true)."
        exit 0
    fi

    if ! ensure_layout; then
        if [[ "$CRON_MODE" == "true" ]]; then
            exit 0
        fi
        die "Unsupported installation layout; expected $VENV_LINK to be a symlink (newer installs create /opt/argus_v/current + /opt/argus_v/venv)."
    fi

    local current latest
    current=$(get_current_version)

    info "Current version: ${current:-unknown}"

    if ! latest=$(get_latest_tag); then
        if [[ "$CRON_MODE" == "true" ]]; then
            warn "Unable to check for updates (network/GitHub failure)."
            exit 0
        fi
        die "Unable to check for updates (network/GitHub failure)."
    fi

    info "Latest release tag: $latest"

    if [[ "$FORCE_UPDATE" == "false" ]] && [[ -n "$current" ]] && ! is_newer_version "$latest" "$current"; then
        info "No update available."
        exit 0
    fi

    local tar_name tar_url sums_url
    tar_name="argus_v-${latest}.tar.gz"
    tar_url="https://github.com/${ARGUS_UPDATE_REPO}/releases/download/${latest}/${tar_name}"
    sums_url="https://github.com/${ARGUS_UPDATE_REPO}/releases/download/${latest}/SHA256SUMS"

    local tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    info "Downloading ${tar_name}"
    if ! download_with_retries "$tar_url" "${tmp}/${tar_name}"; then
        if [[ "$CRON_MODE" == "true" ]]; then
            warn "Failed to download release tarball."
            exit 0
        fi
        die "Failed to download release tarball."
    fi

    info "Downloading SHA256SUMS"
    if ! download_with_retries "$sums_url" "${tmp}/SHA256SUMS"; then
        if [[ "$CRON_MODE" == "true" ]]; then
            warn "Failed to download SHA256SUMS."
            exit 0
        fi
        die "Failed to download SHA256SUMS."
    fi

    local expected
    expected=$(grep " ${tar_name}$" "${tmp}/SHA256SUMS" | awk '{print $1}' | head -n 1 || true)
    if [[ -z "$expected" ]]; then
        die "Checksum for ${tar_name} not found in SHA256SUMS"
    fi

    local actual
    actual=$(sha256sum "${tmp}/${tar_name}" | awk '{print $1}')
    if [[ "$expected" != "$actual" ]]; then
        die "Checksum mismatch for ${tar_name} (expected ${expected}, got ${actual})"
    fi

    info "Checksum verified"

    local extract_dir
    extract_dir="${tmp}/extract"
    mkdir -p "$extract_dir"
    tar -xzf "${tmp}/${tar_name}" -C "$extract_dir"

    local top
    top=$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d -name 'argus_v-*' | head -n 1 || true)
    if [[ -z "$top" ]]; then
        die "Unexpected tarball structure (no top-level argus_v-* directory)"
    fi

    local release_dir
    release_dir="${RELEASES_DIR}/$(basename "$top")"

    if [[ -e "$release_dir" ]]; then
        warn "Release directory already exists: $release_dir (will replace)"
        rm -rf "$release_dir"
    fi

    mv "$top" "$release_dir"
    echo "$latest" > "${release_dir}/VERSION"

    local pybin
    if command -v python3.11 &>/dev/null; then
        pybin="python3.11"
    else
        pybin="python3"
    fi

    info "Creating venv for ${latest}"
    "${pybin}" -m venv "${release_dir}/venv"

    source "${release_dir}/venv/bin/activate"
    pip install --quiet --upgrade pip setuptools wheel
    info "Installing ARGUS_V package into venv"
    pip install --quiet "${release_dir}"
    pip install --quiet joblib || true
    deactivate

    local old_target
    old_target=$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)

    info "Switching active release to ${latest}"
    ln -sfn "$release_dir" "$CURRENT_LINK"
    ln -sfn "${CURRENT_LINK}/venv" "$VENV_LINK"

    local expected_services=()
    mapfile -t expected_services < <(list_running_services)

    systemctl daemon-reload || true
    restart_services "${expected_services[@]}"

    if ! health_check "${expected_services[@]}"; then
        error "Critical error after update. Rolling back."
        if [[ -n "$old_target" ]]; then
            ln -sfn "$old_target" "$CURRENT_LINK"
            ln -sfn "${CURRENT_LINK}/venv" "$VENV_LINK"
            systemctl daemon-reload || true
            restart_services "${expected_services[@]}" || true
            health_check "${expected_services[@]}" || true
        fi
        die "Update failed; rollback attempted"
    fi

    install_tools_from_release "$release_dir"
    prune_old_releases "${ARGUS_UPDATE_KEEP_VERSIONS}"

    success "Update to ${latest} completed"
}

success() {
    log "SUCCESS" "$*"
}

usage() {
    cat <<EOF
ARGUS automatic updater

Usage:
  argus-update [--force]
  argus-update --cron

Options:
  --cron     Only run when current UTC time matches ARGUS_UPDATE_SCHEDULE
  --force    Install latest release even if already on latest
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --cron)
                CRON_MODE=true
                shift
                ;;
            --force)
                FORCE_UPDATE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    if [[ "$CRON_MODE" == "true" ]]; then
        load_config

        if [[ "${ARGUS_UPDATE_ENABLED}" != "true" ]]; then
            exit 0
        fi

        if ! cron_matches_now_utc "${ARGUS_UPDATE_SCHEDULE}"; then
            exit 0
        fi

        if already_ran_this_minute; then
            exit 0
        fi

        perform_update
        exit 0
    fi

    perform_update
}

main "$@"
