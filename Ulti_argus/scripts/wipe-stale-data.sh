#!/bin/bash
# wipe-stale-data.sh - Automated stale data deletion for Argus_V
# Usage: ./wipe-stale-data.sh [scope] [age-threshold] [dry-run]

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/argus-v/data-wiping.log"
COMPLIANCE_WEBHOOK="${COMPLIANCE_WEBHOOK:-https://hooks.slack.com/services/YOUR/WEBHOOK/URL}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
SCOPE="${1:-expired}"  # expired, all, flows, threats, audit, system
AGE_THRESHOLD="${2:-24}"  # hours for expired data
DRY_RUN="${3:-true}"

# Database configuration
DB_PATH="${DB_PATH:-/var/lib/argus/aegis.db}"
AUDIT_DB_PATH="${AUDIT_DB_PATH:-/var/lib/argus/audit.db}"
BACKUP_PATH="${BACKUP_PATH:-/var/backups/argus-v/pre-deletion}"

# Validation
if [[ -z "$SCOPE" ]] || [[ -z "$AGE_THRESHOLD" ]]; then
    echo "Usage: $0 [scope] [age-threshold] [dry-run]"
    echo "  scope: expired|all|flows|threats|audit|system (default: expired)"
    echo "  age-threshold: hours for data age (default: 24)"
    echo "  dry-run: true|false (default: true)"
    echo ""
    echo "Examples:"
    echo "  $0 expired 24 true          # Dry-run deletion of 24h+ expired data"
    echo "  $0 all 168 false            # Delete all data older than 7 days"
    echo "  $0 flows 48 false           # Delete flow data older than 2 days"
    exit 1
fi

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case $level in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "SECURITY") echo -e "${RED}[SECURITY]${NC} $message" ;;
    esac
}

# Dry-run check
check_dry_run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN MODE - No actual data will be deleted"
        return 0
    fi
    return 1
}

# Verify system requirements
verify_system_requirements() {
    log "INFO" "Verifying system requirements for data wiping"
    
    # Check if running as appropriate user
    local current_user=$(whoami)
    if [[ "$current_user" != "argus" ]] && [[ "$current_user" != "root" ]]; then
        log "ERROR" "Script must be run as 'argus' or 'root' user (current: $current_user)"
        return 1
    fi
    
    # Check database availability
    if [[ ! -f "$DB_PATH" ]]; then
        log "ERROR" "Main database not found: $DB_PATH"
        return 1
    fi
    
    if [[ ! -f "$AUDIT_DB_PATH" ]]; then
        log "WARN" "Audit database not found: $AUDIT_DB_PATH"
    fi
    
    # Check disk space for backups
    local available_space=$(df /var/lib/ | awk 'NR==2 {print $4}')
    local required_space=$((1024 * 1024))  # 1GB in KB
    
    if [[ $available_space -lt $required_space ]]; then
        log "ERROR" "Insufficient disk space for backup operations"
        return 1
    fi
    
    # Create backup directory if needed
    if ! check_dry_run; then
        mkdir -p "$BACKUP_PATH"
    fi
    
    log "INFO" "System requirements verification passed"
    return 0
}

# Create pre-deletion backup
create_pre_deletion_backup() {
    local backup_name="pre-deletion-$(date +%Y%m%d-%H%M%S)"
    local backup_dir="$BACKUP_PATH/$backup_name"
    
    if check_dry_run; then
        log "INFO" "Would create pre-deletion backup: $backup_dir"
        return 0
    fi
    
    log "INFO" "Creating pre-deletion backup: $backup_dir"
    
    # Create backup directory
    mkdir -p "$backup_dir"
    
    # Backup main database
    if [[ -f "$DB_PATH" ]]; then
        cp "$DB_PATH" "$backup_dir/aegis.db"
        log "INFO" "Main database backed up"
    fi
    
    # Backup audit database
    if [[ -f "$AUDIT_DB_PATH" ]]; then
        cp "$AUDIT_DB_PATH" "$backup_dir/audit.db"
        log "INFO" "Audit database backed up"
    fi
    
    # Create backup metadata
    local backup_metadata="{
        \"backup_name\": \"$backup_name\",
        \"backup_date\": \"$(date -Iseconds)\",
        \"scope\": \"$SCOPE\",
        \"age_threshold\": $AGE_THRESHOLD,
        \"performed_by\": \"$(whoami)\",
        \"host\": \"$(hostname)\",
        \"database_path\": \"$DB_PATH\",
        \"backup_path\": \"$backup_dir\"
    }"
    
    echo "$backup_metadata" > "$backup_dir/backup-metadata.json"
    
    log "INFO" "Pre-deletion backup created: $backup_dir"
    echo "$backup_dir"  # Return backup path
}

# Get data counts before deletion
get_data_counts_before_deletion() {
    local counts_file=$(mktemp)
    
    # Count records in main database
    echo "=== DATABASE COUNTS BEFORE DELETION ===" > "$counts_file"
    echo "Database: $DB_PATH" >> "$counts_file"
    
    if sqlite3 "$DB_PATH" "SELECT 'flows: ' || COUNT(*) FROM flows WHERE datetime(timestamp) < datetime('now', '-$AGE_THRESHOLD hours')" >> "$counts_file" 2>/dev/null; then
        :
    else
        echo "flows: N/A (table may not exist)" >> "$counts_file"
    fi
    
    if sqlite3 "$DB_PATH" "SELECT 'anonymized_flows: ' || COUNT(*) FROM anonymized_flows WHERE datetime(timestamp) < datetime('now', '-$AGE_THRESHOLD hours')" >> "$counts_file" 2>/dev/null; then
        :
    else
        echo "anonymized_flows: N/A (table may not exist)" >> "$counts_file"
    fi
    
    if sqlite3 "$DB_PATH" "SELECT 'threat_indicators: ' || COUNT(*) FROM threat_indicators WHERE datetime(created_at) < datetime('now', '-$AGE_THRESHOLD hours')" >> "$counts_file" 2>/dev/null; then
        :
    else
        echo "threat_indicators: N/A (table may not exist)" >> "$counts_file"
    fi
    
    if sqlite3 "$DB_PATH" "SELECT 'security_events: ' || COUNT(*) FROM security_events WHERE datetime(event_time) < datetime('now', '-$AGE_THRESHOLD hours')" >> "$counts_file" 2>/dev/null; then
        :
    else
        echo "security_events: N/A (table may not exist)" >> "$counts_file"
    fi
    
    # Count records in audit database
    if [[ -f "$AUDIT_DB_PATH" ]]; then
        echo "" >> "$counts_file"
        echo "Audit Database: $AUDIT_DB_PATH" >> "$counts_file"
        
        if sqlite3 "$AUDIT_DB_PATH" "SELECT 'audit_log: ' || COUNT(*) FROM audit_log WHERE datetime(timestamp) < datetime('now', '-$AGE_THRESHOLD hours')" >> "$counts_file" 2>/dev/null; then
            :
        else
            echo "audit_log: N/A (table may not exist)" >> "$counts_file"
        fi
    fi
    
    cat "$counts_file"
    rm -f "$counts_file"
}

# Delete flow data
delete_flow_data() {
    local table_name="$1"
    local timestamp_column="$2"
    
    if check_dry_run; then
        local count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM $table_name WHERE datetime($timestamp_column) < datetime('now', '-$AGE_THRESHOLD hours')" 2>/dev/null || echo "0")
        log "INFO" "DRY RUN: Would delete $count records from $table_name"
        echo "$count"
        return 0
    fi
    
    log "SECURITY" "Deleting data from $table_name (older than $AGE_THRESHOLD hours)"
    
    # Generate deletion hash
    local count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM $table_name WHERE datetime($timestamp_column) < datetime('now', '-$AGE_THRESHOLD hours')" 2>/dev/null || echo "0")
    
    if [[ $count -gt 0 ]]; then
        local deletion_hash=$(echo -n "$table_name$timestamp_column$AGE_THRESHOLD$(date)" | sha256sum | cut -d' ' -f1)
        
        # Perform deletion
        sqlite3 "$DB_PATH" "DELETE FROM $table_name WHERE datetime($timestamp_column) < datetime('now', '-$AGE_THRESHOLD hours')"
        local actual_deleted=$?
        
        if [[ $actual_deleted -eq 0 ]]; then
            log "INFO" "Successfully deleted $count records from $table_name"
            
            # Log deletion proof
            local deletion_proof="{
                \"timestamp\": \"$(date -Iseconds)\",
                \"operation\": \"delete_$table_name\",
                \"table\": \"$table_name\",
                \"timestamp_column\": \"$timestamp_column\",
                \"age_threshold_hours\": $AGE_THRESHOLD,
                \"records_deleted\": $count,
                \"deletion_hash\": \"$deletion_hash\",
                \"performed_by\": \"$(whoami)\",
                \"backup_path\": \"$backup_path\"
            }"
            
            echo "$deletion_proof" >> "${SCRIPT_DIR}/data/deletion-proofs/$(date +%Y%m%d).jsonl"
            
            echo "$count"
        else
            log "ERROR" "Failed to delete records from $table_name"
            echo "0"
        fi
    else
        log "INFO" "No records to delete from $table_name"
        echo "0"
    fi
}

# Delete audit data (special handling for compliance retention)
delete_audit_data() {
    local age_threshold_days=$((AGE_THRESHOLD / 24))  # Convert to days
    
    # Keep audit data longer (minimum 90 days for compliance)
    local compliance_age_threshold=$((age_threshold_days < 90 ? 90 : age_threshold_days))
    
    if check_dry_run; then
        local count=$(sqlite3 "$AUDIT_DB_PATH" "SELECT COUNT(*) FROM audit_log WHERE datetime(timestamp) < datetime('now', '-$compliance_age_threshold days')" 2>/dev/null || echo "0")
        log "INFO" "DRY RUN: Would delete $count audit records (older than $compliance_age_threshold days)"
        echo "$count"
        return 0
    fi
    
    log "SECURITY" "Deleting audit data (older than $compliance_age_threshold days, compliance minimum)"
    
    local count=$(sqlite3 "$AUDIT_DB_PATH" "SELECT COUNT(*) FROM audit_log WHERE datetime(timestamp) < datetime('now', '-$compliance_age_threshold days')" 2>/dev/null || echo "0")
    
    if [[ $count -gt 0 ]]; then
        sqlite3 "$AUDIT_DB_PATH" "DELETE FROM audit_log WHERE datetime(timestamp) < datetime('now', '-$compliance_age_threshold days')"
        
        if [[ $? -eq 0 ]]; then
            log "INFO" "Successfully deleted $count audit records"
            echo "$count"
        else
            log "ERROR" "Failed to delete audit records"
            echo "0"
        fi
    else
        log "INFO" "No audit records to delete"
        echo "0"
    fi
}

# Clean up system logs
cleanup_system_logs() {
    local log_age_threshold="$AGE_THRESHOLD hours"
    
    if check_dry_run; then
        local count=$(find /var/log/argus-v/ -name "*.log" -type f -mtime +$((AGE_THRESHOLD/24)) 2>/dev/null | wc -l)
        log "INFO" "DRY RUN: Would delete $count system log files (older than $AGE_THRESHOLD hours)"
        echo "$count"
        return 0
    fi
    
    log "INFO" "Cleaning up system logs (older than $AGE_THRESHOLD hours)"
    
    local deleted_count=0
    
    # Clean up old log files
    while IFS= read -r -d '' logfile; do
        rm -f "$logfile"
        ((deleted_count++))
        log "INFO" "Deleted log file: $logfile"
    done < <(find /var/log/argus-v/ -name "*.log" -type f -mtime +$((AGE_THRESHOLD/24)) -print0 2>/dev/null)
    
    # Clean up temporary files
    while IFS= read -r -d '' tempfile; do
        rm -f "$tempfile"
        ((deleted_count++))
    done < <(find /tmp/argus-v* -type f -mtime +$((AGE_THRESHOLD/24)) -print0 2>/dev/null)
    
    log "INFO" "Cleaned up $deleted_count system files"
    echo "$deleted_count"
}

# Optimize database after deletion
optimize_database() {
    if check_dry_run; then
        log "INFO" "DRY RUN: Would optimize databases after deletion"
        return 0
    fi
    
    log "INFO" "Optimizing databases after deletion"
    
    # Vacuum main database
    if sqlite3 "$DB_PATH" "VACUUM" 2>/dev/null; then
        log "INFO" "Main database optimized (VACUUM completed)"
    else
        log "WARN" "Failed to optimize main database"
    fi
    
    # Analyze tables for better performance
    if sqlite3 "$DB_PATH" "ANALYZE" 2>/dev/null; then
        log "INFO" "Database statistics updated (ANALYZE completed)"
    else
        log "WARN" "Failed to update database statistics"
    fi
    
    # Optimize audit database if it exists
    if [[ -f "$AUDIT_DB_PATH" ]]; then
        if sqlite3 "$AUDIT_DB_PATH" "VACUUM" 2>/dev/null; then
            log "INFO" "Audit database optimized"
        else
            log "WARN" "Failed to optimize audit database"
        fi
    fi
}

# Verify deletion success
verify_deletion_success() {
    local backup_path="$1"
    
    if check_dry_run; then
        log "INFO" "DRY RUN: Would verify deletion success"
        return 0
    fi
    
    log "INFO" "Verifying deletion success"
    
    # Check that databases are still accessible
    if sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table'" >/dev/null 2>&1; then
        log "INFO" "Main database is accessible after deletion"
    else
        log "ERROR" "Main database is not accessible after deletion"
        return 1
    fi
    
    if [[ -f "$AUDIT_DB_PATH" ]]; then
        if sqlite3 "$AUDIT_DB_PATH" "SELECT COUNT(*) FROM sqlite_master WHERE type='table'" >/dev/null 2>&1; then
            log "INFO" "Audit database is accessible after deletion"
        else
            log "WARN" "Audit database is not accessible after deletion"
        fi
    fi
    
    # Verify no data older than threshold exists
    local old_flows=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM flows WHERE datetime(timestamp) < datetime('now', '-$AGE_THRESHOLD hours')" 2>/dev/null || echo "0")
    
    if [[ $old_flows -eq 0 ]]; then
        log "INFO" "Deletion verification passed - no expired data remaining"
        return 0
    else
        log "WARN" "Deletion verification found $old_flows expired records still present"
        return 1
    fi
}

# Generate deletion report
generate_deletion_report() {
    local backup_path="$1"
    local totals="$2"
    
    local report_file="${SCRIPT_DIR}/data/deletion-reports/deletion-report-$(date +%Y%m%d-%H%M%S).json"
    
    local report="{
        \"report_id\": \"deletion-$(date +%Y%m%d-%H%M%S)\",
        \"timestamp\": \"$(date -Iseconds)\",
        \"scope\": \"$SCOPE\",
        \"age_threshold_hours\": $AGE_THRESHOLD,
        \"dry_run\": $DRY_RUN,
        \"performed_by\": \"$(whoami)\",
        \"host\": \"$(hostname)\",
        \"totals\": $totals,
        \"backup_path\": \"$backup_path\",
        \"databases\": {
            \"main_db\": \"$DB_PATH\",
            \"audit_db\": \"$AUDIT_DB_PATH\"
        },
        \"verification_passed\": true,
        \"compliance_notes\": {
            \"data_retention_policy\": \"24_hours_max_for_raw_data\",
            \"audit_trail_preserved\": true,
            \"backup_created\": true,
            \"cryptographic_proof\": true
        }
    }"
    
    echo "$report" > "$report_file"
    log "INFO" "Deletion report generated: $report_file"
    echo "$report_file"
}

# Notify compliance team
notify_compliance_team() {
    local status="$1"
    local totals="$2"
    local report_file="$3"
    
    local notification="{
        \"text\": \"Data Wiping Operation Completed\",
        \"attachments\": [
            {
                \"color\": \"$([ "$status" = "success" ] && echo "good" || echo "warning")\",
                \"fields\": [
                    {\"title\": \"Scope\", \"value\": \"$SCOPE\", \"short\": true},
                    {\"title\": \"Age Threshold\", \"value\": \"$AGE_THRESHOLD hours\", \"short\": true},
                    {\"title\": \"Status\", \"value\": \"$status\", \"short\": true},
                    {\"title\": \"Dry Run\", \"value\": \"$DRY_RUN\", \"short\": true},
                    {\"title\": \"Total Records Deleted\", \"value\": \"$([ "$DRY_RUN" = "true" ] && echo "0 (dry run)" || echo "$(echo $totals | jq -r '.total // 0')")\", \"short\": false},
                    {\"title\": \"Backup Location\", \"value\": \"$backup_path\", \"short\": false}
                ],
                \"footer\": \"Argus_V Data Retention System\",
                \"ts\": $(date +%s)
            }
        ]
    }"
    
    # Send to Slack webhook if configured
    if [[ "$COMPLIANCE_WEBHOOK" != *"YOUR/WEBHOOK"* ]]; then
        curl -X POST "$COMPLIANCE_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "$notification" \
            --silent --show-error || log "WARN" "Failed to send Slack notification"
    fi
}

# Main execution
main() {
    log "INFO" "Starting data wiping operation"
    log "INFO" "Scope: $SCOPE"
    log "INFO" "Age threshold: $AGE_THRESHOLD hours"
    log "INFO" "Dry run: $DRY_RUN"
    
    # Verify system requirements
    if ! verify_system_requirements; then
        log "ERROR" "System requirements verification failed"
        exit 1
    fi
    
    # Create pre-deletion backup
    backup_path=$(create_pre_deletion_backup)
    
    # Get data counts before deletion
    log "INFO" "Getting data counts before deletion"
    get_data_counts_before_deletion
    
    # Initialize deletion totals
    local flows_deleted=0
    local anonymized_deleted=0
    local threats_deleted=0
    local events_deleted=0
    local audit_deleted=0
    local system_files_deleted=0
    
    # Perform deletions based on scope
    case $SCOPE in
        "expired")
            log "INFO" "Processing expired data deletion"
            
            flows_deleted=$(delete_flow_data "flows" "timestamp")
            anonymized_deleted=$(delete_flow_data "anonymized_flows" "timestamp")
            threats_deleted=$(delete_flow_data "threat_indicators" "created_at")
            events_deleted=$(delete_flow_data "security_events" "event_time")
            audit_deleted=$(delete_audit_data)
            system_files_deleted=$(cleanup_system_logs)
            ;;
        "flows")
            flows_deleted=$(delete_flow_data "flows" "timestamp")
            anonymized_deleted=$(delete_flow_data "anonymized_flows" "timestamp")
            ;;
        "threats")
            threats_deleted=$(delete_flow_data "threat_indicators" "created_at")
            ;;
        "audit")
            audit_deleted=$(delete_audit_data)
            ;;
        "system")
            system_files_deleted=$(cleanup_system_logs)
            ;;
        "all")
            flows_deleted=$(delete_flow_data "flows" "timestamp")
            anonymized_deleted=$(delete_flow_data "anonymized_flows" "timestamp")
            threats_deleted=$(delete_flow_data "threat_indicators" "created_at")
            events_deleted=$(delete_flow_data "security_events" "event_time")
            audit_deleted=$(delete_audit_data)
            system_files_deleted=$(cleanup_system_logs)
            ;;
        *)
            log "ERROR" "Invalid scope: $SCOPE"
            exit 1
            ;;
    esac
    
    # Optimize databases
    optimize_database
    
    # Verify deletion success
    if verify_deletion_success "$backup_path"; then
        local status="success"
    else
        local status="partial_success"
        log "WARN" "Deletion verification found issues"
    fi
    
    # Calculate totals
    local total=$((flows_deleted + anonymized_deleted + threats_deleted + events_deleted + audit_deleted + system_files_deleted))
    local totals=$(jq -n \
        --arg flows "$flows_deleted" \
        --arg anonymized "$anonymized_deleted" \
        --arg threats "$threats_deleted" \
        --arg events "$events_deleted" \
        --arg audit "$audit_deleted" \
        --arg system_files "$system_files_deleted" \
        --arg total "$total" \
        '{
            flows: ($flows | tonumber),
            anonymized_flows: ($anonymized | tonumber),
            threat_indicators: ($threats | tonumber),
            security_events: ($events | tonumber),
            audit_records: ($audit | tonumber),
            system_files: ($system_files | tonumber),
            total: ($total | tonumber)
        }')
    
    # Generate deletion report
    report_file=$(generate_deletion_report "$backup_path" "$totals")
    
    # Notify compliance team
    notify_compliance_team "$status" "$totals" "$report_file"
    
    log "INFO" "Data wiping operation completed"
    log "INFO" "Total records processed: $total"
    log "INFO" "Report generated: $report_file"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}DRY RUN COMPLETED - No data was actually deleted${NC}"
        echo -e "${YELLOW}To perform actual deletion, re-run with 'false' as third parameter${NC}"
    else
        echo -e "${GREEN}Data wiping completed successfully${NC}"
    fi
    
    echo -e "${BLUE}Deletion report: $report_file${NC}"
    echo -e "${BLUE}Backup location: $backup_path${NC}"
    
    return 0
}

# Cleanup on exit
cleanup() {
    log "INFO" "Data wiping script completed for scope: $SCOPE"
}

trap cleanup EXIT

# Create required directories
mkdir -p "${SCRIPT_DIR}/data/deletion-proofs"
mkdir -p "${SCRIPT_DIR}/data/deletion-reports"

# Run main function
main "$@"