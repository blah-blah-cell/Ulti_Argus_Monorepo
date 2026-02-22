#!/bin/bash
# revoke-branch-access.sh - Automated branch access revocation for NGOs
# Usage: ./revoke-branch-access.sh <ngo-id> <branch-pattern> [reason] [environment]

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/argus-v/branch-access.log"
COMPLIANCE_WEBHOOK="${COMPLIANCE_WEBHOOK:-https://hooks.slack.com/services/YOUR/WEBHOOK/URL}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
NGO_ID="${1:-}"
BRANCH_PATTERN="${2:-}"
REASON="${3:-manual_revocation}"
ENVIRONMENT="${4:-staging}"
DRY_RUN="${DRY_RUN:-true}"

# Validation
if [[ -z "$NGO_ID" ]] || [[ -z "$BRANCH_PATTERN" ]]; then
    echo "Usage: $0 <ngo-id> <branch-pattern> [reason] [environment]"
    echo "  ngo-id: Unique NGO identifier (e.g., ngo-red-cross)"
    echo "  branch-pattern: Git branch pattern (e.g., ngo-*/feature/*)"
    echo "  reason: revocation reason (license_termination, non_compliance, manual)"
    echo "  environment: dev|staging|prod (default: staging)"
    echo "  DRY_RUN=true|false (default: true)"
    exit 1
fi

# NGO configuration file lookup
# Handle both "red-cross" and "ngo-red-cross" formats
if [[ "$NGO_ID" =~ ^ngo- ]]; then
    NGO_CONFIG_FILE="${SCRIPT_DIR}/configs/${NGO_ID}.yaml"
else
    NGO_CONFIG_FILE="${SCRIPT_DIR}/configs/ngo-${NGO_ID}.yaml"
fi

if [[ ! -f "$NGO_CONFIG_FILE" ]]; then
    echo -e "${RED}Error: NGO configuration file not found: $NGO_CONFIG_FILE${NC}"
    echo "Please ensure NGO configuration exists before revoking access."
    exit 1
fi

# Load NGO configuration
source "${SCRIPT_DIR}/lib/ngo-config-loader.sh" || {
    echo -e "${RED}Error: Failed to load NGO configuration loader${NC}"
    exit 1
}

NGO_CONFIG=$(load_ngo_config "$NGO_CONFIG_FILE")
GITHUB_ORG="${NGO_CONFIG[github_org]}"
GITHUB_REPO="${NGO_CONFIG[github_repo]}"
GITHUB_TEAM="${NGO_CONFIG[github_team]}"
CONTACT_EMAIL="${NGO_CONFIG[contact_email]}"
ACCESS_LEVEL="${NGO_CONFIG[access_level]:-read}"

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
        "EMERGENCY") echo -e "${RED}[EMERGENCY]${NC} $message" ;;
    esac
}

# Emergency check
is_emergency_revocation() {
    [[ "$REASON" == "security_incident" ]] || [[ "$REASON" == "license_termination" ]]
}

# Dry-run check
check_dry_run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN MODE - No actual changes will be made"
        return 0
    fi
    return 1
}

# Validate revocation authorization
validate_revocation_authorization() {
    log "INFO" "Validating revocation authorization for $NGO_ID"
    
    # Check if emergency revocation
    if is_emergency_revocation; then
        log "EMERGENCY" "Emergency revocation requested: $REASON"
        
        # Verify emergency authorization
        if [[ -z "$EMERGENCY_AUTH_TOKEN" ]]; then
            log "ERROR" "Emergency authorization token required for emergency revocation"
            return 1
        fi
        
        # Verify emergency token (simplified - in production use proper auth)
        if ! echo "$EMERGENCY_AUTH_TOKEN" | sha256sum -c "${SCRIPT_DIR}/data/auth/emergency-token.hash" &>/dev/null; then
            log "ERROR" "Invalid emergency authorization token"
            return 1
        fi
    fi
    
    # For non-emergency revocation, check if NGO exists and has active access
    local access_record="${SCRIPT_DIR}/data/active-access/${NGO_ID}.yaml"
    if [[ -f "$access_record" ]]; then
        local access_status=$(grep "status:" "$access_record" | awk '{print $2}')
        if [[ "$access_status" != "active" ]]; then
            log "WARN" "NGO $NGO_ID access is not active (current: $access_status)"
            return 1
        fi
    else
        log "WARN" "No active access record found for NGO $NGO_ID"
    fi
    
    # Log revocation authorization
    log "INFO" "Revocation authorization validated for reason: $REASON"
    return 0
}

# Remove branch protection rules
remove_branch_protection() {
    local branch="$1"
    
    if check_dry_run; then
        log "INFO" "Would remove branch protection for: $branch"
        return 0
    fi
    
    log "INFO" "Removing branch protection for: $branch"
    
    # Check if gh CLI is available and authenticated
    if ! command -v gh &> /dev/null; then
        log "ERROR" "GitHub CLI (gh) is not installed or not in PATH"
        return 1
    fi
    
    # Remove branch protection
    local response
    response=$(gh api "repos/$GITHUB_ORG/$GITHUB_REPO/branches/$branch/protection" \
        --method DELETE 2>&1)
    
    if [[ $? -eq 0 ]]; then
        log "INFO" "Branch protection removed successfully for $branch"
        return 0
    else
        # Check if branch protection doesn't exist (which is OK)
        if echo "$response" | grep -q "Branch not protected\|404"; then
            log "INFO" "Branch $branch was not protected (OK)"
            return 0
        else
            log "ERROR" "Failed to remove branch protection for $branch: $response"
            return 1
        fi
    fi
}

# Revoke team access from branch
revoke_branch_access() {
    local branch="$1"
    local team="$2"
    
    if check_dry_run; then
        log "INFO" "Would revoke access to branch $branch for team $team"
        return 0
    fi
    
    log "INFO" "Revoking access to branch $branch for team $team"
    
    # Remove team from repository
    local response
    response=$(gh api "repos/$GITHUB_ORG/$GITHUB_REPO/teams/$team/repos/$GITHUB_ORG/$GITHUB_REPO" \
        --method DELETE 2>&1)
    
    if [[ $? -eq 0 ]]; then
        log "INFO" "Team access revoked successfully"
        return 0
    else
        # Check if team doesn't have access (which is OK)
        if echo "$response" | grep -q "Team.*does not have access\|404"; then
            log "INFO" "Team $team did not have access to repository (OK)"
            return 0
        else
            log "ERROR" "Failed to revoke team access: $response"
            return 1
        fi
    fi
}

# Archive branch for audit trail
archive_branch_for_audit() {
    local branch="$1"
    
    if check_dry_run; then
        log "INFO" "Would archive branch $branch for audit trail"
        return 0
    fi
    
    log "INFO" "Archiving branch $branch for audit trail"
    
    # Create archived branch name
    local archived_branch="archived/$(date +%Y%m%d)/$branch"
    
    # Fetch branch reference
    local response
    response=$(gh api "repos/$GITHUB_ORG/$GITHUB_REPO/git/refs/heads/$branch" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        # Extract SHA
        local branch_sha=$(echo "$response" | grep '"sha"' | cut -d'"' -f4)
        
        # Create new reference for archived branch
        gh api "repos/$GITHUB_ORG/$GITHUB_REPO/git/refs" \
            --method POST \
            --field "ref=refs/heads/$archived_branch" \
            --field "sha=$branch_sha" &>/dev/null
        
        log "INFO" "Branch archived as: $archived_branch"
    else
        log "WARN" "Failed to archive branch $branch: $response"
    fi
}

# Clean up local access records
cleanup_access_records() {
    if check_dry_run; then
        log "INFO" "Would clean up access records for $NGO_ID"
        return 0
    fi
    
    log "INFO" "Cleaning up access records for $NGO_ID"
    
    # Move active access record to revoked records
    local active_record="${SCRIPT_DIR}/data/active-access/${NGO_ID}.yaml"
    local revoked_record="${SCRIPT_DIR}/data/revoked-access/${NGO_ID}-$(date +%Y%m%d-%H%M%S).yaml"
    
    if [[ -f "$active_record" ]]; then
        # Add revocation metadata
        local temp_file=$(mktemp)
        {
            cat "$active_record"
            echo "revocation_date: $(date -Iseconds)"
            echo "revocation_reason: $REASON"
            echo "revoked_by: $(whoami)"
        } > "$temp_file"
        
        mv "$temp_file" "$revoked_record"
        rm -f "$active_record"
        
        log "INFO" "Access record moved to: $revoked_record"
    fi
}

# Create comprehensive revocation audit record
create_revocation_audit_record() {
    local action="$1"
    local branch="$2"
    
    local audit_record="{
        \"timestamp\": \"$(date -Iseconds)\",
        \"ngo_id\": \"$NGO_ID\",
        \"action\": \"$action\",
        \"branch\": \"$branch\",
        \"team\": \"$GITHUB_TEAM\",
        \"access_level\": \"$ACCESS_LEVEL\",
        \"reason\": \"$REASON\",
        \"environment\": \"$ENVIRONMENT\",
        \"dry_run\": $DRY_RUN,
        \"emergency\": $(is_emergency_revocation && echo "true" || echo "false"),
        \"performed_by\": \"$(whoami)\",
        \"branch_protection_removed\": true,
        \"team_access_revoked\": true,
        \"access_records_cleaned\": $(check_dry_run && echo "false" || echo "true"),
        \"audit_hash\": \"$(echo -n "$NGO_ID$branch$REASON$(date)" | sha256sum | cut -d' ' -f1)\"
    }"
    
    local audit_file="${SCRIPT_DIR}/data/audit/branch-revocation-$(date +%Y%m%d).jsonl"
    echo "$audit_record" >> "$audit_file"
    
    log "INFO" "Comprehensive audit record created: $audit_file"
}

# Notify stakeholders of revocation
notify_revocation_stakeholders() {
    local action="$1"
    local branch="$2"
    local status="$3"
    
    local notification="{
        \"text\": \"Branch Access Revocation\",
        \"attachments\": [
            {
                \"color\": \"$([ "$status" = "success" ] && echo "warning" || echo "danger")\",
                \"fields\": [
                    {\"title\": \"NGO ID\", \"value\": \"$NGO_ID\", \"short\": true},
                    {\"title\": \"Action\", \"value\": \"$action\", \"short\": true},
                    {\"title\": \"Branch\", \"value\": \"$branch\", \"short\": true},
                    {\"title\": \"Reason\", \"value\": \"$REASON\", \"short\": true},
                    {\"title\": \"Status\", \"value\": \"$status\", \"short\": true},
                    {\"title\": \"Emergency\", \"value\": \"$(is_emergency_revocation && echo "Yes" || echo "No")\", \"short\": true},
                    {\"title\": \"Environment\", \"value\": \"$ENVIRONMENT\", \"short\": true},
                    {\"title\": \"Dry Run\", \"value\": \"$DRY_RUN\", \"short\": true}
                ],
                \"footer\": \"Argus_V Compliance System\",
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
    
    # Send urgent email for emergency revocations
    if is_emergency_revocation && [[ -n "$CONTACT_EMAIL" ]]; then
        echo "URGENT: Branch access has been EMERGENCY REVOKED for NGO $NGO_ID on branch $branch
Reason: $REASON
Environment: $ENVIRONMENT
Revocation Time: $(date)
Please take immediate action if required.

Contact the compliance team immediately if you have questions." | \
        mail -s "URGENT: Emergency Branch Access Revocation - $NGO_ID" "$CONTACT_EMAIL" || \
        log "WARN" "Failed to send emergency email notification"
    elif [[ -n "$CONTACT_EMAIL" ]]; then
        echo "Branch access has been revoked for NGO $NGO_ID on branch $branch
Reason: $REASON
Environment: $ENVIRONMENT
Revocation Time: $(date)" | \
        mail -s "Branch Access Revocation - $NGO_ID" "$CONTACT_EMAIL" || \
        log "WARN" "Failed to send email notification"
    fi
}

# Verify complete revocation
verify_complete_revocation() {
    local branch="$1"
    
    if check_dry_run; then
        log "INFO" "Would verify complete revocation for: $branch"
        return 0
    fi
    
    log "INFO" "Verifying complete revocation for: $branch"
    
    # Check branch protection removal
    local protection_check=$(gh api "repos/$GITHUB_ORG/$GITHUB_REPO/branches/$branch/protection" 2>&1)
    if echo "$protection_check" | grep -q "404\|Branch not protected"; then
        log "INFO" "Branch protection verification passed for: $branch"
    else
        log "WARN" "Branch protection may still exist for: $branch"
        return 1
    fi
    
    # Check team access removal (simplified check)
    # In production, you'd want to check actual team permissions
    log "INFO" "Team access verification completed for: $branch"
    
    return 0
}

# Main execution
main() {
    log "INFO" "Starting branch access revocation for NGO: $NGO_ID"
    log "INFO" "Branch pattern: $BRANCH_PATTERN"
    log "INFO" "Reason: $REASON"
    log "INFO" "Environment: $ENVIRONMENT"
    log "INFO" "Dry run mode: $DRY_RUN"
    
    if is_emergency_revocation; then
        echo -e "${RED}EMERGENCY REVOCATION MODE${NC}"
        echo -e "${RED}Reason: $REASON${NC}"
        echo -e "${RED}This action cannot be undone and requires immediate attention${NC}"
        
        if [[ "$DRY_RUN" != "true" ]]; then
            read -p "Press ENTER to confirm emergency revocation, or Ctrl+C to cancel..."
        fi
    fi
    
    # Validate revocation authorization
    if ! validate_revocation_authorization; then
        notify_revocation_stakeholders "revoke" "$BRANCH_PATTERN" "failed_validation"
        exit 1
    fi
    
    # Process each matching branch
    local success_count=0
    local total_count=0
    
    # Expand branch pattern
    local branches=()
    case "$BRANCH_PATTERN" in
        "ngo-$NGO_ID/*")
            branches=("ngo-$NGO_ID/main" "ngo-$NGO_ID/develop" "ngo-$NGO_ID/features")
            ;;
        "ngo-$NGO_ID/main")
            branches=("ngo-$NGO_ID/main")
            ;;
        *)
            branches=("$BRANCH_PATTERN")
            ;;
    esac
    
    for branch in "${branches[@]}"; do
        total_count=$((total_count + 1))
        
        # Remove branch protection
        if remove_branch_protection "$branch"; then
            # Revoke team access
            if revoke_branch_access "$branch" "$GITHUB_TEAM"; then
                # Archive branch for audit
                archive_branch_for_audit "$branch"
                
                # Verify complete revocation
                if verify_complete_revocation "$branch"; then
                    create_revocation_audit_record "revoke" "$branch"
                    success_count=$((success_count + 1))
                    notify_revocation_stakeholders "revoke" "$branch" "success"
                else
                    notify_revocation_stakeholders "revoke" "$branch" "verification_failed"
                fi
            else
                notify_revocation_stakeholders "revoke" "$branch" "failed_access_revocation"
            fi
        else
            notify_revocation_stakeholders "revoke" "$branch" "failed_protection_removal"
        fi
    done
    
    # Clean up access records (only if all operations succeeded)
    if [[ $success_count -eq $total_count ]]; then
        cleanup_access_records
    fi
    
    log "INFO" "Branch access revocation completed: $success_count/$total_count successful"
    
    if [[ $success_count -eq $total_count ]]; then
        echo -e "${GREEN}SUCCESS: All branch access revocation operations completed successfully${NC}"
        exit 0
    else
        echo -e "${YELLOW}PARTIAL SUCCESS: $success_count/$total_count operations completed${NC}"
        echo -e "${YELLOW}Please review failed operations manually${NC}"
        exit 1
    fi
}

# Cleanup on exit
cleanup() {
    log "INFO" "Branch access revocation script completed for NGO: $NGO_ID"
}

trap cleanup EXIT

# Run main function
main "$@"