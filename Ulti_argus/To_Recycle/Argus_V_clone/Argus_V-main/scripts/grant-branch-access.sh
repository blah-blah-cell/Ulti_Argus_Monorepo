#!/bin/bash
# grant-branch-access.sh - Automated branch access management for NGOs
# Usage: ./grant-branch-access.sh <ngo-id> <branch-pattern> [environment]

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/argus-v/branch-access.log"
COMPLIANCE_WEBHOOK="${COMPLIANCE_WEBHOOK:-https://hooks.slack.com/services/YOUR/WEBHOOK/URL}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse arguments
NGO_ID="${1:-}"
BRANCH_PATTERN="${2:-}"
ENVIRONMENT="${3:-staging}"
DRY_RUN="${DRY_RUN:-true}"

# Validation
if [[ -z "$NGO_ID" ]] || [[ -z "$BRANCH_PATTERN" ]]; then
    echo "Usage: $0 <ngo-id> <branch-pattern> [environment]"
    echo "  ngo-id: Unique NGO identifier (e.g., ngo-red-cross)"
    echo "  branch-pattern: Git branch pattern (e.g., ngo-*/feature/*)"
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
    echo "Please create NGO configuration with required GitHub access details."
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
    esac
}

# Dry-run check
check_dry_run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log "INFO" "DRY RUN MODE - No actual changes will be made"
        return 0
    fi
    return 1
}

# Validate NGO access eligibility
validate_ngo_access() {
    log "INFO" "Validating NGO access eligibility for $NGO_ID"
    
    # Check if NGO is in good standing
    local status_file="${SCRIPT_DIR}/data/ngo-status/${NGO_ID}.yaml"
    if [[ ! -f "$status_file" ]]; then
        log "ERROR" "NGO status file not found: $status_file"
        return 1
    fi
    
    local status=$(grep "status:" "$status_file" | awk '{print $2}')
    if [[ "$status" != "active" ]]; then
        log "ERROR" "NGO $NGO_ID is not in active status (current: $status)"
        return 1
    fi
    
    # Check license compliance
    local license_check=$(python3 "${SCRIPT_DIR}/lib/license-checker.py" --ngo-id "$NGO_ID" --check-compliant)
    if [[ $? -ne 0 ]]; then
        log "ERROR" "NGO $NGO_ID is not compliant with license requirements"
        return 1
    fi
    
    log "INFO" "NGO $NGO_ID validation passed"
    return 0
}

# Create branch protection rules
setup_branch_protection() {
    local branch="$1"
    
    if check_dry_run; then
        log "INFO" "Would setup branch protection for: $branch"
        log "INFO" "  Required status checks: compliance-check, security-scan"
        log "INFO" "  Required review count: 2"
        log "INFO" "  Enforce for administrators: true"
        return 0
    fi
    
    log "INFO" "Setting up branch protection for: $branch"
    
    # Check if gh CLI is available and authenticated
    if ! command -v gh &> /dev/null; then
        log "ERROR" "GitHub CLI (gh) is not installed or not in PATH"
        return 1
    fi
    
    # Configure branch protection
    local protection_rules='{
        "required_status_checks": {
            "strict": true,
            "contexts": ["compliance-check", "security-scan", "unit-tests"]
        },
        "enforce_admins": true,
        "required_pull_request_reviews": {
            "required_approving_review_count": 2,
            "dismiss_stale_reviews": true
        },
        "restrictions": {
            "users": [],
            "teams": ["'"$GITHUB_TEAM"'"]
        }
    }'
    
    # Apply branch protection
    local response
    response=$(gh api "repos/$GITHUB_ORG/$GITHUB_REPO/branches/$branch/protection" \
        --method PUT \
        --field json="$protection_rules" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        log "INFO" "Branch protection configured successfully for $branch"
        return 0
    else
        log "ERROR" "Failed to configure branch protection for $branch: $response"
        return 1
    fi
}

# Grant team access to branch
grant_branch_access() {
    local branch="$1"
    local team="$2"
    
    if check_dry_run; then
        log "INFO" "Would grant access to branch $branch for team $team"
        log "INFO" "  Access level: $ACCESS_LEVEL"
        log "INFO" "  Team: $GITHUB_ORG/$team"
        return 0
    fi
    
    log "INFO" "Granting access to branch $branch for team $team"
    
    # Add team to repository with appropriate permissions
    local permission="pull"  # Default to read access
    case $ACCESS_LEVEL in
        "write") permission="push" ;;
        "admin") permission="admin" ;;
    esac
    
    local response
    response=$(gh api "repos/$GITHUB_ORG/$GITHUB_REPO/teams/$team/repos/$GITHUB_ORG/$GITHUB_REPO" \
        --method PUT \
        --field permission="$permission" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        log "INFO" "Team access granted successfully"
        return 0
    else
        log "ERROR" "Failed to grant team access: $response"
        return 1
    fi
}

# Create access audit record
create_access_audit_record() {
    local action="$1"
    local branch="$2"
    
    local audit_record="{
        \"timestamp\": \"$(date -Iseconds)\",
        \"ngo_id\": \"$NGO_ID\",
        \"action\": \"$action\",
        \"branch\": \"$branch\",
        \"team\": \"$GITHUB_TEAM\",
        \"access_level\": \"$ACCESS_LEVEL\",
        \"environment\": \"$ENVIRONMENT\",
        \"dry_run\": $DRY_RUN,
        \"performed_by\": \"$(whoami)\",
        \"audit_hash\": \"$(echo -n "$NGO_ID$branch$(date)" | sha256sum | cut -d' ' -f1)\"
    }"
    
    local audit_file="${SCRIPT_DIR}/data/audit/branch-access-$(date +%Y%m%d).jsonl"
    echo "$audit_record" >> "$audit_file"
    
    log "INFO" "Audit record created: $audit_file"
}

# Notify compliance team
notify_compliance_team() {
    local action="$1"
    local branch="$2"
    local status="$3"
    
    local notification="{
        \"text\": \"Branch Access Update\",
        \"attachments\": [
            {
                \"color\": \"$([ "$status" = "success" ] && echo "good" || echo "warning")\",
                \"fields\": [
                    {\"title\": \"NGO ID\", \"value\": \"$NGO_ID\", \"short\": true},
                    {\"title\": \"Action\", \"value\": \"$action\", \"short\": true},
                    {\"title\": \"Branch\", \"value\": \"$branch\", \"short\": true},
                    {\"title\": \"Status\", \"value\": \"$status\", \"short\": true},
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
    
    # Send email notification
    if [[ -n "$CONTACT_EMAIL" ]]; then
        echo "Branch access $action for NGO $NGO_ID on branch $branch - Status: $status" | \
        mail -s "Argus_V Branch Access Update" "$CONTACT_EMAIL" || \
        log "WARN" "Failed to send email notification"
    fi
}

# Main execution
main() {
    log "INFO" "Starting branch access grant for NGO: $NGO_ID"
    log "INFO" "Branch pattern: $BRANCH_PATTERN"
    log "INFO" "Environment: $ENVIRONMENT"
    log "INFO" "Dry run mode: $DRY_RUN"
    
    # Validate NGO access
    if ! validate_ngo_access; then
        notify_compliance_team "grant" "$BRANCH_PATTERN" "failed_validation"
        exit 1
    fi
    
    # Process each matching branch
    local success_count=0
    local total_count=0
    
    # Expand branch pattern (this is a simplified approach)
    # In production, you'd want to query GitHub for actual branches
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
        
        # Setup branch protection
        if setup_branch_protection "$branch"; then
            # Grant access to team
            if grant_branch_access "$branch" "$GITHUB_TEAM"; then
                create_access_audit_record "grant" "$branch"
                success_count=$((success_count + 1))
                notify_compliance_team "grant" "$branch" "success"
            else
                notify_compliance_team "grant" "$branch" "failed_access"
            fi
        else
            notify_compliance_team "grant" "$branch" "failed_protection"
        fi
    done
    
    log "INFO" "Branch access grant completed: $success_count/$total_count successful"
    
    if [[ $success_count -eq $total_count ]]; then
        echo -e "${GREEN}SUCCESS: All branch access operations completed successfully${NC}"
        exit 0
    else
        echo -e "${YELLOW}PARTIAL SUCCESS: $success_count/$total_count operations completed${NC}"
        exit 1
    fi
}

# Cleanup on exit
cleanup() {
    log "INFO" "Branch access grant script completed for NGO: $NGO_ID"
}

trap cleanup EXIT

# Run main function
main "$@"