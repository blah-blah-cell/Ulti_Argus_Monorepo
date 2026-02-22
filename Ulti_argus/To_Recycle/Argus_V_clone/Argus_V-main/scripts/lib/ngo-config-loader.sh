#!/bin/bash
# ngo-config-loader.sh - Load and validate NGO configuration files
# This script provides functions to load and validate NGO configurations

# Load NGO configuration from YAML file
load_ngo_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file not found: $config_file" >&2
        return 1
    fi
    
    # Parse YAML-like format (simplified YAML parser)
    local github_org=$(grep "^github_org:" "$config_file" | awk '{print $2}' | tr -d '"')
    local github_repo=$(grep "^github_repo:" "$config_file" | awk '{print $2}' | tr -d '"')
    local github_team=$(grep "^github_team:" "$config_file" | awk '{print $2}' | tr -d '"')
    local contact_email=$(grep "^contact_email:" "$config_file" | awk '{print $2}' | tr -d '"')
    local access_level=$(grep "^access_level:" "$config_file" | awk '{print $2}' | tr -d '"' | head -1)
    local license_type=$(grep "^license_type:" "$config_file" | awk '{print $2}' | tr -d '"')
    local organization_name=$(grep "^organization_name:" "$config_file" | awk '{print $2}' | tr -d '"')
    local registration_number=$(grep "^registration_number:" "$config_file" | awk '{print $2}' | tr -d '"')
    
    # Return configuration as associative array format
    echo "github_org=$github_org"
    echo "github_repo=$github_repo"
    echo "github_team=$github_team"
    echo "contact_email=$contact_email"
    echo "access_level=$access_level"
    echo "license_type=$license_type"
    echo "organization_name=$organization_name"
    echo "registration_number=$registration_number"
}

# Validate NGO configuration
validate_ngo_config() {
    local config_file="$1"
    local errors=0
    
    # Check required fields
    local required_fields=("github_org" "github_repo" "github_team" "contact_email" "license_type")
    
    for field in "${required_fields[@]}"; do
        if ! grep -q "^$field:" "$config_file"; then
            echo "Error: Missing required field: $field" >&2
            ((errors++))
        fi
    done
    
    # Validate GitHub team format
    local github_team=$(grep "^github_team:" "$config_file" | awk '{print $2}' | tr -d '"')
    if [[ -n "$github_team" ]] && [[ ! "$github_team" =~ ^[a-zA-Z0-9-]+$ ]]; then
        echo "Error: Invalid GitHub team format: $github_team" >&2
        ((errors++))
    fi
    
    # Validate email format
    local contact_email=$(grep "^contact_email:" "$config_file" | awk '{print $2}' | tr -d '"')
    if [[ -n "$contact_email" ]] && [[ ! "$contact_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        echo "Error: Invalid email format: $contact_email" >&2
        ((errors++))
    fi
    
    # Validate access level
    local access_level=$(grep "^access_level:" "$config_file" | awk '{print $2}' | tr -d '"' | head -1)
    if [[ -n "$access_level" ]] && [[ ! "$access_level" =~ ^(read|write|admin)$ ]]; then
        echo "Error: Invalid access level: $access_level (must be read, write, or admin)" >&2
        ((errors++))
    fi
    
    return $errors
}

# Create default NGO configuration template
create_ngo_config_template() {
    local config_file="$1"
    local org_name="$2"
    local contact_email="$3"
    
    cat > "$config_file" << EOF
# NGO Configuration for Argus_V Branch Access Management
# Generated on $(date)

organization_name: "$org_name"
registration_number: "REG-$(date +%Y%m%d)-001"
license_type: "free_tier"  # free_tier, standard_tier, enterprise_tier
access_level: "read"       # read, write, admin

# GitHub configuration
github_org: "argus-v-ngo"
github_repo: "argus-v-security"
github_team: "ngo-$org_name"

# Contact information
contact_email: "$contact_email"
emergency_contact: "$contact_email"

# Compliance settings
compliance_enabled: true
audit_required: true
retention_policy: "24_hours"
anonymization_required: true

# Branch access patterns
allowed_branch_patterns:
  - "ngo-$org_name/*"
  - "ngo-$org_name/main"
  - "ngo-$org_name/features/*"

# Access scheduling
access_start_date: "$(date -Iseconds)"
access_duration_days: 365
renewal_required: true

# Monitoring and reporting
monitoring_enabled: true
weekly_reports: true
compliance_checks: true
EOF
    
    echo "NGO configuration template created: $config_file"
}

# Update NGO configuration
update_ngo_config() {
    local config_file="$1"
    local field="$2"
    local value="$3"
    
    if [[ ! -f "$config_file" ]]; then
        echo "Error: Configuration file not found: $config_file" >&2
        return 1
    fi
    
    # Use sed to update or add the field
    if grep -q "^$field:" "$config_file"; then
        sed -i "s/^$field:.*/$field: $value/" "$config_file"
    else
        echo "$field: $value" >> "$config_file"
    fi
    
    echo "Updated $field to $value in $config_file"
}

# Get NGO status from configuration
get_ngo_status() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        echo "inactive"
        return
    fi
    
    local status=$(grep "^status:" "$config_file" 2>/dev/null | awk '{print $2}' | tr -d '"')
    echo "${status:-active}"
}

# Set NGO status
set_ngo_status() {
    local config_file="$1"
    local status="$2"
    
    update_ngo_config "$config_file" "status" "\"$status\""
    
    # Log status change
    local log_entry="$(date -Iseconds): NGO status changed to $status"
    echo "$log_entry" >> "${SCRIPT_DIR:-.}/data/ngo-status-changes.log"
}