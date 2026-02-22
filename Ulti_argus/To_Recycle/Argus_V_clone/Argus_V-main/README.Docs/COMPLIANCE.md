# Argus_V Compliance & Legal Framework

This document provides comprehensive compliance guidelines for Argus_V deployments, focusing on NGO licensing, data protection, privacy guarantees, and regulatory alignment.

## Table of Contents

1. [Overview](#overview)
2. [Data Protection & Privacy](#data-protection--privacy)
3. [NGO Licensing Framework](#ngo-licensing-framework)
4. [Tier Differentiation](#tier-differentiation)
5. [India Data Protection Compliance](#india-data-protection-compliance)
6. [Branch-Based Access Management](#branch-based-access-management)
7. [Data Retention & Deletion](#data-retention--deletion)
8. [Support & Update Commitments](#support--update-commitments)
9. [Compliance Validation](#compliance-validation)

## Overview

Argus_V is designed with privacy-first principles and regulatory compliance in mind. This framework ensures that:

- **Data Minimization**: Only essential flow data is collected and processed
- **Temporal Limits**: Strict 24-hour retention with automatic deletion
- **Anonymization**: All data is anonymized using industry-standard techniques
- **Transparency**: Clear audit trails and compliance reporting
- **User Control**: Granular access management and consent mechanisms

## Data Protection & Privacy

### Core Privacy Guarantees

#### 1. IP Anonymization
```python
# All IP addresses are hashed using HMAC-SHA256
from argus_v.oracle_core.anonymize import hash_ip

# Raw IPs are never stored or logged
hashed_ip = hash_ip("192.168.1.100", salt="project-specific-salt")
```

#### 2. Data Minimization
- **Flow Data Only**: Only network flow metadata is processed
- **No Content Inspection**: Packet contents are never analyzed
- **Aggregate Statistics**: Only statistical aggregations are stored
- **Minimal Fields**: Core fields (src_ip, dst_ip, ports, bytes, duration)

#### 3. Secure Storage
- **Local First**: Data stored locally by default
- **Encrypted Transit**: TLS 1.3 for all cloud communications
- **Access Controls**: Role-based access with audit logging
- **Regular Patches**: Security updates within 48 hours of disclosure

### Privacy-Preserving Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Raw Network    │───▶│  Anonymization  │───▶│  ML Processing  │
│  Flow Data      │    │  Layer          │    │  & Analysis     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Hash Database  │    │  Statistical    │
                       │  (24h TTL)      │    │  Aggregates     │
                       └─────────────────┘    └─────────────────┘
```

## NGO Licensing Framework

### License Categories

#### Free Tier (v1.5+)
- **Organizations**: Registered NGOs with annual revenue < $100,000 USD
- **Features**: Core monitoring, basic ML analysis, 1 deployment
- **Support**: Community forums, documentation, GitHub issues
- **Updates**: Security patches only, quarterly feature releases
- **Compliance**: Basic privacy compliance, automated audit logs

#### Standard Tier (Paid)
- **Organizations**: Commercial entities, NGOs with revenue > $100,000 USD
- **Features**: Full feature set, unlimited deployments, priority support
- **Support**: 24/7 technical support, dedicated compliance assistance
- **Updates**: Monthly security updates, feature releases on request
- **Compliance**: Full regulatory compliance, custom legal templates

#### Enterprise Tier (Custom)
- **Organizations**: Large enterprises, government agencies
- **Features**: Custom deployment, integration services, on-premise options
- **Support**: Dedicated support team, compliance consulting
- **Updates**: Custom update schedules, long-term support commitments
- **Compliance**: Industry-specific compliance (HIPAA, SOC2, etc.)

### NGO-Specific Provisions

#### Required Documentation
1. **Registration Certificate**: Current NGO registration
2. **Non-Profit Status**: Tax-exempt status documentation
3. **Purpose Statement**: Organization's charitable objectives
4. **Annual Report**: Previous year's activities and financials

#### Compliance Obligations
- **Data Processing Agreement**: Mandatory for all tiers
- **Privacy Impact Assessment**: Annual review for Standard+ tiers
- **Incident Response Plan**: Documented procedures for data breaches
- **Regular Audits**: Quarterly compliance checks for Enterprise tier

## Tier Differentiation

### Free Tier (v1.5+)

**Target Users**: Small NGOs, educational institutions, research organizations

**Included Features**:
- ✅ Basic network monitoring (up to 1Gbps)
- ✅ Single Raspberry Pi deployment
- ✅ Core ML anomaly detection
- ✅ 24-hour data retention
- ✅ Anonymous flow analysis
- ✅ Community support

**Limitations**:
- ❌ No multi-site deployment
- ❌ No custom integrations
- ❌ No priority support
- ❌ Limited to 10,000 flows/hour
- ❌ No custom ML models

**Support & Updates**:
- GitHub Issues: Community support
- Documentation: Comprehensive guides and API references
- Security Updates: Critical patches within 72 hours
- Feature Releases: Quarterly minor updates

### Standard Tier (Paid)

**Target Users**: Medium NGOs, commercial organizations, service providers

**Included Features**:
- ✅ All Free Tier features
- ✅ Multi-site deployment (up to 5 locations)
- ✅ Advanced ML models and custom thresholds
- ✅ Extended data retention (7 days)
- ✅ API access and webhooks
- ✅ Priority support with 4-hour response time
- ✅ Integration support (SIEM, logging, alerting)

**Pricing Structure**:
- Base License: $500/month per organization
- Per-site fee: $100/month per additional deployment
- Support tier: $200/month for 24/7 coverage

**Support & Updates**:
- Email/Phone Support: Business hours (9 AM - 6 PM local time)
- Feature Requests: Included in quarterly roadmap planning
- Security Updates: Within 24 hours for critical issues
- Major Releases: Semi-annual feature releases

### Enterprise Tier (Custom)

**Target Users**: Large enterprises, government agencies, critical infrastructure

**Included Features**:
- ✅ All Standard Tier features
- ✅ Unlimited deployments
- ✅ Custom ML model development
- ✅ On-premise deployment options
- ✅ Dedicated support team
- ✅ Custom integrations and workflow automation
- ✅ Compliance consulting services

**Support & Updates**:
- Dedicated Support: Named support team with SLAs
- Custom Development: Bespoke features and integrations
- Security Updates: Within 4 hours for critical issues
- Long-term Support: Extended support commitments

## India Data Protection Compliance

### Regulatory Framework Alignment

#### Personal Data Protection Bill (PDPB) 2023 Compliance

**1. Lawful Basis for Processing**
- **Legitimate Interest**: Network security and anomaly detection
- **Consent**: Explicit consent for data collection and processing
- **Contract**: Service delivery obligations
- **Compliance**: Legal and regulatory requirements

**2. Data Subject Rights Implementation**
```python
# Data subject rights automation
class ComplianceManager:
    def handle_access_request(self, user_id):
        """Provide copy of personal data within 30 days"""
        pass
    
    def handle_rectification_request(self, user_id, corrections):
        """Correct inaccurate personal data within 30 days"""
        pass
    
    def handle_erasure_request(self, user_id):
        """Delete personal data within 30 days"""
        pass
    
    def handle_portability_request(self, user_id):
        """Transfer data to another service provider"""
        pass
```

**3. Data Protection Officer (DPO)**
- **Contact Information**: dpo@argus-v.com
- **Responsibilities**: Privacy impact assessments, breach notifications
- **Authority**: Independent oversight of data processing activities

**4. Cross-Border Data Transfers**
- **Adequate Countries**: EU, UK, Canada, Australia (approved jurisdictions)
- **Standard Contractual Clauses**: For non-adequate countries
- **Impact Assessments**: For new transfer mechanisms

#### Information Technology Act (IT Act) 2000 Compliance

**1. Reasonable Security Practices**
- **Encryption**: AES-256 for data at rest, TLS 1.3 for transit
- **Access Controls**: Multi-factor authentication, role-based access
- **Audit Trails**: Comprehensive logging of all data access
- **Incident Response**: 24-hour breach notification procedures

**2. Data Localization Requirements**
- **Critical Data**: Must be stored within India for critical infrastructure
- **Personal Data**: Government data subject to localization requirements
- **Cloud Providers**: Indian data centers preferred for sensitive deployments

### India-Specific Features

#### 1. Hindi Language Support
```yaml
# Configuration for Hindi language interface
ui:
  language: "hi"
  localization:
    date_format: "DD/MM/YYYY"
    time_format: "12h"
    timezone: "Asia/Kolkata"
```

#### 2. Regional Compliance Settings
```yaml
# India-specific compliance configuration
compliance:
  data_residency: "india"
  localization_required: true
  breach_notification_time_hours: 72
  audit_retention_days: 2555  # 7 years
```

#### 3. Local Support
- **Support Hours**: 9 AM - 6 PM IST (Monday - Friday)
- **Response Time**: 4 hours for critical issues
- **Local Partners**: Authorized resellers in Mumbai, Delhi, Bangalore

## Branch-Based Access Management

### Access Control Framework

#### Role-Based Access Control (RBAC)

**1. Organization Roles**
- **Owner**: Full access, billing, license management
- **Admin**: User management, compliance oversight
- **Operator**: Technical management, deployment operations
- **Viewer**: Read-only access to monitoring data

**2. Branch-Level Permissions**
```yaml
# Branch access configuration
access_control:
  default_branch: "main"
  protected_branches:
    - "production"
    - "compliance-v1.5"
    - "enterprise-features"
  
  permissions:
    read:
      - main
      - develop
      - feature/*
    write:
      - feature/*
    admin:
      - "*"  # Admins can access all branches
```

#### GitHub Integration

**1. Automated Branch Protection**
```bash
# Enable branch protection for production branches
gh api repos/{owner}/{repo}/branches/{branch}/protection \
  -f required_status_checks.contexts[]=compliance-check \
  -f required_status_checks.strict=true \
  -f enforce_admins=true \
  -f required_pull_request_reviews.required_approving_review_count=2
```

**2. NGO-Specific Branch Policies**
- **Main Branch**: Protected, requires compliance approval
- **Feature Branches**: Auto-generated per NGO request
- **Compliance Branches**: Version-specific compliance documentation
- **Emergency Branches**: Time-limited access for incident response

### Access Revocation Procedures

#### Automated Revocation
```bash
#!/bin/bash
# revoke-branch-access.sh
# Usage: ./revoke-branch-access.sh <ngo-id> <branch-pattern>

NGO_ID="$1"
BRANCH_PATTERN="$2"
REASON="$3"

echo "Revoking access for NGO: $NGO_ID"
echo "Branch pattern: $BRANCH_PATTERN"
echo "Reason: $REASON"

# Audit log
echo "$(date): NGO $NGO_ID access revoked - $REASON" >> /var/log/argus-v/access-revocation.log

# GitHub API call to remove team access
gh api repos/{owner}/{repo}/teams/{team-name}/repos/{owner}/{repo} \
  --method DELETE

# Update branch protection
gh api repos/{owner}/{repo}/branches/$BRANCH_PATTERN/protection \
  --method DELETE

# Send notification to compliance team
curl -X POST "$COMPLIANCE_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d "{\"event\": \"access_revoked\", \"ngo_id\": \"$NGO_ID\", \"reason\": \"$REASON\"}"
```

## Data Retention & Deletion

### 24-Hour Retention Policy

#### Automatic Data Deletion
```python
# Data retention automation
class DataRetentionManager:
    def __init__(self, config):
        self.retention_hours = config.get('data_retention_hours', 24)
        self.cleanup_interval = config.get('cleanup_interval_minutes', 60)
    
    def enforce_retention_policy(self):
        """Delete data older than retention period"""
        cutoff_time = datetime.utcnow() - timedelta(hours=self.retention_hours)
        
        # Clean flow data
        self.db.execute(
            "DELETE FROM flows WHERE timestamp < ?",
            (cutoff_time,)
        )
        
        # Clean blacklist entries
        self.db.execute(
            "DELETE FROM blacklist WHERE created_at < ?",
            (cutoff_time,)
        )
        
        # Clean audit logs (keep longer for compliance)
        audit_cutoff = datetime.utcnow() - timedelta(days=90)
        self.db.execute(
            "DELETE FROM audit_logs WHERE created_at < ? AND level != 'ERROR'",
            (audit_cutoff,)
        )
```

#### Deletion Workflow Triggers

**1. Time-Based Deletion**
- **Frequency**: Every hour at minute 0
- **Scope**: All expired data older than 24 hours
- **Verification**: Deletion log with cryptographic hash verification

**2. Manual Deletion Requests**
```bash
# Manual data deletion for compliance
sudo python -m argus_v.compliance delete-data \
  --scope flows \
  --date-range "2023-12-01" \
  --reason "GDPR compliance request" \
  --verification-required
```

**3. Emergency Deletion**
```bash
# Emergency data deletion for incident response
sudo python -m argus_v.compliance emergency-delete \
  --scope all \
  --reason "Security incident - data compromise" \
  --notify-compliance-team
```

### Deletion Verification

#### Cryptographic Proof of Deletion
```python
import hashlib
import json

class DeletionVerifier:
    def __init__(self):
        self.proof_log = "/var/log/argus-v/deletion-proof.log"
    
    def verify_deletion(self, data_hash, scope):
        """Generate cryptographic proof of deletion"""
        deletion_proof = {
            "timestamp": datetime.utcnow().isoformat(),
            "data_hash": data_hash,
            "scope": scope,
            "deletion_hash": hashlib.sha256(
                f"{data_hash}{datetime.utcnow().isoformat()}".encode()
            ).hexdigest(),
            "verification_key": self.generate_verification_key()
        }
        
        # Log deletion proof
        with open(self.proof_log, 'a') as f:
            f.write(json.dumps(deletion_proof) + "\n")
        
        return deletion_proof
```

## Support & Update Commitments

### Version 1.5+ Support Framework

#### Free Tier Support (v1.5+)
**Community Support Model**:
- **GitHub Issues**: Bug reports and feature requests
- **Documentation**: Comprehensive guides and troubleshooting
- **Community Forum**: Peer-to-peer support and discussions
- **Security Updates**: Critical patches within 72 hours

**Update Schedule**:
- **Security Updates**: As needed, typically weekly
- **Minor Updates**: Quarterly feature releases
- **Major Updates**: Annual major version releases
- **End of Life**: 2 years after last release

#### Standard Tier Support
**Professional Support Model**:
- **Email Support**: Business hours response (4-hour SLA)
- **Phone Support**: Priority hotline for critical issues
- **Documentation**: Enhanced documentation with API examples
- **Training**: Quarterly webinars and training sessions

**Update Schedule**:
- **Security Updates**: Within 24 hours for critical issues
- **Feature Updates**: Monthly releases
- **Major Updates**: Semi-annual major releases
- **Custom Updates**: Available for additional fees

#### Enterprise Tier Support
**Dedicated Support Model**:
- **Named Support Team**: Dedicated support engineers
- **Custom SLAs**: Tailored service level agreements
- **On-site Support**: Available for critical deployments
- **Compliance Consulting**: Privacy and security assessments

**Update Schedule**:
- **Security Updates**: Within 4 hours for critical issues
- **Feature Updates**: Monthly releases with custom prioritization
- **Major Updates**: Custom rollout schedules
- **Long-term Support**: Extended support periods (5+ years)

### Update Communication

#### Notification Framework
```yaml
# Update notification configuration
notifications:
  security_updates:
    channels: ["email", "slack", "dashboard"]
    immediate: true
  
  feature_updates:
    channels: ["email", "dashboard"]
    advance_notice: "14 days"
  
  deprecation_notices:
    channels: ["email", "dashboard", "api"]
    advance_notice: "90 days"
```

#### Rollback Procedures
```bash
# Automated rollback for failed updates
./rollback-procedure.sh --version "v1.5.0" --reason "critical-bug"

# Rollback verification
./verify-rollback.sh --version "v1.5.0"
```

## Compliance Validation

### Automated Compliance Checking

#### Daily Compliance Audit
```bash
#!/bin/bash
# compliance-check.sh
# Daily automated compliance validation

echo "Starting daily compliance audit..."

# Check data retention enforcement
python -m argus_v.compliance audit retention

# Verify anonymization is working
python -m argus_v.compliance audit anonymization

# Check access control logs
python -m argus_v.compliance audit access-control

# Validate GDPR compliance
python -m argus_v.compliance audit gdpr

# Check India compliance
python -m argus_v.compliance audit india-pdpb

# Generate compliance report
python -m argus_v.compliance report --format pdf --output /var/reports/daily-$(date +%Y%m%d).pdf

echo "Compliance audit complete. Report generated."
```

#### Continuous Monitoring
```python
# Continuous compliance monitoring
class ComplianceMonitor:
    def __init__(self):
        self.checks = [
            DataRetentionCheck(),
            AnonymizationCheck(),
            AccessControlCheck(),
            IndiaComplianceCheck()
        ]
    
    def continuous_monitor(self):
        """Run compliance checks every 15 minutes"""
        while True:
            for check in self.checks:
                try:
                    result = check.validate()
                    if not result.passed:
                        self.handle_compliance_violation(result)
                except Exception as e:
                    self.handle_check_error(e)
            
            time.sleep(900)  # 15 minutes
```

### Compliance Reporting

#### Monthly Compliance Report
```bash
# Generate comprehensive compliance report
python -m argus_v.compliance report \
  --type monthly \
  --format comprehensive \
  --include-metrics \
  --include-incidents \
  --include-audits \
  --output /var/reports/monthly-$(date +%Y-%m).pdf
```

#### Real-time Dashboard
- **Compliance Status**: Live compliance status indicators
- **Data Retention**: Real-time retention policy enforcement
- **Access Violations**: Live monitoring of unauthorized access attempts
- **Privacy Metrics**: Anonymization success rates, data minimization metrics

---

**Document Version**: 1.0  
**Last Updated**: 2024-12-18  
**Next Review**: 2025-06-18  
**Compliance Officer**: dpo@argus-v.com