# Security & Compliance Framework

**Document Version**: 1.0  
**Effective Date**: January 1, 2025  
**Last Updated**: December 18, 2024  
**Scope**: Argus_V Security & Compliance Implementation

---

## Executive Summary

This document outlines the comprehensive security and compliance framework for Argus_V deployments, focusing on NGO access management, data protection, privacy guarantees, and regulatory compliance. The framework provides automated tooling and documented procedures to ensure consistent compliance across all Argus_V deployments.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Compliance Automation](#compliance-automation)
3. [Data Protection Implementation](#data-protection-implementation)
4. [Access Control Framework](#access-control-framework)
5. [Deployment Procedures](#deployment-procedures)
6. [Monitoring and Alerting](#monitoring-and-alerting)
7. [Incident Response](#incident-response)
8. [Audit and Compliance](#audit-and-compliance)

## Security Architecture

### Core Security Principles

#### 1. Privacy by Design
Argus_V implements privacy-by-design principles at every level:

```python
# Privacy-first architecture
from argus_v.oracle_core.anonymize import hash_ip, round_datetime

class PrivacyManager:
    def __init__(self):
        self.anonymization_salt = os.environ.get('ANONYMIZATION_SALT')
        self.retention_hours = 24
    
    def anonymize_flow_data(self, flow_data):
        """Anonymize all personal data before processing"""
        anonymized = flow_data.copy()
        
        # Anonymize IP addresses
        anonymized['src_ip'] = hash_ip(flow_data['src_ip'], self.anonymization_salt)
        anonymized['dst_ip'] = hash_ip(flow_data['dst_ip'], self.anonymization_salt)
        
        # Round timestamps to hour precision
        anonymized['timestamp'] = round_datetime(flow_data['timestamp'], 3600)
        
        # Remove any potentially identifying information
        anonymized.pop('user_agent', None)
        anonymized.pop('session_id', None)
        
        return anonymized
```

#### 2. Defense in Depth
Multiple layers of security controls:

- **Network Security**: Encrypted communications, firewall rules
- **Application Security**: Input validation, secure coding practices
- **Data Security**: Encryption at rest and in transit, access controls
- **Infrastructure Security**: Hardened systems, minimal attack surface
- **Operational Security**: Monitoring, incident response, regular updates

#### 3. Zero Trust Architecture
No implicit trust based on network location:

```yaml
# Zero trust configuration
security:
  authentication:
    multi_factor_required: true
    certificate_based_auth: true
    session_timeout: 3600  # 1 hour
  
  authorization:
    rbac_enabled: true
    principle_of_least_privilege: true
    regular_access_reviews: true
  
  network:
    mTLS_required: true
    encrypted_only: true
    source_ip_restrictions: true
```

### Security Controls Implementation

#### Access Control Matrix
```yaml
# Role-based access control
access_matrix:
  admin:
    permissions: ["read", "write", "delete", "configure", "audit"]
    scope: "all_resources"
    mfa_required: true
    approval_required: false
  
  operator:
    permissions: ["read", "write", "configure"]
    scope: "operational_resources"
    mfa_required: true
    approval_required: true
  
  auditor:
    permissions: ["read", "audit"]
    scope: "audit_resources"
    mfa_required: false
    approval_required: true
  
  viewer:
    permissions: ["read"]
    scope: "monitoring_data"
    mfa_required: false
    approval_required: false
```

#### Encryption Standards
- **Data at Rest**: AES-256 encryption for all stored data
- **Data in Transit**: TLS 1.3 for all network communications
- **Key Management**: Hardware security modules (HSM) for production
- **Key Rotation**: Automated rotation every 90 days

## Compliance Automation

### Automated Compliance Checking

#### Daily Compliance Workflow
```bash
#!/bin/bash
# Daily compliance automation
# Runs every day at 02:00 UTC

# 1. Data retention verification
echo "Checking data retention compliance..."
./scripts/compliance-check.sh all retention

# 2. Anonymization verification
echo "Verifying anonymization..."
python3 -c "
from src.argus_v.oracle_core.anonymize import hash_ip
test_result = hash_ip('192.0.2.1', 'daily-test-salt')
if len(test_result) == 64:
    print('✓ Anonymization working')
else:
    print('✗ Anonymization failed')
    exit(1)
"

# 3. Access control audit
echo "Auditing access controls..."
./scripts/audit-access.sh daily

# 4. Generate daily compliance report
echo "Generating compliance report..."
./scripts/generate-daily-report.sh
```

#### Real-time Compliance Monitoring
```python
class ComplianceMonitor:
    def __init__(self):
        self.compliance_rules = ComplianceRuleEngine()
        self.alert_manager = AlertManager()
    
    def monitor_compliance_realtime(self):
        """Monitor compliance in real-time"""
        while True:
            try:
                # Check data retention
                if not self.check_data_retention():
                    self.alert_manager.send_alert(
                        "CRITICAL", "Data retention policy violation"
                    )
                
                # Check anonymization
                if not self.verify_anonymization():
                    self.alert_manager.send_alert(
                        "HIGH", "Anonymization verification failed"
                    )
                
                # Check access controls
                if not self.audit_access_controls():
                    self.alert_manager.send_alert(
                        "MEDIUM", "Access control audit failure"
                    )
                
                # Sleep for 5 minutes
                time.sleep(300)
                
            except Exception as e:
                self.alert_manager.send_alert(
                    "CRITICAL", f"Compliance monitoring error: {str(e)}"
                )
```

### Compliance Reporting Automation

#### Monthly Compliance Report Generation
```python
def generate_monthly_compliance_report():
    """Generate comprehensive monthly compliance report"""
    
    report = {
        "report_metadata": {
            "report_id": f"monthly-{datetime.now().strftime('%Y-%m')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "reporting_period": f"{datetime.now().replace(day=1).date()} to {datetime.now().date()}",
            "compliance_framework": ["GDPR", "India PDPB", "SOC2"]
        },
        
        "executive_summary": {
            "overall_compliance_score": calculate_overall_score(),
            "key_achievements": get_key_achievements(),
            "areas_for_improvement": get_improvement_areas(),
            "regulatory_changes": get_regulatory_updates()
        },
        
        "detailed_metrics": {
            "data_retention_compliance": get_retention_metrics(),
            "anonymization_effectiveness": get_anonymization_metrics(),
            "access_control_effectiveness": get_access_metrics(),
            "incident_response_metrics": get_incident_metrics(),
            "audit_trail_completeness": get_audit_metrics()
        },
        
        "regulatory_compliance": {
            "gdpr_compliance": generate_gdpr_report(),
            "pdpb_compliance": generate_pdpb_report(),
            "soc2_compliance": generate_soc2_report()
        },
        
        "recommendations": generate_recommendations(),
        "appendices": generate_technical_appendices()
    }
    
    # Generate PDF report
    pdf_report = generate_pdf_report(report)
    
    # Distribute to stakeholders
    distribute_report(pdf_report)
    
    return report
```

## Data Protection Implementation

### Data Classification and Handling

#### Data Classification Matrix
```yaml
data_classification:
  public:
    description: "Information that can be freely shared"
    examples: ["public_documentation", "general_statistics"]
    retention: "indefinite"
    encryption: "optional"
    access_controls: "none"
  
  internal:
    description: "Information for internal use only"
    examples: ["system_logs", "configuration_data"]
    retention: "1_year"
    encryption: "recommended"
    access_controls: "role_based"
  
  confidential:
    description: "Sensitive business information"
    examples: ["threat_intelligence", "compliance_reports"]
    retention: "7_years"
    encryption: "required"
    access_controls: "restricted"
  
  restricted:
    description: "Highly sensitive personal data"
    examples: ["raw_network_flows", "user_identifiers"]
    retention: "24_hours"
    encryption: "required_strong"
    access_controls: "approved_only"
```

### Data Processing Controls

#### Data Minimization Implementation
```python
class DataMinimizationProcessor:
    def __init__(self):
        self.required_fields = {
            "flow_monitoring": [
                "timestamp", "anonymized_src_ip", "anonymized_dst_ip",
                "src_port", "dst_port", "protocol", "bytes_transferred"
            ],
            "threat_detection": [
                "anonymized_src_ip", "anonymized_dst_ip", 
                "threat_score", "detection_timestamp"
            ]
        }
    
    def minimize_data(self, raw_data, processing_purpose):
        """Minimize data collection based on purpose"""
        
        required_fields = self.required_fields.get(processing_purpose, [])
        
        minimized_data = {}
        for field in required_fields:
            if field in raw_data:
                # Apply appropriate anonymization
                if "anonymized" in field:
                    minimized_data[field] = self.anonymize_field(raw_data[field], field)
                else:
                    minimized_data[field] = raw_data[field]
        
        return minimized_data
    
    def anonymize_field(self, value, field_type):
        """Apply appropriate anonymization based on field type"""
        if field_type == "anonymized_src_ip":
            return hash_ip(value, self.get_context_salt())
        elif field_type == "anonymized_dst_ip":
            return hash_ip(value, self.get_context_salt())
        else:
            return value
```

## Access Control Framework

### NGO Access Management

#### Branch-Based Access Control
```python
class NGOBranchAccessManager:
    def __init__(self):
        self.access_policies = {
            "free_tier": {
                "max_branches": 3,
                "max_collaborators": 5,
                "access_level": "read_only",
                "duration_days": 365
            },
            "standard_tier": {
                "max_branches": 10,
                "max_collaborators": 20,
                "access_level": "read_write",
                "duration_days": 365
            },
            "enterprise_tier": {
                "max_branches": "unlimited",
                "max_collaborators": "unlimited",
                "access_level": "admin",
                "duration_days": "custom"
            }
        }
    
    def grant_branch_access(self, ngo_id, branch_pattern, tier):
        """Grant access to specified branches"""
        
        policy = self.access_policies[tier]
        
        # Validate access request
        validation_result = self.validate_access_request(
            ngo_id, branch_pattern, policy
        )
        
        if not validation_result.is_valid:
            raise AccessDeniedError(validation_result.reason)
        
        # Generate access tokens
        access_tokens = self.generate_access_tokens(
            ngo_id, branch_pattern, policy
        )
        
        # Log access grant
        self.log_access_grant(
            ngo_id, branch_pattern, policy, access_tokens
        )
        
        return access_tokens
```

#### Automated Access Revocation
```python
def automated_access_revocation():
    """Automated system to revoke expired or non-compliant access"""
    
    # Find all active NGO access records
    active_access_records = get_active_access_records()
    
    for record in active_access_records:
        # Check if access has expired
        if is_access_expired(record):
            revoke_access(record.ngo_id, "expired_access")
            continue
        
        # Check if NGO is still compliant
        compliance_status = check_ngo_compliance(record.ngo_id)
        
        if not compliance_status.is_compliant:
            revoke_access(record.ngo_id, "non_compliance")
            
            # Notify compliance team
            notify_compliance_team(
                f"NGO {record.ngo_id} access revoked due to non-compliance",
                compliance_status.violations
            )
        
        # Check for security incidents
        if has_security_incidents(record.ngo_id):
            revoke_access(record.ngo_id, "security_incident")
            
            # Trigger emergency response
            trigger_emergency_response(record.ngo_id)
```

## Deployment Procedures

### Secure Deployment Checklist

#### Pre-Deployment Security Validation
```bash
#!/bin/bash
# Pre-deployment security checklist
set -e

echo "Running pre-deployment security validation..."

# 1. Code security scan
echo "Running security scan..."
bandit -r src/ -f json -o security-scan.json

# 2. Dependency vulnerability check
echo "Checking dependencies..."
safety check --json --output dependencies-check.json

# 3. Configuration validation
echo "Validating configuration..."
python3 -c "
import yaml
with open('aegis-config.example.yaml') as f:
    config = yaml.safe_load(f)
    
# Validate security settings
if not config.get('security', {}).get('encryption_enabled', False):
    print('ERROR: Encryption not enabled')
    exit(1)
    
if not config.get('privacy', {}).get('anonymization_required', False):
    print('ERROR: Anonymization not required')
    exit(1)
    
print('✓ Configuration validation passed')
"

# 4. Privacy impact assessment
echo "Performing privacy impact assessment..."
python3 scripts/privacy-impact-assessment.py

# 5. Generate deployment security report
echo "Generating deployment security report..."
python3 scripts/generate-security-report.py

echo "Pre-deployment security validation completed successfully"
```

#### Deployment Security Controls
```yaml
# Deployment security configuration
deployment_security:
  # Container security
  containers:
    base_image: "ubuntu:22.04"
    security_scanning: true
    vulnerability_threshold: "medium"
    run_as_non_root: true
    read_only_filesystem: true
  
  # Network security
  network:
    encryption_required: true
    mTLS_enabled: true
    firewall_rules: "restricted"
    ip_whitelisting: true
  
  # Secrets management
  secrets:
    vault_integration: true
    rotation_enabled: true
    encryption_at_rest: true
    access_logging: true
  
  # Monitoring
  monitoring:
    security_events: true
    compliance_monitoring: true
    real_time_alerts: true
    log_retention_days: 2555  # 7 years
```

### Raspberry Pi Deployment Security

#### Hardened Raspberry Pi Configuration
```bash
#!/bin/bash
# Raspberry Pi security hardening script
set -e

echo "Hardening Raspberry Pi security configuration..."

# 1. System updates and patches
apt update && apt upgrade -y
apt install -y unattended-upgrades fail2ban ufw

# 2. Disable unnecessary services
systemctl disable bluetooth
systemctl disable cups
systemctl disable avahi-daemon

# 3. Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 443/tcp
ufw enable

# 4. Secure SSH configuration
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
systemctl restart sshd

# 5. Configure automatic security updates
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

systemctl enable unattended-upgrades

echo "Raspberry Pi security hardening completed"
```

## Monitoring and Alerting

### Security Monitoring Framework

#### Real-time Security Monitoring
```python
class SecurityMonitoringSystem:
    def __init__(self):
        self.alert_manager = AlertManager()
        self.event_processor = EventProcessor()
        self.threat_intelligence = ThreatIntelligenceFeed()
    
    def monitor_security_events(self):
        """Monitor security events in real-time"""
        
        event_sources = [
            "system_logs",
            "application_logs", 
            "network_logs",
            "access_logs",
            "compliance_logs"
        ]
        
        for source in event_sources:
            threading.Thread(
                target=self.monitor_event_source,
                args=(source,),
                daemon=True
            ).start()
    
    def monitor_event_source(self, source):
        """Monitor a specific event source"""
        
        while True:
            try:
                events = self.event_processor.get_recent_events(source)
                
                for event in events:
                    # Analyze event for security implications
                    analysis = self.analyze_security_event(event)
                    
                    if analysis.is_security_incident:
                        self.handle_security_incident(event, analysis)
                    
                    if analysis.requires_alert:
                        self.alert_manager.send_alert(
                            analysis.severity,
                            analysis.message,
                            event
                        )
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.alert_manager.send_alert(
                    "CRITICAL",
                    f"Security monitoring error: {str(e)}"
                )
```

#### Compliance Monitoring
```python
class ComplianceMonitoringSystem:
    def __init__(self):
        self.compliance_engine = ComplianceEngine()
        self.monitoring_rules = self.load_monitoring_rules()
    
    def monitor_compliance_continuously(self):
        """Monitor compliance continuously"""
        
        compliance_checks = [
            "data_retention_compliance",
            "anonymization_compliance", 
            "access_control_compliance",
            "audit_trail_compliance",
            "consent_compliance"
        ]
        
        while True:
            for check_name in compliance_checks:
                try:
                    result = self.run_compliance_check(check_name)
                    
                    if not result.is_compliant:
                        self.handle_compliance_violation(check_name, result)
                    
                    # Log compliance status
                    self.log_compliance_status(check_name, result)
                    
                except Exception as e:
                    self.alert_compliance_system_error(check_name, str(e))
            
            # Check every hour
            time.sleep(3600)
```

### Alert Management System

#### Multi-Channel Alert Distribution
```python
class AlertManager:
    def __init__(self):
        self.channels = {
            "email": EmailAlertChannel(),
            "slack": SlackAlertChannel(),
            "sms": SMSAlertChannel(),
            "webhook": WebhookAlertChannel(),
            "dashboard": DashboardAlertChannel()
        }
        
        self.alert_routing = {
            "CRITICAL": ["email", "slack", "sms", "webhook"],
            "HIGH": ["email", "slack", "webhook"],
            "MEDIUM": ["email", "dashboard"],
            "LOW": ["dashboard"]
        }
    
    def send_alert(self, severity, message, event_data=None):
        """Send alert through appropriate channels"""
        
        channels = self.alert_routing.get(severity, ["dashboard"])
        
        for channel_name in channels:
            channel = self.channels[channel_name]
            
            try:
                alert_data = {
                    "severity": severity,
                    "message": message,
                    "event_data": event_data,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "argus-v-security-system"
                }
                
                channel.send_alert(alert_data)
                
            except Exception as e:
                # Log alert delivery failure but don't fail completely
                logger.error(f"Failed to send alert via {channel_name}: {str(e)}")
```

## Incident Response

### Security Incident Response Framework

#### Incident Response Workflow
```python
class SecurityIncidentResponse:
    def __init__(self):
        self.incident_handler = IncidentHandler()
        self.forensics_collector = ForensicsCollector()
        self.notification_system = NotificationSystem()
    
    def handle_security_incident(self, incident):
        """Handle security incident according to response playbook"""
        
        # Immediate response (0-15 minutes)
        incident_id = self.incident_handler.create_incident(incident)
        
        # Isolate affected systems
        self.isolate_affected_systems(incident)
        
        # Preserve evidence
        self.forensics_collector.collect_evidence(incident_id, incident)
        
        # Notify stakeholders
        self.notification_system.notify_stakeholders(incident_id, incident)
        
        # Investigation phase (15 minutes - 4 hours)
        investigation_thread = threading.Thread(
            target=self.investigate_incident,
            args=(incident_id, incident),
            daemon=True
        )
        investigation_thread.start()
        
        return incident_id
    
    def investigate_incident(self, incident_id, incident):
        """Investigate security incident"""
        
        # Analyze evidence
        evidence_analysis = self.forensics_collector.analyze_evidence(incident_id)
        
        # Determine scope and impact
        impact_assessment = self.assess_impact(incident, evidence_analysis)
        
        # Develop remediation plan
        remediation_plan = self.develop_remediation_plan(incident, impact_assessment)
        
        # Implement remediation
        self.implement_remediation(remediation_plan)
        
        # Update incident status
        self.incident_handler.update_incident_status(
            incident_id, "resolved", remediation_plan
        )
```

#### Breach Notification System
```python
class BreachNotificationSystem:
    def __init__(self):
        self.notification_templates = self.load_notification_templates()
        self.regulatory_contacts = self.load_regulatory_contacts()
    
    def handle_data_breach(self, breach_details):
        """Handle data breach notification requirements"""
        
        # Immediate notification to internal team
        self.notify_internal_team(breach_details)
        
        # Assess regulatory notification requirements
        notification_requirements = self.assess_notification_requirements(
            breach_details
        )
        
        # GDPR Article 33 - 72 hour notification
        if notification_requirements.requires_gdpr_notification:
            self.schedule_regulatory_notification(
                "gdpr_supervisor",
                breach_details,
                hours=72
            )
        
        # India PDPB notification
        if notification_requirements.requires_pdpb_notification:
            self.schedule_regulatory_notification(
                "india_data_protection_board",
                breach_details,
                hours=24
            )
        
        # Individual notifications if required
        if notification_requirements.requires_individual_notification:
            self.schedule_individual_notifications(
                breach_details.affected_individuals,
                breach_details
            )
```

## Audit and Compliance

### Comprehensive Audit Framework

#### Audit Trail Implementation
```python
class AuditTrailSystem:
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.compliance_reporter = ComplianceReporter()
    
    def log_security_event(self, event_type, details, user_id=None):
        """Log security event for audit purposes"""
        
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id or "system",
            "details": details,
            "session_id": self.get_current_session_id(),
            "ip_address": self.get_current_ip(),
            "user_agent": self.get_current_user_agent(),
            "compliance_relevant": self.is_compliance_relevant(event_type),
            "audit_hash": self.generate_audit_hash(details)
        }
        
        # Log to secure audit database
        self.audit_logger.log_entry(audit_entry)
        
        # Real-time compliance monitoring
        if audit_entry["compliance_relevant"]:
            self.monitor_compliance_event(audit_entry)
    
    def generate_audit_report(self, start_date, end_date, report_type):
        """Generate comprehensive audit report"""
        
        report = {
            "report_metadata": {
                "report_id": f"audit-{report_type}-{start_date}-{end_date}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "reporting_period": f"{start_date} to {end_date}",
                "report_type": report_type
            },
            
            "executive_summary": {
                "total_events": self.get_event_count(start_date, end_date),
                "security_incidents": self.get_incident_count(start_date, end_date),
                "compliance_violations": self.get_violation_count(start_date, end_date),
                "overall_compliance_score": self.calculate_compliance_score(start_date, end_date)
            },
            
            "detailed_analysis": {
                "event_breakdown": self.analyze_event_types(start_date, end_date),
                "security_trends": self.analyze_security_trends(start_date, end_date),
                "compliance_trends": self.analyze_compliance_trends(start_date, end_date),
                "user_activity_analysis": self.analyze_user_activity(start_date, end_date)
            },
            
            "regulatory_compliance": {
                "gdpr_compliance": self.assess_gdpr_compliance(start_date, end_date),
                "pdpb_compliance": self.assess_pdpb_compliance(start_date, end_date),
                "audit_trail_completeness": self.assess_audit_completeness(start_date, end_date)
            },
            
            "recommendations": self.generate_recommendations(start_date, end_date)
        }
        
        return report
```

#### Compliance Automation
```python
class ComplianceAutomation:
    def __init__(self):
        self.compliance_rules = ComplianceRuleEngine()
        self.automation_engine = AutomationEngine()
    
    def automate_compliance_checking(self):
        """Automate compliance checking and remediation"""
        
        while True:
            try:
                # Run comprehensive compliance check
                compliance_status = self.run_compliance_assessment()
                
                # Automatically remediate minor violations
                for violation in compliance_status.minor_violations:
                    if self.can_auto_remediate(violation):
                        remediation_success = self.automate_remediation(violation)
                        
                        if remediation_success:
                            self.log_auto_remediation(violation)
                
                # Alert on major violations
                for violation in compliance_status.major_violations:
                    self.alert_compliance_team(violation)
                
                # Update compliance dashboard
                self.update_compliance_dashboard(compliance_status)
                
                # Sleep for 15 minutes
                time.sleep(900)
                
            except Exception as e:
                logger.error(f"Compliance automation error: {str(e)}")
                time.sleep(300)  # Retry after 5 minutes
```

### Documentation and Training

#### Security Training Program
```markdown
# Argus_V Security Training Program

## Module 1: Privacy by Design Principles
- Data minimization techniques
- Anonymization methods
- Consent management
- Right to erasure implementation

## Module 2: Compliance Framework
- GDPR requirements
- India PDPB obligations
- SOC2 controls
- Audit trail management

## Module 3: Access Control
- Role-based access control (RBAC)
- NGO branch access management
- Privileged access monitoring
- Zero trust principles

## Module 4: Incident Response
- Security incident classification
- Breach notification procedures
- Evidence preservation
- Recovery procedures

## Module 5: Technical Implementation
- Secure coding practices
- Encryption standards
- Network security
- Monitoring and alerting
```

---

**Document Authority**: Security & Compliance Team, Argus_V Security Solutions  
**Review Schedule**: Quarterly security review, annual comprehensive audit  
**Training Requirements**: All personnel must complete security training annually  
**Compliance Framework**: GDPR, India PDPB 2023, SOC2 Type II  
**Emergency Contact**: security-incident@argus-v.com