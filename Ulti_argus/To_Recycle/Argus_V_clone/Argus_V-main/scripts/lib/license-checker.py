#!/usr/bin/env python3
"""
Compliance checker for Argus_V NGO licensing and branch access management
Validates NGO compliance with licensing requirements and branch access policies
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

import yaml


class ComplianceChecker:
    def __init__(self, config_dir: str = None):
        self.config_dir = config_dir or os.path.join(os.path.dirname(__file__), 'configs')
        self.data_dir = os.path.join(os.path.dirname(__file__), 'data')
        self.audit_file = os.path.join(self.data_dir, 'compliance-audit.log')
        
        # Ensure directories exist
        Path(self.config_dir).mkdir(exist_ok=True)
        Path(self.data_dir).mkdir(exist_ok=True)
        
    def check_ngo_compliance(self, ngo_id: str) -> Dict:
        """Check comprehensive NGO compliance status"""
        
        compliance_result = {
            "ngo_id": ngo_id,
            "check_timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_status": "unknown",
            "checks": {},
            "violations": [],
            "recommendations": [],
            "compliance_score": 0
        }
        
        # Run all compliance checks
        compliance_result["checks"] = {
            "license_status": self.check_license_status(ngo_id),
            "branch_access_compliance": self.check_branch_access_compliance(ngo_id),
            "data_retention_compliance": self.check_data_retention_compliance(ngo_id),
            "security_compliance": self.check_security_compliance(ngo_id),
            "audit_compliance": self.check_audit_compliance(ngo_id),
            "consent_compliance": self.check_consent_compliance(ngo_id)
        }
        
        # Calculate overall compliance
        compliance_result = self.calculate_overall_compliance(compliance_result)
        
        # Log compliance check
        self.log_compliance_check(compliance_result)
        
        return compliance_result
    
    def check_license_status(self, ngo_id: str) -> Dict:
        """Check NGO license status and requirements"""
        
        config_file = os.path.join(self.config_dir, f"ngo-{ngo_id}.yaml")
        
        if not os.path.exists(config_file):
            return {
                "status": "error",
                "message": "NGO configuration file not found",
                "compliant": False
            }
        
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            check_result = {
                "status": "unknown",
                "message": "",
                "compliant": False,
                "checks": {}
            }
            
            # Check license type and requirements
            license_type = config.get('license_type', 'free_tier')
            check_result["checks"]["license_type"] = {
                "required": True,
                "value": license_type,
                "valid": license_type in ['free_tier', 'standard_tier', 'enterprise_tier']
            }
            
            # Check organization registration
            reg_number = config.get('registration_number')
            check_result["checks"]["registration_number"] = {
                "required": True,
                "value": reg_number,
                "valid": reg_number and reg_number.startswith('REG-')
            }
            
            # Check contact information
            contact_email = config.get('contact_email')
            check_result["checks"]["contact_email"] = {
                "required": True,
                "value": contact_email,
                "valid": self.is_valid_email(contact_email)
            }
            
            # Check compliance settings
            compliance_enabled = config.get('compliance_enabled', False)
            check_result["checks"]["compliance_enabled"] = {
                "required": True,
                "value": compliance_enabled,
                "valid": compliance_enabled == True
            }
            
            # Determine overall status
            all_checks_valid = all(check["valid"] for check in check_result["checks"].values())
            
            if all_checks_valid:
                if license_type == 'free_tier':
                    check_result["status"] = "active_free_tier"
                    check_result["message"] = "Free tier NGO license active and compliant"
                    check_result["compliant"] = True
                elif license_type == 'standard_tier':
                    check_result["status"] = "active_standard_tier"
                    check_result["message"] = "Standard tier NGO license active and compliant"
                    check_result["compliant"] = True
                else:
                    check_result["status"] = "active_enterprise_tier"
                    check_result["message"] = "Enterprise tier NGO license active and compliant"
                    check_result["compliant"] = True
            else:
                check_result["status"] = "non_compliant"
                check_result["message"] = "NGO license requirements not fully met"
                check_result["compliant"] = False
            
            return check_result
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking license status: {str(e)}",
                "compliant": False
            }
    
    def check_branch_access_compliance(self, ngo_id: str) -> Dict:
        """Check branch access compliance and policies"""
        
        try:
            # Check for active branch access records
            active_access_file = os.path.join(self.data_dir, 'active-access', f'{ngo_id}.yaml')
            
            if not os.path.exists(active_access_file):
                return {
                    "status": "no_active_access",
                    "message": "No active branch access found for NGO",
                    "compliant": True
                }
            
            with open(active_access_file, 'r') as f:
                access_config = yaml.safe_load(f)
            
            check_result = {
                "status": "unknown",
                "message": "",
                "compliant": False,
                "checks": {}
            }
            
            # Check access level appropriateness
            access_level = access_config.get('access_level', 'read')
            check_result["checks"]["access_level"] = {
                "required": True,
                "value": access_level,
                "valid": access_level in ['read', 'write', 'admin']
            }
            
            # Check access duration
            access_start = access_config.get('access_start_date')
            if access_start:
                start_date = datetime.fromisoformat(access_start.replace('Z', '+00:00'))
                days_active = (datetime.now(timezone.utc) - start_date).days
                
                # NGO access should not exceed 365 days without renewal
                check_result["checks"]["access_duration"] = {
                    "required": True,
                    "value": days_active,
                    "valid": days_active <= 365,
                    "warning": days_active > 300
                }
            
            # Check for required compliance monitoring
            monitoring_enabled = access_config.get('monitoring_enabled', False)
            check_result["checks"]["monitoring_enabled"] = {
                "required": True,
                "value": monitoring_enabled,
                "valid": monitoring_enabled == True
            }
            
            # Check branch protection settings
            branch_protection = access_config.get('branch_protection_enabled', False)
            check_result["checks"]["branch_protection"] = {
                "required": True,
                "value": branch_protection,
                "valid": branch_protection == True
            }
            
            all_checks_valid = all(check.get("valid", False) for check in check_result["checks"].values())
            
            if all_checks_valid:
                check_result["status"] = "compliant"
                check_result["message"] = "Branch access is compliant with policy"
                check_result["compliant"] = True
            else:
                check_result["status"] = "non_compliant"
                check_result["message"] = "Branch access does not meet compliance requirements"
                check_result["compliant"] = False
            
            return check_result
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking branch access compliance: {str(e)}",
                "compliant": False
            }
    
    def check_data_retention_compliance(self, ngo_id: str) -> Dict:
        """Check data retention compliance (24-hour policy)"""
        
        try:
            # Check if data retention policy is configured
            config_file = os.path.join(self.config_dir, f"ngo-{ngo_id}.yaml")
            
            if not os.path.exists(config_file):
                return {
                    "status": "no_config",
                    "message": "No configuration file found for data retention check",
                    "compliant": False
                }
            
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            check_result = {
                "status": "unknown",
                "message": "",
                "compliant": False,
                "checks": {}
            }
            
            # Check retention policy configuration
            retention_policy = config.get('retention_policy', '24_hours')
            check_result["checks"]["retention_policy"] = {
                "required": True,
                "value": retention_policy,
                "valid": retention_policy == '24_hours'
            }
            
            # Check anonymization requirement
            anonymization_required = config.get('anonymization_required', False)
            check_result["checks"]["anonymization_required"] = {
                "required": True,
                "value": anonymization_required,
                "valid": anonymization_required == True
            }
            
            # Check if automated deletion is enabled
            automated_deletion = config.get('automated_deletion_enabled', True)
            check_result["checks"]["automated_deletion"] = {
                "required": True,
                "value": automated_deletion,
                "valid": automated_deletion == True
            }
            
            # Check audit trail requirement
            audit_required = config.get('audit_required', False)
            check_result["checks"]["audit_required"] = {
                "required": True,
                "value": audit_required,
                "valid": audit_required == True
            }
            
            all_checks_valid = all(check.get("valid", False) for check in check_result["checks"].values())
            
            if all_checks_valid:
                check_result["status"] = "compliant"
                check_result["message"] = "Data retention policy is compliant"
                check_result["compliant"] = True
            else:
                check_result["status"] = "non_compliant"
                check_result["message"] = "Data retention policy does not meet requirements"
                check_result["compliant"] = False
            
            return check_result
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking data retention compliance: {str(e)}",
                "compliant": False
            }
    
    def check_security_compliance(self, ngo_id: str) -> Dict:
        """Check security compliance requirements"""
        
        try:
            config_file = os.path.join(self.config_dir, f"ngo-{ngo_id}.yaml")
            
            if not os.path.exists(config_file):
                return {
                    "status": "no_config",
                    "message": "No configuration file found for security check",
                    "compliant": False
                }
            
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            check_result = {
                "status": "unknown",
                "message": "",
                "compliant": False,
                "checks": {}
            }
            
            # Check encryption requirements
            encryption_required = config.get('encryption_required', True)
            check_result["checks"]["encryption_required"] = {
                "required": True,
                "value": encryption_required,
                "valid": encryption_required == True
            }
            
            # Check access control requirements
            access_control = config.get('access_control_enabled', True)
            check_result["checks"]["access_control"] = {
                "required": True,
                "value": access_control,
                "valid": access_control == True
            }
            
            # Check incident response requirement
            incident_response = config.get('incident_response_plan', False)
            check_result["checks"]["incident_response"] = {
                "required": True,
                "value": incident_response,
                "valid": incident_response == True
            }
            
            all_checks_valid = all(check.get("valid", False) for check in check_result["checks"].values())
            
            if all_checks_valid:
                check_result["status"] = "compliant"
                check_result["message"] = "Security requirements are met"
                check_result["compliant"] = True
            else:
                check_result["status"] = "non_compliant"
                check_result["message"] = "Security requirements not fully met"
                check_result["compliant"] = False
            
            return check_result
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking security compliance: {str(e)}",
                "compliant": False
            }
    
    def check_audit_compliance(self, ngo_id: str) -> Dict:
        """Check audit trail compliance"""
        
        try:
            # Check for recent audit logs
            audit_dir = os.path.join(self.data_dir, 'audit')
            
            if not os.path.exists(audit_dir):
                return {
                    "status": "no_audit_dir",
                    "message": "Audit directory not found",
                    "compliant": False
                }
            
            # Check for audit files in the last 30 days
            audit_files = list(Path(audit_dir).glob(f"*access*{ngo_id}*.jsonl"))
            recent_audit_files = []
            
            for audit_file in audit_files:
                if audit_file.stat().st_mtime > (datetime.now().timestamp() - 30 * 24 * 3600):
                    recent_audit_files.append(audit_file)
            
            check_result = {
                "status": "unknown",
                "message": "",
                "compliant": False,
                "checks": {}
            }
            
            # Check audit log presence
            check_result["checks"]["audit_logs_present"] = {
                "required": True,
                "value": len(audit_files),
                "valid": len(audit_files) > 0
            }
            
            # Check recent audit activity
            check_result["checks"]["recent_audit_activity"] = {
                "required": True,
                "value": len(recent_audit_files),
                "valid": len(recent_audit_files) > 0
            }
            
            all_checks_valid = all(check.get("valid", False) for check in check_result["checks"].values())
            
            if all_checks_valid:
                check_result["status"] = "compliant"
                check_result["message"] = "Audit trail requirements are met"
                check_result["compliant"] = True
            else:
                check_result["status"] = "non_compliant"
                check_result["message"] = "Audit trail requirements not met"
                check_result["compliant"] = False
            
            return check_result
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking audit compliance: {str(e)}",
                "compliant": False
            }
    
    def check_consent_compliance(self, ngo_id: str) -> Dict:
        """Check data subject consent compliance"""
        
        try:
            config_file = os.path.join(self.config_dir, f"ngo-{ngo_id}.yaml")
            
            if not os.path.exists(config_file):
                return {
                    "status": "no_config",
                    "message": "No configuration file found for consent check",
                    "compliant": False
                }
            
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            check_result = {
                "status": "unknown",
                "message": "",
                "compliant": False,
                "checks": {}
            }
            
            # Check consent management requirement
            consent_management = config.get('consent_management_enabled', True)
            check_result["checks"]["consent_management"] = {
                "required": True,
                "value": consent_management,
                "valid": consent_management == True
            }
            
            # Check withdrawal mechanism
            withdrawal_mechanism = config.get('consent_withdrawal_mechanism', False)
            check_result["checks"]["withdrawal_mechanism"] = {
                "required": True,
                "value": withdrawal_mechanism,
                "valid": withdrawal_mechanism == True
            }
            
            # Check data subject rights implementation
            rights_implementation = config.get('data_subject_rights_implemented', True)
            check_result["checks"]["rights_implementation"] = {
                "required": True,
                "value": rights_implementation,
                "valid": rights_implementation == True
            }
            
            all_checks_valid = all(check.get("valid", False) for check in check_result["checks"].values())
            
            if all_checks_valid:
                check_result["status"] = "compliant"
                check_result["message"] = "Consent management requirements are met"
                check_result["compliant"] = True
            else:
                check_result["status"] = "non_compliant"
                check_result["message"] = "Consent management requirements not met"
                check_result["compliant"] = False
            
            return check_result
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error checking consent compliance: {str(e)}",
                "compliant": False
            }
    
    def calculate_overall_compliance(self, compliance_result: Dict) -> Dict:
        """Calculate overall compliance score and status"""
        
        checks = compliance_result["checks"]
        total_checks = len(checks)
        passed_checks = sum(1 for check in checks.values() if check.get("compliant", False))
        
        compliance_score = (passed_checks / total_checks) * 100 if total_checks > 0 else 0
        
        compliance_result["compliance_score"] = compliance_score
        compliance_result["checks_passed"] = passed_checks
        compliance_result["checks_total"] = total_checks
        
        # Determine overall status
        if compliance_score == 100:
            compliance_result["overall_status"] = "fully_compliant"
        elif compliance_score >= 80:
            compliance_result["overall_status"] = "mostly_compliant"
            compliance_result["recommendations"].append("Address remaining compliance gaps")
        elif compliance_score >= 60:
            compliance_result["overall_status"] = "partially_compliant"
            compliance_result["recommendations"].append("Significant compliance improvements needed")
        else:
            compliance_result["overall_status"] = "non_compliant"
            compliance_result["violations"].append("Major compliance failures detected")
        
        return compliance_result
    
    def is_valid_email(self, email: str) -> bool:
        """Simple email validation"""
        import re
        pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
        return bool(re.match(pattern, email)) if email else False
    
    def log_compliance_check(self, compliance_result: Dict):
        """Log compliance check results"""
        
        log_entry = {
            "timestamp": compliance_result["check_timestamp"],
            "ngo_id": compliance_result["ngo_id"],
            "overall_status": compliance_result["overall_status"],
            "compliance_score": compliance_result["compliance_score"],
            "checks_passed": compliance_result["checks_passed"],
            "checks_total": compliance_result["checks_total"]
        }
        
        # Append to audit file
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def generate_compliance_report(self, ngo_id: str, output_file: str = None) -> str:
        """Generate comprehensive compliance report"""
        
        compliance_result = self.check_ngo_compliance(ngo_id)
        
        report_content = {
            "compliance_report": {
                "report_id": f"compliance-{ngo_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "ngo_id": ngo_id,
                "overall_status": compliance_result["overall_status"],
                "compliance_score": compliance_result["compliance_score"],
                "checks_performed": len(compliance_result["checks"]),
                "checks_passed": compliance_result["checks_passed"],
                "checks_failed": compliance_result["checks_total"] - compliance_result["checks_passed"],
                "detailed_results": compliance_result["checks"],
                "violations": compliance_result["violations"],
                "recommendations": compliance_result["recommendations"]
            }
        }
        
        # Write to output file or return JSON
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report_content, f, indent=2)
            return output_file
        else:
            return json.dumps(report_content, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Argus_V Compliance Checker')
    parser.add_argument('--ngo-id', required=True, help='NGO identifier to check')
    parser.add_argument('--check-license', action='store_true', help='Check license status only')
    parser.add_argument('--check-branch-access', action='store_true', help='Check branch access compliance only')
    parser.add_argument('--check-data-retention', action='store_true', help='Check data retention compliance only')
    parser.add_argument('--check-compliant', action='store_true', help='Return exit code 0 if compliant, 1 if not')
    parser.add_argument('--output-file', help='Output file for compliance report')
    parser.add_argument('--config-dir', help='Configuration directory path')
    
    args = parser.parse_args()
    
    checker = ComplianceChecker(args.config_dir)
    
    try:
        if args.check_license:
            result = checker.check_license_status(args.ngo_id)
            print(json.dumps(result, indent=2))
            
        elif args.check_branch_access:
            result = checker.check_branch_access_compliance(args.ngo_id)
            print(json.dumps(result, indent=2))
            
        elif args.check_data_retention:
            result = checker.check_data_retention_compliance(args.ngo_id)
            print(json.dumps(result, indent=2))
            
        elif args.check_compliant:
            # Quick compliance check for scripts
            compliance_result = checker.check_ngo_compliance(args.ngo_id)
            is_compliant = compliance_result["overall_status"] in ["fully_compliant", "mostly_compliant"]
            
            if is_compliant:
                print(f"NGO {args.ngo_id} is compliant")
                sys.exit(0)
            else:
                print(f"NGO {args.ngo_id} is not compliant")
                sys.exit(1)
            
        else:
            # Full compliance check
            if args.output_file:
                output_file = checker.generate_compliance_report(args.ngo_id, args.output_file)
                print(f"Compliance report generated: {output_file}")
            else:
                report = checker.generate_compliance_report(args.ngo_id)
                print(report)
                
    except Exception as e:
        print(f"Error checking compliance: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()