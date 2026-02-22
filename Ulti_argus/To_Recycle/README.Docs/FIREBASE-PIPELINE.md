# Firebase Free-Tier Pipeline Documentation

**Document Version**: 1.0  
**Effective Date**: January 1, 2025  
**Last Updated**: December 18, 2024  

---

## Overview

This document outlines the comprehensive Firebase integration for Argus_V, focusing on free-tier optimizations, cost management, and efficient data pipelines. The implementation leverages Firebase's generous free tier while maintaining robust security, privacy, and compliance standards.

## Table of Contents

1. [Firebase Free-Tier Architecture](#firebase-free-tier-architecture)
2. [Cost Optimization Strategies](#cost-optimization-strategies)
3. [Data Pipeline Implementation](#data-pipeline-implementation)
4. [Security and Privacy Controls](#security-and-privacy-controls)
5. [Monitoring and Alerting](#monitoring-and-alerting)
6. [Backup and Disaster Recovery](#backup-and-disaster-recovery)
7. [Operational Procedures](#operational-procedures)
8. [Cost Management](#cost-management)

## Firebase Free-Tier Architecture

### Free Tier Limits and Allocation

#### Firebase Free Tier Specifications
```yaml
firebase_free_tier_limits:
  firestore:
    document_reads: 50,000_per_day
    document_writes: 20,000_per_day
    document_deletes: 20,000_per_day
    stored_data: 1_GB
    bandwidth: 10_GB_per_month
  
  storage:
    stored_data: 5_GB
    downloads: 10_GB_per_month
    upload_operations: 125,000_per_month
  
  hosting:
    stored_data: 10_GB
    bandwidth: 10_GB_per_month
  
  authentication:
    monthly_active_users: 50,000
    phone_number_signups: 10,000_per_month
  
  cloud_functions:
    invocations: 125,000_per_month
    compute_time: 2_000,000_GHz_seconds_per_month
    bandwidth: 125_GB_per_month
```

#### Argus_V Free-Tier Resource Allocation
```yaml
argus_v_resource_allocation:
  ml_models:
    storage: 2_GB
    downloads: 5_GB_per_month
    update_frequency: "weekly"
  
  threat_intelligence:
    storage: 1_GB
    bandwidth: 3_GB_per_month
    sync_frequency: "hourly"
  
  compliance_reports:
    storage: 500_MB
    bandwidth: 1_GB_per_month
    retention: "quarterly"
  
  system_logs:
    storage: 1_GB
    bandwidth: 2_GB_per_month
    retention: "monthly"
  
  user_data:
    storage: 500_MB
    bandwidth: 1_GB_per_month
    retention: "24_hours_anonymized"
```

### Multi-Project Architecture

#### Development and Production Separation
```python
class FirebaseProjectManager:
    def __init__(self):
        self.projects = {
            'development': {
                'project_id': 'argus-v-dev',
                'free_tier_limits': 'full_allocation',
                'data_retention': 'reduced',
                'monitoring': 'comprehensive'
            },
            'staging': {
                'project_id': 'argus-v-staging',
                'free_tier_limits': 'full_allocation',
                'data_retention': 'production_like',
                'monitoring': 'production_monitoring'
            },
            'production': {
                'project_id': 'argus-v-prod',
                'free_tier_limits': 'production_allocated',
                'data_retention': 'full_compliance',
                'monitoring': 'full_alerting'
            }
        }
    
    def get_project_config(self, environment: str) -> Dict:
        """Get Firebase configuration for specific environment"""
        return self.projects.get(environment, {})
```

## Cost Optimization Strategies

### Efficient Data Storage Patterns

#### Document Design for Minimal Reads/Writes
```python
class OptimizedDataDesign:
    def __init__(self):
        self.batch_size = 1000
        self.update_frequency = 'hourly'
        self.compression_enabled = True
    
    def design_threat_intelligence_schema(self):
        """Design schema to minimize Firestore operations"""
        return {
            # Single document per update cycle
            "threat_intelligence_daily": {
                "document_id": "daily_2024_12_18",
                "fields": {
                    "date": "2024-12-18",
                    "threat_indicators_count": 1250,
                    "last_updated": "2024-12-18T10:30:00Z",
                    "threat_data": {
                        # Embedded array of threats to reduce reads
                        "malware_indicators": [...],
                        "suspicious_ips": [...],
                        "domain_reputations": [...]
                    }
                }
            }
        }
    
    def design_ml_model_metadata_schema(self):
        """Minimal write operations for ML model metadata"""
        return {
            "model_metadata": {
                "current_model": {
                    "version": "v1.5.0",
                    "download_url": "https://storage.googleapis.com/...",
                    "model_hash": "sha256_hash",
                    "upload_date": "2024-12-18T10:00:00Z",
                    "performance_metrics": {
                        "accuracy": 0.95,
                        "false_positive_rate": 0.02,
                        "training_date": "2024-12-15"
                    }
                }
            }
        }
```

#### Caching Strategy
```python
class FirebaseCacheManager:
    def __init__(self, firestore_client):
        self.firestore = firestore_client
        self.cache_ttl = 3600  # 1 hour
        self.local_cache_path = '/var/cache/argus-v/firebase/'
    
    async def get_threat_intelligence(self, date: str) -> Dict:
        """Get threat intelligence with local caching"""
        cache_file = f"{self.local_cache_path}/threat_intel_{date}.json"
        
        # Check local cache first
        if await self.is_cache_valid(cache_file):
            return await self.load_from_cache(cache_file)
        
        # Fetch from Firebase
        doc = await self.firestore.collection('threat_intelligence').document(date).get()
        
        if doc.exists:
            data = doc.to_dict()
            await self.save_to_cache(cache_file, data)
            return data
        
        return {}
    
    async def cache_ml_model_metadata(self):
        """Cache ML model metadata locally"""
        doc = await self.firestore.collection('models').document('current').get()
        
        if doc.exists:
            metadata = doc.to_dict()
            cache_file = f"{self.local_cache_path}/model_metadata.json"
            await self.save_to_cache(cache_file, metadata)
            return metadata
        
        return {}
```

### Bandwidth Optimization

#### Data Compression and Minification
```python
class BandwidthOptimizer:
    def __init__(self):
        self.compression_threshold = 1024  # 1KB
        self.enable_gzip = True
        self.minimize_json = True
    
    async def optimize_data_transfer(self, data: Dict) -> bytes:
        """Optimize data for bandwidth efficiency"""
        
        # Convert to JSON
        json_data = json.dumps(data, separators=(',', ':')) if self.minimize_json else json.dumps(data)
        
        # Compress if above threshold
        if len(json_data) > self.compression_threshold and self.enable_gzip:
            compressed_data = gzip.compress(json_data.encode())
            return compressed_data
        
        return json_data.encode()
    
    def calculate_transfer_cost(self, data_size_mb: float) -> Dict:
        """Calculate estimated transfer costs within free tier"""
        monthly_bandwidth_limit_gb = 10
        current_usage_gb = self.get_monthly_bandwidth_usage()
        
        remaining_quota_gb = monthly_bandwidth_limit_gb - current_usage_gb
        
        return {
            "data_size_mb": data_size_mb,
            "will_fit_in_quota": data_size_mb <= (remaining_quota_gb * 1024),
            "quota_utilization_percent": (current_usage_gb / monthly_bandwidth_limit_gb) * 100,
            "estimated_cost_excess": max(0, (data_size_mb / 1024 - remaining_quota_gb) * 0.12)  # $0.12/GB excess
        }
```

## Data Pipeline Implementation

### ML Model Pipeline

#### Automated Model Updates
```python
class FirebaseModelPipeline:
    def __init__(self, firestore_client, storage_client):
        self.firestore = firestore_client
        self.storage = storage_client
        self.bucket_name = 'argus-v-models'
    
    async def upload_new_model(self, model_path: str, model_metadata: Dict) -> bool:
        """Upload new ML model to Firebase Storage"""
        try:
            # Validate model file
            model_size = os.path.getsize(model_path)
            if model_size > 100 * 1024 * 1024:  # 100MB limit
                raise ValueError("Model file too large for free tier")
            
            # Generate unique model identifier
            model_id = f"model_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
            
            # Upload to Storage
            bucket = self.storage.bucket(self.bucket_name)
            blob = bucket.blob(f"models/{model_id}.pkl")
            
            # Upload with metadata
            metadata = {
                'model_id': model_id,
                'upload_date': datetime.now(timezone.utc).isoformat(),
                'file_size': str(model_size),
                'model_type': model_metadata.get('type', 'unknown'),
                'version': model_metadata.get('version', 'unknown')
            }
            
            blob.upload_from_filename(model_path, metadata=metadata)
            
            # Update Firestore with model info
            await self.update_model_metadata(model_id, metadata)
            
            # Clean up old models (keep only latest 3)
            await self.cleanup_old_models()
            
            return True
            
        except Exception as e:
            logger.error(f"Model upload failed: {str(e)}")
            return False
    
    async def update_model_metadata(self, model_id: str, metadata: Dict):
        """Update model metadata in Firestore"""
        await self.firestore.collection('model_versions').document(model_id).set({
            **metadata,
            'is_active': False,
            'is_current': False
        })
        
        # Set current model
        await self.firestore.collection('models').document('current').update({
            'current_model_id': model_id,
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'is_active': True
        })
    
    async def download_current_model(self) -> Optional[bytes]:
        """Download current ML model from Firebase Storage"""
        try:
            # Get current model info
            model_doc = await self.firestore.collection('models').document('current').get()
            
            if not model_doc.exists:
                logger.warning("No current model found")
                return None
            
            model_info = model_doc.to_dict()
            model_id = model_info.get('current_model_id')
            
            if not model_id:
                logger.warning("Current model ID not found")
                return None
            
            # Download from Storage
            bucket = self.storage.bucket(self.bucket_name)
            blob = bucket.blob(f"models/{model_id}.pkl")
            
            model_data = blob.download_as_bytes()
            logger.info(f"Downloaded model {model_id} ({len(model_data)} bytes)")
            
            return model_data
            
        except Exception as e:
            logger.error(f"Model download failed: {str(e)}")
            return None
```

### Threat Intelligence Pipeline

#### Community Threat Sharing
```python
class ThreatIntelligencePipeline:
    def __init__(self, firestore_client):
        self.firestore = firestore_client
        self.collection_name = 'community_threats'
    
    async def submit_anonymized_threat(self, threat_data: Dict) -> bool:
        """Submit anonymized threat indicator to community intelligence"""
        try:
            # Validate threat data
            if not self.validate_threat_data(threat_data):
                return False
            
            # Anonymize sensitive data
            anonymized_threat = self.anonymize_threat_data(threat_data)
            
            # Add metadata
            anonymized_threat.update({
                'submission_id': self.generate_submission_id(),
                'submission_time': datetime.now(timezone.utc).isoformat(),
                'submission_source': 'community_member',
                'verification_status': 'pending'
            })
            
            # Store in Firestore
            await self.firestore.collection(self.collection_name).add(anonymized_threat)
            
            return True
            
        except Exception as e:
            logger.error(f"Threat submission failed: {str(e)}")
            return False
    
    def anonymize_threat_data(self, threat_data: Dict) -> Dict:
        """Anonymize threat data for community sharing"""
        anonymized = threat_data.copy()
        
        # Hash IP addresses
        if 'ip_address' in anonymized:
            anonymized['anonymized_ip'] = self.hash_ip_address(anonymized['ip_address'])
            del anonymized['ip_address']
        
        # Hash domain names
        if 'domain' in anonymized:
            anonymized['anonymized_domain'] = self.hash_domain_name(anonymized['domain'])
            del anonymized['domain']
        
        # Round timestamps to hour precision
        if 'first_seen' in anonymized:
            anonymized['first_seen_rounded'] = self.round_timestamp(anonymized['first_seen'])
            del anonymized['first_seen']
        
        return anonymized
    
    async def fetch_latest_threat_intelligence(self) -> List[Dict]:
        """Fetch latest threat intelligence from community"""
        try:
            # Get threats from last 24 hours
            yesterday = datetime.now(timezone.utc) - timedelta(days=1)
            
            docs = (self.firestore.collection(self.collection_name)
                   .where('submission_time', '>=', yesterday.isoformat())
                   .order_by('submission_time', direction=firestore.Query.DESCENDING)
                   .limit(1000)
                   .stream())
            
            threats = []
            for doc in docs:
                threat = doc.to_dict()
                threat['doc_id'] = doc.id
                threats.append(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"Threat intelligence fetch failed: {str(e)}")
            return []
```

### Compliance Report Pipeline

#### Automated Compliance Reporting
```python
class ComplianceReportingPipeline:
    def __init__(self, firestore_client, storage_client):
        self.firestore = firestore_client
        self.storage = storage_client
        self.reports_bucket = 'argus-v-reports'
    
    async def generate_monthly_report(self, year: int, month: int) -> str:
        """Generate and upload monthly compliance report"""
        try:
            # Gather compliance data
            report_data = await self.gather_compliance_data(year, month)
            
            # Generate PDF report
            pdf_content = self.generate_compliance_pdf(report_data)
            
            # Upload to Firebase Storage
            report_filename = f"compliance_reports/monthly_{year}_{month:02d}.pdf"
            await self.upload_report(pdf_content, report_filename)
            
            # Update report metadata
            await self.update_report_metadata(year, month, report_filename)
            
            return report_filename
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            return None
    
    async def gather_compliance_data(self, year: int, month: int) -> Dict:
        """Gather all compliance data for reporting period"""
        start_date = datetime(year, month, 1, tzinfo=timezone.utc)
        if month == 12:
            end_date = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            end_date = datetime(year, month + 1, 1, tzinfo=timezone.utc)
        
        data = {
            "reporting_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "year": year,
                "month": month
            },
            
            "data_retention_compliance": await self.get_retention_compliance(start_date, end_date),
            
            "anonymization_metrics": await self.get_anonymization_metrics(start_date, end_date),
            
            "access_control_audit": await self.get_access_audit(start_date, end_date),
            
            "threat_detection_statistics": await self.get_threat_detection_stats(start_date, end_date),
            
            "privacy_incidents": await self.get_privacy_incidents(start_date, end_date),
            
            "compliance_violations": await self.get_compliance_violations(start_date, end_date)
        }
        
        return data
    
    def generate_compliance_pdf(self, report_data: Dict) -> bytes:
        """Generate PDF compliance report"""
        # This would use a PDF generation library like reportlab
        # For now, return a placeholder
        return b"PDF report content"
    
    async def upload_report(self, pdf_content: bytes, filename: str) -> bool:
        """Upload report to Firebase Storage"""
        try:
            bucket = self.storage.bucket(self.reports_bucket)
            blob = bucket.blob(filename)
            
            blob.upload_from_bytes(pdf_content, content_type='application/pdf')
            
            # Set metadata
            blob.metadata = {
                'report_type': 'compliance',
                'generated_date': datetime.now(timezone.utc).isoformat(),
                'content_disposition': 'attachment'
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Report upload failed: {str(e)}")
            return False
```

## Security and Privacy Controls

### End-to-End Encryption

#### Client-Side Encryption
```python
class FirebaseEncryptionManager:
    def __init__(self, encryption_key: str):
        self.encryption_key = encryption_key.encode()
        self.cipher_suite = Fernet(self.encryption_key)
    
    async def encrypt_sensitive_data(self, data: Dict) -> Dict:
        """Encrypt sensitive data before Firebase upload"""
        encrypted_data = {}
        
        for key, value in data.items():
            if self.is_sensitive_field(key):
                # Encrypt the value
                encrypted_value = self.cipher_suite.encrypt(json.dumps(value).encode())
                encrypted_data[f"encrypted_{key}"] = base64.b64encode(encrypted_value).decode()
            else:
                encrypted_data[key] = value
        
        return encrypted_data
    
    async def decrypt_sensitive_data(self, encrypted_data: Dict) -> Dict:
        """Decrypt sensitive data after Firebase download"""
        decrypted_data = {}
        
        for key, value in encrypted_data.items():
            if key.startswith("encrypted_"):
                # Decrypt the value
                encrypted_value = base64.b64decode(value.encode())
                decrypted_value = self.cipher_suite.decrypt(encrypted_value)
                original_key = key[10:]  # Remove "encrypted_" prefix
                decrypted_data[original_key] = json.loads(decrypted_value.decode())
            else:
                decrypted_data[key] = value
        
        return decrypted_data
    
    def is_sensitive_field(self, field_name: str) -> bool:
        """Identify sensitive fields that require encryption"""
        sensitive_fields = [
            'email', 'phone', 'ip_address', 'user_id', 
            'session_token', 'api_key', 'personal_data'
        ]
        return any(field in field_name.lower() for field in sensitive_fields)
```

### Access Control

#### Firebase Security Rules
```javascript
// Firestore Security Rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    // Public access to current model metadata (read-only)
    match /models/current {
      allow read: if true;
      allow write: if request.auth != null && 
        request.auth.token.admin == true;
    }
    
    // Community threat intelligence (authenticated users only)
    match /community_threats/{threatId} {
      allow read: if request.auth != null;
      allow create: if request.auth != null && 
        validateThreatSubmission(request.resource.data);
      allow update, delete: if false; // Immutable
    }
    
    // Compliance reports (admin only)
    match /compliance_reports/{reportId} {
      allow read: if request.auth != null && 
        hasAnyRole(['admin', 'compliance_officer']);
      allow write: if false; // Generated by system
    }
    
    // User preferences (user-specific)
    match /user_preferences/{userId} {
      allow read, write: if request.auth != null && 
        request.auth.uid == userId;
    }
  }
}

function hasAnyRole(roles) {
  return request.auth != null && 
    roles.hasAny([request.auth.token.role]);
}

function validateThreatSubmission(data) {
  return data.keys().hasAll(['threat_type', 'anonymized_ip']) &&
    data.anonymized_ip.matches('^[a-f0-9]{64}$') && // SHA-256 hash format
    data.threat_type in ['malware', 'phishing', 'suspicious_activity'];
}
```

```yaml
# Storage Security Rules
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    
    // ML models (read-only public access)
    match /models/{modelFile} {
      allow read: if true;
      allow write: if request.auth != null && 
        request.auth.token.admin == true;
    }
    
    // Compliance reports (admin access only)
    match /compliance_reports/{reportFile} {
      allow read: if request.auth != null && 
        hasAnyRole(['admin', 'compliance_officer']);
      allow write: if false;
    }
    
    // System logs (restricted access)
    match /system_logs/{logFile} {
      allow read: if request.auth != null && 
        hasAnyRole(['admin', 'developer']);
      allow write: if request.auth != null && 
        request.auth.token.role == 'system';
    }
  }
}
```

## Monitoring and Alerting

### Firebase Usage Monitoring

#### Real-time Quota Tracking
```python
class FirebaseQuotaMonitor:
    def __init__(self, firestore_client):
        self.firestore = firestore_client
        self.alert_thresholds = {
            'firestore_reads_percent': 80,
            'firestore_writes_percent': 80,
            'storage_usage_percent': 90,
            'bandwidth_usage_percent': 80
        }
    
    async def check_quota_usage(self) -> Dict:
        """Check current quota usage and alert if approaching limits"""
        usage_stats = await self.get_usage_statistics()
        alerts = []
        
        # Check Firestore reads
        reads_percent = (usage_stats['firestore_reads_today'] / 50000) * 100
        if reads_percent > self.alert_thresholds['firestore_reads_percent']:
            alerts.append({
                'type': 'firestore_reads',
                'severity': 'warning',
                'current_usage': reads_percent,
                'threshold': self.alert_thresholds['firestore_reads_percent'],
                'message': f"Firestore reads at {reads_percent:.1f}% of daily limit"
            })
        
        # Check storage usage
        storage_percent = (usage_stats['storage_used_gb'] / 5.0) * 100
        if storage_percent > self.alert_thresholds['storage_usage_percent']:
            alerts.append({
                'type': 'storage_usage',
                'severity': 'critical',
                'current_usage': storage_percent,
                'threshold': self.alert_thresholds['storage_usage_percent'],
                'message': f"Storage usage at {storage_percent:.1f}% of limit"
            })
        
        return {
            'usage_stats': usage_stats,
            'alerts': alerts,
            'quota_safe': len(alerts) == 0
        }
    
    async def get_usage_statistics(self) -> Dict:
        """Get current usage statistics"""
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        
        # This would integrate with Firebase usage API or custom tracking
        stats = {
            'firestore_reads_today': await self.get_firestore_read_count(today),
            'firestore_writes_today': await self.get_firestore_write_count(today),
            'storage_used_gb': await self.get_storage_usage_gb(),
            'bandwidth_used_gb_month': await self.get_bandwidth_usage_gb(),
            'last_updated': datetime.now(timezone.utc).isoformat()
        }
        
        return stats
```

### Cost Monitoring Dashboard

#### Automated Cost Tracking
```python
class FirebaseCostMonitor:
    def __init__(self):
        self.free_tier_costs = {
            'firestore_reads': 0.036 / 100000,  # $0.036 per 100k reads
            'firestore_writes': 0.108 / 100000, # $0.108 per 100k writes
            'storage_gb_month': 0.018,          # $0.018 per GB-month
            'bandwidth_gb': 0.12               # $0.12 per GB
        }
    
    def calculate_estimated_costs(self, usage_stats: Dict) -> Dict:
        """Calculate estimated costs based on usage"""
        
        # Calculate overages
        reads_overage = max(0, usage_stats['firestore_reads_today'] - 50000)
        writes_overage = max(0, usage_stats['firestore_writes_today'] - 20000)
        storage_overage = max(0, usage_stats['storage_used_gb'] - 5)
        bandwidth_overage = max(0, usage_stats['bandwidth_used_gb_month'] - 10)
        
        # Calculate costs
        costs = {
            'free_tier_usage': 0,  # Always free within limits
            'firestore_reads_cost': reads_overage * self.free_tier_costs['firestore_reads'],
            'firestore_writes_cost': writes_overage * self.free_tier_costs['firestore_writes'],
            'storage_cost': storage_overage * self.free_tier_costs['storage_gb_month'],
            'bandwidth_cost': bandwidth_overage * self.free_tier_costs['bandwidth_gb'],
            'total_estimated_cost': 0
        }
        
        costs['total_estimated_cost'] = (
            costs['firestore_reads_cost'] +
            costs['firestore_writes_cost'] +
            costs['storage_cost'] +
            costs['bandwidth_cost']
        )
        
        return costs
```

## Backup and Disaster Recovery

### Automated Backup Strategy

#### Local Backup with Firebase Sync
```python
class BackupManager:
    def __init__(self, firestore_client, storage_client):
        self.firestore = firestore_client
        self.storage = storage_client
        self.local_backup_path = '/var/backups/argus-v/firebase'
        self.backup_retention_days = 30
    
    async def create_daily_backup(self) -> bool:
        """Create daily backup of critical data"""
        try:
            backup_date = datetime.now(timezone.utc).strftime('%Y%m%d')
            backup_path = f"{self.local_backup_path}/{backup_date}/"
            
            # Create backup directory
            Path(backup_path).mkdir(parents=True, exist_ok=True)
            
            # Backup Firestore collections
            await self.backup_firestore_collections(backup_path)
            
            # Backup Storage buckets
            await self.backup_storage_buckets(backup_path)
            
            # Upload backup metadata to Firebase
            await self.upload_backup_metadata(backup_date, backup_path)
            
            # Clean up old local backups
            await self.cleanup_old_backups()
            
            return True
            
        except Exception as e:
            logger.error(f"Backup creation failed: {str(e)}")
            return False
    
    async def backup_firestore_collections(self, backup_path: str):
        """Backup Firestore collections"""
        collections_to_backup = [
            'models', 'community_threats', 'compliance_reports', 
            'user_preferences', 'system_logs'
        ]
        
        for collection_name in collections_to_backup:
            collection_data = {}
            
            docs = self.firestore.collection(collection_name).stream()
            for doc in docs:
                collection_data[doc.id] = doc.to_dict()
            
            # Save to local file
            backup_file = f"{backup_path}/{collection_name}.json"
            with open(backup_file, 'w') as f:
                json.dump(collection_data, f, indent=2)
            
            logger.info(f"Backed up {len(collection_data)} documents from {collection_name}")
```

## Operational Procedures

### Deployment Pipeline

#### Automated Deployment Script
```bash
#!/bin/bash
# firebase-deployment.sh

set -e

ENVIRONMENT="$1"
VERSION="$2"

case $ENVIRONMENT in
    "dev"|"development")
        PROJECT_ID="argus-v-dev"
        ;;
    "staging")
        PROJECT_ID="argus-v-staging"
        ;;
    "prod"|"production")
        PROJECT_ID="argus-v-prod"
        ;;
    *)
        echo "Usage: $0 {dev|staging|prod} <version>"
        exit 1
        ;;
esac

echo "Deploying Argus_V v$VERSION to $ENVIRONMENT"

# Set Firebase project
firebase use $PROJECT_ID

# Build and deploy Cloud Functions
firebase deploy --only functions

# Deploy Firestore security rules
firebase deploy --only firestore:rules

# Deploy Storage security rules
firebase deploy --only storage

# Update configuration
firebase functions:config:set argus.version="$VERSION"
firebase functions:config:set argus.environment="$ENVIRONMENT"

# Run post-deployment tests
python3 -m pytest tests/firebase/test_deployment_$ENVIRONMENT.py -v

echo "Deployment completed successfully"
```

### Monitoring and Alerting Setup

#### Alert Configuration
```yaml
# firebase-alerts.yaml
alerts:
  quota_usage:
    firestore_reads:
      threshold: 80  # percent
      action: "notify_admin"
      message: "Firestore reads approaching daily limit"
    
    storage_usage:
      threshold: 90  # percent
      action: "emergency_cleanup"
      message: "Storage usage critically high"
    
    bandwidth_usage:
      threshold: 80  # percent
      action: "rate_limit_operations"
      message: "Bandwidth usage high"
  
  cost_alerts:
    daily_cost_threshold: 5  # dollars
    monthly_cost_threshold: 25  # dollars
    action: "suspend_non_critical_operations"
  
  security_alerts:
    unusual_access_patterns:
      action: "investigate_and_alert"
      message: "Unusual Firebase access patterns detected"
    
    failed_authentication_spike:
      threshold: 10  # failures per minute
      action: "notify_security_team"
      message: "High number of authentication failures"
```

---

**Document Authority**: DevOps Team, Argus_V Security Solutions  
**Review Schedule**: Monthly cost review, quarterly architecture review  
**Cost Management**: Automated monitoring with manual oversight  
**Emergency Procedures**: Documented for quota exhaustion scenarios