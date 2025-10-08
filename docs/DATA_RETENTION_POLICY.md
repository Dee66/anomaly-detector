# Data Retention and Immutability Policies

## 📋 Overview

This document outlines the data retention and immutability policies for security logs processed by the Anomaly Detector system. These policies ensure compliance with regulatory requirements (SOC 2, PCI DSS, GDPR) while optimizing storage costs and maintaining audit trail integrity.

## 🔒 Security Log Categories

### 1. **Raw Security Logs** (Tier 1 - Critical)
- **Source**: CloudTrail, VPC Flow Logs, S3 Access Logs
- **Retention**: 7 years (regulatory compliance)
- **Immutability**: Write-once, read-many (WORM) with Object Lock
- **Encryption**: KMS Customer-Managed Keys (CMKs)

### 2. **Processed Compliance Outputs** (Tier 2 - High)
- **Source**: Entity extraction results, anomaly scores, recommendations
- **Retention**: 5 years (audit trail requirements)
- **Immutability**: Append-only with versioning
- **Encryption**: KMS CMKs with envelope encryption

### 3. **Model Training Data** (Tier 3 - Medium)
- **Source**: Synthetic logs, labeled datasets, feature stores
- **Retention**: 3 years (model reproducibility)
- **Immutability**: Versioned with git-like semantics
- **Encryption**: KMS CMKs

### 4. **Operational Logs** (Tier 4 - Standard)
- **Source**: Application logs, CloudWatch metrics, debug traces
- **Retention**: 1 year (operational troubleshooting)
- **Immutability**: Standard versioning
- **Encryption**: SSE-S3 (acceptable for non-sensitive data)

## 📊 S3 Lifecycle Policies

### Raw Security Logs Lifecycle
```yaml
# 7-year retention with cost optimization
Immediate (0-30 days):
  - Storage Class: S3 Standard
  - Access Pattern: Frequent (real-time processing)
  - Cost: $23/TB/month

Hot Archive (30 days - 1 year):
  - Storage Class: S3 Infrequent Access (IA)
  - Access Pattern: Occasional (investigations)
  - Cost: $12.5/TB/month
  - Retrieval: Immediate

Cold Archive (1-3 years):
  - Storage Class: S3 Glacier
  - Access Pattern: Rare (compliance audits)
  - Cost: $4/TB/month
  - Retrieval: 1-5 minutes (Expedited)

Deep Archive (3-7 years):
  - Storage Class: S3 Glacier Deep Archive
  - Access Pattern: Regulatory only
  - Cost: $1/TB/month
  - Retrieval: 12 hours (Standard)

Expiration: 7 years + 30 days (grace period)
```

### Processed Compliance Outputs Lifecycle
```yaml
# 5-year retention optimized for audit access
Active (0-90 days):
  - Storage Class: S3 Standard
  - Access Pattern: Regular (reporting, dashboards)

Archive (90 days - 2 years):
  - Storage Class: S3 IA
  - Access Pattern: Audit investigations

Deep Storage (2-5 years):
  - Storage Class: S3 Glacier
  - Access Pattern: Regulatory compliance

Expiration: 5 years
```

## 🛡️ Immutability Controls

### Object Lock Configuration
```yaml
Legal Hold: Enabled for all Tier 1 & Tier 2 data
Retention Mode: Governance (allows privileged deletion)
Default Retention: 
  - Raw Logs: 7 years
  - Compliance Outputs: 5 years
```

### Access Controls
- **Write Permissions**: Restricted to authenticated service roles only
- **Delete Permissions**: Require MFA + dual approval for break-glass scenarios
- **Modify Permissions**: Prohibited (append-only for new data)

### Audit Trail
- **All access logged**: CloudTrail with data events enabled
- **Integrity verification**: SHA-256 checksums for all objects
- **Monitoring**: CloudWatch alarms for unauthorized access attempts

## 📐 Parameterizable Configuration

All retention policies are configurable via the central config loader:

```yaml
# config/prod.yml
data_retention:
  raw_security_logs:
    retention_years: 7
    immutable: true
    lifecycle_transitions:
      - days: 30
        storage_class: "STANDARD_IA"
      - days: 365
        storage_class: "GLACIER"
      - days: 1095  # 3 years
        storage_class: "DEEP_ARCHIVE"
    
  compliance_outputs:
    retention_years: 5
    immutable: true
    lifecycle_transitions:
      - days: 90
        storage_class: "STANDARD_IA"
      - days: 730  # 2 years
        storage_class: "GLACIER"
  
  model_artifacts:
    retention_years: 3
    immutable: false  # Allow model updates
    
bucket_configuration:
  raw_logs_bucket: "${environment}-security-logs-raw"
  processed_bucket: "${environment}-security-logs-processed"
  model_bucket: "${environment}-ml-model-artifacts"
  kms_key_arn: "${kms_key_arn}"
  enable_object_lock: true
  mfa_delete: true
```

## 🔍 Compliance Mapping

### SOC 2 Type II Requirements
- **CC6.1**: Logical access controls → IAM policies with least privilege
- **CC6.7**: Data transmission → TLS 1.3 + KMS encryption
- **CC7.2**: Data retention → 7-year lifecycle policies
- **CC8.1**: Change management → Immutable logs + versioning

### PCI DSS Requirements
- **Req 3**: Cardholder data protection → KMS CMKs + Object Lock
- **Req 10**: Logging and monitoring → CloudTrail data events
- **Req 10.5.3**: Log retention → 1 year active + archival

### GDPR Requirements
- **Art 5(1)(e)**: Data minimization → Automated expiration policies
- **Art 17**: Right to erasure → Legal hold exceptions documented
- **Art 32**: Security measures → Encryption at rest + in transit

## 💰 Cost Optimization

### Estimated Monthly Costs (per TB)
```
Raw Security Logs (7-year retention):
Year 1: $23.00 (Standard) → $12.50 (IA after 30 days)
Year 2-3: $4.00 (Glacier)
Year 4-7: $1.00 (Deep Archive)

Average cost per TB over 7 years: ~$3.50/month

Compliance Outputs (5-year retention):
Average cost per TB over 5 years: ~$6.20/month
```

### Monitoring & Alerts
- **Budget alerts**: 80% and 95% of monthly storage budget
- **Unexpected access**: Alerts for Deep Archive retrievals
- **Lifecycle failures**: CloudWatch alarms for transition errors

## 🚨 Break-Glass Procedures

### Emergency Data Access
1. **Incident Response**: Expedited retrieval for security incidents
2. **Legal Hold**: Suspend expiration policies during litigation
3. **Compliance Audit**: Batch retrieval for regulatory reviews

### Approval Workflow
- **Tier 1/2 Data**: CISO + Legal approval required
- **MFA Required**: All break-glass operations
- **Audit Log**: Detailed justification and access logs

## 📋 Implementation Checklist

- [ ] Configure S3 buckets with Object Lock enabled
- [ ] Deploy lifecycle policies via CDK/CloudFormation
- [ ] Set up CloudWatch monitoring and alarms
- [ ] Create IAM policies with appropriate restrictions
- [ ] Implement automated compliance reporting
- [ ] Test break-glass procedures
- [ ] Document runbook for operations team

## 🔄 Review Schedule

- **Quarterly**: Review storage costs and usage patterns
- **Annually**: Update retention periods based on regulatory changes
- **As needed**: Adjust policies for new data sources or requirements

---

*This document is version-controlled and requires approval from Security, Legal, and Engineering teams for any modifications.*