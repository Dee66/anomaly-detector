# AWS Setup Guide for Anomaly Detector

## Overview

This guide provides detailed setup instructions for AWS CLI v2.27.50+ and the mandatory AWS Secrets Manager configuration required for the Anomaly Detector project.

## 🚨 Security Requirements Summary

- **AWS CLI v2.27.50+** with dedicated IAM profile
- **All credentials stored in AWS Secrets Manager** (no local storage)
- **Restricted IAM permissions** following least-privilege principle
- **KMS encryption** for all sensitive data
- **Proper resource tagging** for compliance and cost tracking

## 📋 Step-by-Step Setup

### Step 1: AWS CLI Installation and Verification

#### 1.1 Check Current Version
```bash
aws --version
# Required output: aws-cli/2.27.50 or higher
```

#### 1.2 Upgrade if Necessary

**macOS (Homebrew):**
```bash
brew update
brew upgrade awscli
```

**macOS (Official Installer):**
```bash
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /
```

**Linux x86_64:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install --update
```

**Windows:**
Download and run the MSI installer from:
https://awscli.amazonaws.com/AWSCLIV2.msi

#### 1.3 Verify Installation
```bash
aws --version
which aws
# Should show: aws-cli/2.27.50 or higher
```

### Step 2: IAM User and Profile Setup

#### 2.1 Create Dedicated IAM User

**Via AWS Console:**
1. Navigate to IAM → Users → Create User
2. User name: `anomaly-detector-service`
3. Select "Programmatic access"
4. Attach custom policy (see policy below)
5. Add tags:
   - Project: anomaly-detector
   - Purpose: service-account
   - Environment: dev|staging|prod

#### 2.2 IAM Policy for Anomaly Detector

**Policy Name:** `AnomalyDetectorServicePolicy`

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3LogAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket",
                "s3:DeleteObject",
                "s3:GetBucketLocation",
                "s3:GetBucketVersioning"
            ],
            "Resource": [
                "arn:aws:s3:::anomaly-detector-logs-*",
                "arn:aws:s3:::anomaly-detector-logs-*/*",
                "arn:aws:s3:::anomaly-detector-models-*",
                "arn:aws:s3:::anomaly-detector-models-*/*"
            ]
        },
        {
            "Sid": "KMSAccess",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyWithoutPlaintext",
                "kms:DescribeKey",
                "kms:CreateGrant"
            ],
            "Resource": [
                "arn:aws:kms:*:*:key/*"
            ],
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": [
                        "s3.*.amazonaws.com",
                        "secretsmanager.*.amazonaws.com",
                        "lambda.*.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Sid": "SecretsManagerAccess",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecrets",
                "secretsmanager:CreateSecret",
                "secretsmanager:UpdateSecret",
                "secretsmanager:TagResource"
            ],
            "Resource": [
                "arn:aws:secretsmanager:*:*:secret:anomaly-detector/*"
            ]
        },
        {
            "Sid": "CloudWatchLogs",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": [
                "arn:aws:logs:*:*:log-group:/aws/lambda/anomaly-detector-*",
                "arn:aws:logs:*:*:log-group:/ecs/anomaly-detector-*"
            ]
        },
        {
            "Sid": "IAMPassRole",
            "Effect": "Allow",
            "Action": [
                "iam:PassRole",
                "iam:GetRole"
            ],
            "Resource": "arn:aws:iam::*:role/anomaly-detector-*",
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": [
                        "lambda.amazonaws.com",
                        "ecs-tasks.amazonaws.com",
                        "sagemaker.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Sid": "SageMakerInference",
            "Effect": "Allow",
            "Action": [
                "sagemaker:InvokeEndpoint",
                "sagemaker:DescribeEndpoint",
                "sagemaker:DescribeEndpointConfig"
            ],
            "Resource": [
                "arn:aws:sagemaker:*:*:endpoint/anomaly-detector-*"
            ]
        },
        {
            "Sid": "VPCAccess",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkInterfaces"
            ],
            "Resource": "*"
        }
    ]
}
```

#### 2.3 Configure AWS Profile

```bash
# Create dedicated profile
aws configure --profile anomaly-detector-dev
# Enter the access key and secret from step 2.1
# Default region: us-east-1 (or your preferred region)
# Default output format: json

# Test the profile
aws sts get-caller-identity --profile anomaly-detector-dev

# Set as default for this project
export AWS_PROFILE=anomaly-detector-dev
echo 'export AWS_PROFILE=anomaly-detector-dev' >> ~/.bashrc
```

### Step 3: AWS Secrets Manager Setup

#### 3.1 Create Required Secrets

**Model Endpoint Configuration:**
```bash
aws secretsmanager create-secret \
  --name "anomaly-detector/model-endpoints/primary" \
  --description "Primary NER model endpoint configuration" \
  --secret-string '{
    "endpoint_name": "anomaly-detector-ner-model",
    "endpoint_url": "https://your-sagemaker-endpoint-url",
    "api_key": "your-secure-api-key",
    "model_version": "v1.0.0",
    "inference_timeout": 30,
    "max_retries": 3,
    "batch_size": 32
  }' \
  --tags '[
    {"Key": "Project", "Value": "anomaly-detector"},
    {"Key": "Environment", "Value": "development"},
    {"Key": "SecretType", "Value": "model-config"}
  ]' \
  --profile anomaly-detector-dev
```

**External API Credentials (Hugging Face):**
```bash
aws secretsmanager create-secret \
  --name "anomaly-detector/external-apis/huggingface" \
  --description "Hugging Face API credentials for model access" \
  --secret-string '{
    "api_token": "hf_your_token_here",
    "model_repository": "your-org/security-ner-model",
    "cache_dir": "/tmp/hf_cache",
    "max_model_size": "2GB"
  }' \
  --tags '[
    {"Key": "Project", "Value": "anomaly-detector"},
    {"Key": "Environment", "Value": "development"},
    {"Key": "SecretType", "Value": "external-api"}
  ]' \
  --profile anomaly-detector-dev
```

**Database Connection (Optional):**
```bash
aws secretsmanager create-secret \
  --name "anomaly-detector/database/audit-store" \
  --description "Database connection for audit trail storage" \
  --secret-string '{
    "host": "your-rds-endpoint.region.rds.amazonaws.com",
    "port": 5432,
    "database": "anomaly_detector",
    "username": "detector_app",
    "password": "your-secure-password",
    "ssl_mode": "require",
    "connection_timeout": 30
  }' \
  --tags '[
    {"Key": "Project", "Value": "anomaly-detector"},
    {"Key": "Environment", "Value": "development"},
    {"Key": "SecretType", "Value": "database"}
  ]' \
  --profile anomaly-detector-dev
```

**Notification Configuration:**
```bash
aws secretsmanager create-secret \
  --name "anomaly-detector/notifications/alerts" \
  --description "Configuration for security alert notifications" \
  --secret-string '{
    "sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:anomaly-alerts",
    "email_endpoints": ["security-team@company.com"],
    "slack_webhook": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
    "pagerduty_key": "your-pagerduty-integration-key"
  }' \
  --tags '[
    {"Key": "Project", "Value": "anomaly-detector"},
    {"Key": "Environment", "Value": "development"},
    {"Key": "SecretType", "Value": "notifications"}
  ]' \
  --profile anomaly-detector-dev
```

#### 3.2 Enable Secret Rotation (Production)

**For Database Secrets:**
```bash
aws secretsmanager rotate-secret \
  --secret-id "anomaly-detector/database/audit-store" \
  --rotation-lambda-arn "arn:aws:lambda:us-east-1:123456789012:function:rotate-database-secret" \
  --rotation-rules AutomaticallyAfterDays=30 \
  --profile anomaly-detector-dev
```

#### 3.3 Verify Secret Access

**Test secret retrieval:**
```bash
# Test access to model config secret
aws secretsmanager get-secret-value \
  --secret-id "anomaly-detector/model-endpoints/primary" \
  --query 'SecretString' \
  --output text \
  --profile anomaly-detector-dev | jq .

# Test access to API credentials
aws secretsmanager get-secret-value \
  --secret-id "anomaly-detector/external-apis/huggingface" \
  --query 'SecretString' \
  --output text \
  --profile anomaly-detector-dev | jq .
```

### Step 4: Environment Configuration

#### 4.1 Update Project Configuration

**Update config/dev.yml:**
```yaml
aws:
  profile: "anomaly-detector-dev"
  region: "us-east-1"
  
secrets:
  model_endpoint: "anomaly-detector/model-endpoints/primary"
  external_apis: "anomaly-detector/external-apis/huggingface"
  database: "anomaly-detector/database/audit-store"
  notifications: "anomaly-detector/notifications/alerts"
  
security:
  kms_key_id: "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
  enable_encryption: true
  vpc_only_access: true
```

#### 4.2 Environment Variables

**Required environment variables:**
```bash
# Add to your ~/.bashrc or project .env file
export AWS_PROFILE=anomaly-detector-dev
export AWS_DEFAULT_REGION=us-east-1
export ENVIRONMENT=development

# For production deployments only
export ALLOW_AWS_DEPLOY=1

# Secret names (override defaults if needed)
export MODEL_ENDPOINT_SECRET="anomaly-detector/model-endpoints/primary"
export HUGGINGFACE_SECRET="anomaly-detector/external-apis/huggingface"
export DATABASE_SECRET="anomaly-detector/database/audit-store"
export NOTIFICATIONS_SECRET="anomaly-detector/notifications/alerts"
```

### Step 5: Validation and Testing

#### 5.1 Test AWS CLI Access
```bash
# Verify identity
aws sts get-caller-identity --profile anomaly-detector-dev

# Test S3 access (replace with your bucket)
aws s3 ls s3://anomaly-detector-logs-dev --profile anomaly-detector-dev

# Test Secrets Manager access
aws secretsmanager list-secrets \
  --filters Key=name,Values=anomaly-detector/ \
  --profile anomaly-detector-dev
```

#### 5.2 Test Application Configuration
```bash
cd /path/to/anomaly-detector
poetry shell

# Test configuration loading
python -c "
from src.detector.config import load_config
config = load_config('dev')
print(f'AWS Profile: {config.aws.profile}')
print(f'Model Secret: {config.secrets.model_endpoint}')
"
```

## 🔒 Security Best Practices

### 1. Credential Rotation
- Set up automatic rotation for database credentials (30 days)
- Manually rotate API keys quarterly
- Monitor secret access patterns in CloudTrail

### 2. Access Monitoring
- Enable CloudTrail logging for all secret access
- Set up CloudWatch alarms for unusual access patterns
- Review IAM access patterns monthly

### 3. Backup and Recovery
- Enable cross-region secret replication for critical secrets
- Document secret recovery procedures
- Test disaster recovery procedures quarterly

### 4. Compliance
- Tag all secrets with appropriate classification levels
- Document all secret usage in security reviews
- Ensure secrets meet company data retention policies

## 🚨 Troubleshooting

### Common Issues

**AWS CLI Version Issues:**
```bash
# If aws --version shows older version after upgrade
which aws
# May show multiple installations, ensure the new one is in PATH

# Force reinstall if needed
pip uninstall awscli
# Then reinstall using method above
```

**Permission Denied Errors:**
```bash
# Check current profile
aws configure list --profile anomaly-detector-dev

# Verify IAM permissions
aws iam get-user --profile anomaly-detector-dev
aws iam list-attached-user-policies --user-name anomaly-detector-service --profile anomaly-detector-dev
```

**Secrets Manager Access Issues:**
```bash
# Check secret exists
aws secretsmanager describe-secret \
  --secret-id "anomaly-detector/model-endpoints/primary" \
  --profile anomaly-detector-dev

# Check KMS permissions
aws kms describe-key \
  --key-id "your-kms-key-id" \
  --profile anomaly-detector-dev
```

## 📞 Support

For setup issues:
1. Check CloudTrail logs for detailed error messages
2. Verify all IAM permissions are correctly applied
3. Ensure KMS key policies allow access from your IAM user
4. Contact the security team for policy reviews

**Next Steps:** After completing this setup, proceed to the main [README.md](../README.md) for local development setup.