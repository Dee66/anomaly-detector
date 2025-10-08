# Anomaly Detector

Security log anomaly detector with NER-based entity extraction for AWS environments.

## 🎯 Objective: Security & Compliance Automation

This project implements a **comprehensive automated security compliance system** designed to continuously monitor, analyze, and respond to security events across AWS environments. The system addresses critical enterprise security challenges through intelligent automation and real-time threat detection.

### 🎯 **Primary Mission**
Transform reactive security monitoring into **proactive compliance automation** by leveraging AI/ML for real-time security event analysis, entity extraction, and automated compliance remediation.

### 🚨 **Core Problem Statement**
Organizations struggle with:
- **Manual Security Review Burden**: Security teams overwhelmed by volume of CloudTrail/VPC logs requiring manual investigation
- **Delayed Threat Detection**: Traditional rule-based systems miss sophisticated attack patterns and zero-day exploits
- **Compliance Gaps**: Difficulty proving continuous compliance with regulatory frameworks (SOC 2, PCI DSS, GDPR)
- **False Positive Fatigue**: Alert systems generating excessive noise, leading to genuine threats being overlooked
- **Audit Trail Complexity**: Challenges in correlating security events across multiple AWS services for forensic analysis

### 🔧 **Solution Architecture**

This system provides **end-to-end security automation** through four integrated components:

#### 1. **Intelligent Log Ingestion & Processing**
- **Real-time ingestion** of CloudTrail, VPC Flow Logs, and S3 access logs via EventBridge/SQS
- **Secure storage** with KMS-encrypted S3 buckets and configurable retention policies
- **Scalable processing** using AWS Lambda/Fargate with auto-scaling based on log volume
- **Data quality assurance** with schema validation and error handling

#### 2. **AI-Powered Entity Extraction (NER)**
- **Advanced NLP models** fine-tuned for AWS security context (IAM roles, IP addresses, KMS keys, VPC resources)
- **High-confidence extraction** with configurable confidence thresholds and human-in-the-loop validation
- **Contextual understanding** that considers event patterns, user behavior, and resource relationships
- **Continuous learning** from security team feedback to improve accuracy over time

#### 3. **Sophisticated Anomaly Detection**
- **Multi-dimensional scoring** using statistical analysis, behavioral baselines, and rare entity combinations
- **Time-series analysis** to detect unusual access patterns, privilege escalations, and lateral movement
- **Risk stratification** with configurable thresholds for different entity types and event sources
- **False positive reduction** through adaptive learning and security team feedback integration

#### 4. **Automated Compliance & Response**
- **Real-time alerting** with customizable severity levels and escalation workflows
- **Actionable recommendations** for immediate security remediation and preventive measures
- **Audit trail generation** with immutable logging for compliance verification and forensic analysis
- **Integration endpoints** for Security Hub, SIEM systems, and incident response platforms

### 🎯 **Compliance Automation Goals**

#### **Immediate Value (Weeks 1-4)**
- ✅ **Automated Entity Discovery**: Identify all security-relevant resources across AWS accounts
- ✅ **Baseline Risk Profiling**: Establish normal behavioral patterns for users and services
- ✅ **Alert Noise Reduction**: Replace rule-based alerts with intelligent anomaly detection
- ✅ **Audit Trail Automation**: Generate compliance-ready audit logs without manual intervention

#### **Medium-term Impact (Months 2-6)**
- 🎯 **Predictive Threat Detection**: Identify potential security incidents before they escalate
- 🎯 **Automated Remediation**: Auto-execute approved security responses (disable users, rotate keys)
- 🎯 **Compliance Dashboard**: Real-time compliance posture visibility for executive reporting
- 🎯 **Cost Optimization**: Reduce security team manual effort by 70-80%

#### **Long-term Transformation (Months 6-12)**
- 🚀 **Zero-Touch Compliance**: Fully automated compliance monitoring and reporting
- 🚀 **Advanced Threat Hunting**: AI-driven investigation of sophisticated attack campaigns
- 🚀 **Cross-Account Correlation**: Enterprise-wide security event correlation and analysis
- 🚀 **Regulatory Automation**: Automated generation of SOC 2, PCI DSS, and GDPR compliance reports

### 📊 **Success Metrics & KPIs**

| **Metric Category** | **Current State** | **Target (6 months)** | **Impact** |
|---------------------|-------------------|------------------------|------------|
| **Alert Quality** | 80% false positives | <10% false positives | Reduced alert fatigue |
| **Response Time** | 4-8 hours manual review | <15 minutes automated | Faster threat containment |
| **Coverage** | 30% of security events analyzed | 95% automated analysis | Comprehensive monitoring |
| **Compliance** | Manual quarterly audits | Continuous real-time compliance | Regulatory confidence |
| **Cost Efficiency** | 40 FTE hours/week security review | 8 FTE hours/week oversight | 80% effort reduction |

### 🔐 **Security-First Design Principles**

#### **Zero-Trust Architecture**
- **VPC isolation**: All compute resources deployed in private subnets with VPC endpoints only
- **Least-privilege IAM**: Role-based access with permission boundaries and time-limited credentials
- **Multi-layer encryption**: KMS CMKs for data at rest, TLS 1.3 for data in transit, envelope encryption for sensitive data

#### **Compliance by Design**
- **Immutable audit logs**: Write-only log storage with retention policies aligned to regulatory requirements
- **Data sovereignty**: Configurable data residency controls for GDPR/regional compliance
- **Privacy protection**: Automatic PII detection and redaction in log processing pipelines

#### **Operational Security**
- **Secure CI/CD**: Signed commits, vulnerability scanning, infrastructure-as-code validation
- **Incident response**: Automated playbooks for common security scenarios with manual escalation paths
- **Disaster recovery**: Multi-region deployment with automated failover and data replication

### 🎯 **Business Impact & ROI**

#### **Risk Reduction**
- **Faster threat detection**: Reduce dwell time from weeks to minutes
- **Compliance assurance**: Continuous compliance monitoring prevents regulatory fines
- **Insider threat detection**: Behavioral analysis identifies privilege abuse and data exfiltration

#### **Operational Efficiency**
- **Automated investigations**: AI handles routine security event triage
- **Resource optimization**: Focus security team on high-value strategic initiatives
- **Scalable monitoring**: System scales with business growth without proportional staffing increases

#### **Competitive Advantage**
- **Customer trust**: Demonstrate proactive security posture to enterprise customers
- **Regulatory readiness**: Streamlined compliance for new markets and regulations
- **Innovation enablement**: Security automation enables faster, safer product development

This **Security & Compliance Automation** system represents a fundamental shift from reactive security operations to **proactive, intelligent, and automated security governance** that scales with modern cloud infrastructure demands.

## 🏗️ Architecture

### Core Components
- **Entity Extraction**: NLP/NER models for identifying security-relevant entities
- **Anomaly Detection**: Statistical analysis using modified z-score and pattern recognition
- **Real-time Processing**: Event-driven architecture with AWS Lambda/Fargate
- **Secure Storage**: KMS-encrypted S3 buckets with lifecycle policies
- **Alerting**: SNS-based notifications with customizable thresholds

### Security Features
- VPC-only deployment with private subnets
- KMS Customer-Managed Keys (CMKs) for all encryption
- IAM least-privilege access with permission boundaries
- Audit trail persistence to Security Hub and CloudTrail
- Long-term log retention with immutable storage policies

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Poetry for dependency management
- **AWS CLI v2.27.50+** (see [AWS Setup Guide](#aws-setup-requirements))
- AWS CDK CLI
- Node.js (for CDK)
- **Configured AWS profile with restricted IAM permissions** (see [IAM Setup](#iam-profile-setup))

### Local Development Setup

#### Poetry and Virtual Environment Management

This project uses **Poetry** for dependency management and reproducible development environments. Poetry automatically creates and manages a local `.venv` directory for isolated package installation.

**Prerequisites:**
- Python 3.11+ installed system-wide
- Poetry 1.4+ installed (`pip install poetry` or see [Poetry installation guide](https://python-poetry.org/docs/#installation))

#### 1. **Initial Setup (First Time)**

```bash
# Clone the repository
git clone https://github.com/Dee66/anomaly-detector.git
cd anomaly-detector

# Install dependencies and create local .venv
poetry install

# Verify virtual environment creation
ls -la .venv/
# Should show a local virtual environment directory

# Activate the virtual environment
poetry shell
# OR use poetry run for individual commands
```

#### 2. **Daily Development Workflow**

```bash
# Always work within the Poetry environment
cd anomaly-detector

# Option A: Activate shell (recommended for multiple commands)
poetry shell
python --version  # Should show Python 3.11.x
which python      # Should point to .venv/bin/python

# Option B: Run individual commands with poetry run
poetry run python -m pytest
poetry run python src/detector/cli.py --help
poetry run nox -s tests
```

#### 3. **Dependency Management**

```bash
# Add new dependencies
poetry add requests boto3
poetry add --group dev pytest-mock  # Development dependencies

# Update dependencies
poetry update

# Show current dependencies
poetry show
poetry show --tree  # Show dependency tree

# Export requirements (for CI/containers)
poetry export -f requirements.txt --output requirements.txt
poetry export --dev -f requirements.txt --output requirements-dev.txt
```

#### 4. **Virtual Environment Details**

```bash
# Show virtual environment info
poetry env info
# Output includes:
# - Virtualenv path: /path/to/anomaly-detector/.venv
# - Python version: 3.11.x
# - Python executable: /path/to/anomaly-detector/.venv/bin/python

# List available environments
poetry env list

# Remove current environment (if needed)
poetry env remove python3.11

# Recreate environment
poetry install
```

#### 5. **Cross-Platform Compatibility**

**Linux/macOS:**
```bash
# Activate environment
poetry shell
source .venv/bin/activate  # Alternative activation

# Python executable location
.venv/bin/python
```

**Windows:**
```cmd
# Activate environment
poetry shell
.venv\Scripts\activate.bat  # Alternative activation

# Python executable location
.venv\Scripts\python.exe
```

#### 6. **IDE Integration**

**VS Code:**
```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "./.venv/bin/python",
  "python.terminal.activateEnvironment": true,
  "python.testing.pytestEnabled": true,
  "python.testing.pytestPath": "./.venv/bin/pytest"
}
```

**PyCharm:**
1. File → Settings → Project → Python Interpreter
2. Add → Existing Environment
3. Select `.venv/bin/python` (or `.venv\Scripts\python.exe` on Windows)

#### 7. **Reproducible Environment Setup**

**For Team Members:**
```bash
# Ensure exact same dependencies
poetry install --sync  # Removes extra packages not in lock file

# Check for dependency conflicts
poetry check

# Verify environment matches pyproject.toml
poetry run python -c "
import sys
print(f'Python: {sys.version}')
print(f'Path: {sys.executable}')
"
```

**For CI/CD:**
```bash
# In CI environments, use:
poetry config virtualenvs.create true
poetry config virtualenvs.in-project true
poetry install --no-dev  # Production dependencies only
poetry run pytest       # Run tests in isolated environment
```

#### 8. **Environment Variables and Configuration**

```bash
# Set up environment in activated shell
poetry shell

# Configure development environment
export ENVIRONMENT=dev
export AWS_PROFILE=anomaly-detector-dev
export PYTHONPATH="${PWD}/src:${PYTHONPATH}"

# For deployment operations (use with caution)
export ALLOW_AWS_DEPLOY=1

# Verify configuration
poetry run python -c "
import os
from src.detector.config import load_config
print(f'Environment: {os.getenv(\"ENVIRONMENT\", \"not set\")}')
print(f'AWS Profile: {os.getenv(\"AWS_PROFILE\", \"not set\")}')
config = load_config('dev')
print(f'Config loaded: {config.environment}')
"
```

#### 9. **Common Commands Reference**

```bash
# Development workflow
poetry shell                    # Activate environment
poetry run pytest             # Run tests
poetry run nox -s tests       # Run comprehensive tests
poetry run python -m detector.cli --help  # Run CLI

# Dependency management
poetry add package-name        # Add dependency
poetry add --group dev package # Add dev dependency
poetry remove package-name     # Remove dependency
poetry update                  # Update all dependencies

# Environment management
poetry env info               # Show environment details
poetry install --sync         # Sync with lock file
poetry check                  # Verify dependencies
poetry show --outdated        # Check for updates
```

#### 10. **Troubleshooting**

**Common Issues:**

```bash
# Issue: Poetry not found
pip install --user poetry
# Or follow: https://python-poetry.org/docs/#installation

# Issue: Wrong Python version
poetry env use python3.11
poetry install

# Issue: Corrupted environment
poetry env remove python3.11
poetry install

# Issue: Permission errors
# On Linux/macOS:
sudo chown -R $USER:$USER .venv/
# On Windows: Run as administrator

# Issue: Virtual environment not in project
poetry config virtualenvs.in-project true
poetry install
```

**Environment Verification:**
```bash
# Verify everything is working
poetry shell
python --version              # Should be 3.11.x
pip list                      # Should show project dependencies
python -c "import detector"   # Should import without errors
pytest --version             # Should work
nox --version                # Should work
```

### 2. **Configure environment:**
```bash
export ENVIRONMENT=dev
export AWS_PROFILE=your-dev-profile
# For actual deployments (safety flag):
export ALLOW_AWS_DEPLOY=1
```

### 3. **Run tests:**
```bash
poetry run pytest
# OR use nox for comprehensive testing
nox
```

### Configuration Management

Configuration is managed through environment-specific YAML files in `config/`:

- `config/dev.yml` - Development environment
- `config/prod.yml` - Production environment

The configuration loader (`src/detector/config.py`) provides:
- Environment variable overrides
- Type-safe configuration objects
- Validation and defaults

### Infrastructure Deployment

**⚠️ Safety First**: All deployment scripts default to dry-run mode.

1. **Synthesize CDK templates:**
```bash
python scripts/deploy_detector.py --synth-only
```

2. **Deploy infrastructure (dry-run):**
```bash
python scripts/deploy_detector.py --environment dev
```

3. **Deploy infrastructure (actual):**
```bash
export ALLOW_AWS_DEPLOY=1
python scripts/deploy_detector.py --environment dev --apply
```

### Model Packaging

Package model artifacts for deployment:

```bash
# Create model package (dry-run)
python scripts/package_model_artifacts.py ./path/to/model

# Upload to S3 (actual)
export ALLOW_AWS_DEPLOY=1
python scripts/package_model_artifacts.py ./path/to/model --apply
```

## 🧪 Development Workflow

### Available Nox Sessions

```bash
nox -l                    # List available sessions
nox -s tests              # Run tests with coverage
nox -s lint               # Run linting
nox -s format             # Format code
nox -s typecheck          # Type checking
nox -s security           # Security analysis
nox -s e2e_security       # End-to-end security validation
nox -s package            # Build package
nox -s clean              # Clean build artifacts
```

### Project Structure

```
anomaly-detector/
├── config/                 # Environment configurations
│   ├── dev.yml
│   ├── prod.yml
│   └── README.md
├── src/
│   └── detector/           # Core detector module
│       └── config.py       # Configuration management
├── infra/                  # CDK infrastructure
│   ├── app.py             # CDK app entry point
│   └── security_detector_stack.py
├── scripts/                # Deployment and packaging
│   ├── deploy_detector.py
│   └── package_model_artifacts.py
├── anomalydetector/        # Original core module
│   ├── core.py            # Anomaly detection algorithms
│   └── cli.py             # Command line interface
├── tests/                  # Test suite
├── data/                   # Training and test data
├── noxfile.py             # Development automation
└── pyproject.toml         # Project configuration
```

## 🔒 Security & Compliance

### AWS Setup Requirements

#### AWS CLI v2.27.50+ Installation and Configuration

**Required Version**: AWS CLI v2.27.50 or later is mandatory for:
- Enhanced security features and bug fixes
- Compatible API behavior with our CDK templates
- Proper support for KMS customer-managed keys
- SSO and credential management improvements

**Installation:**
```bash
# Verify current version
aws --version

# If upgrading is needed:
# macOS (via Homebrew)
brew update && brew upgrade awscli

# Linux (via pip)
pip install --upgrade awscli

# Windows (via MSI installer)
# Download from: https://aws.amazon.com/cli/
```

#### IAM Profile Setup

**⚠️ Security Requirement**: Use a dedicated, restricted IAM profile for this project.

**Required IAM Permissions:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::your-security-logs-bucket/*",
                "arn:aws:s3:::your-model-artifacts-bucket/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey"
            ],
            "Resource": [
                "arn:aws:kms:*:*:key/your-anomaly-detector-key-id"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:DescribeSecret"
            ],
            "Resource": [
                "arn:aws:secretsmanager:*:*:secret:anomaly-detector/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams"
            ],
            "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/anomaly-detector-*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:PassRole"
            ],
            "Resource": "arn:aws:iam::*:role/anomaly-detector-*",
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": [
                        "lambda.amazonaws.com",
                        "ecs-tasks.amazonaws.com"
                    ]
                }
            }
        }
    ]
}
```

**Profile Configuration:**
```bash
# Configure dedicated profile
aws configure --profile anomaly-detector-dev
# Enter:
# - Access Key ID: [Your restricted access key]
# - Secret Access Key: [Your secret key]
# - Default region: us-east-1 (or your preferred region)
# - Default output format: json

# Set as default for this project
export AWS_PROFILE=anomaly-detector-dev

# Verify configuration
aws sts get-caller-identity --profile anomaly-detector-dev
```

### AWS Secrets Manager Integration

**📋 Mandatory Requirement**: All model and endpoint credentials must be stored in AWS Secrets Manager.

#### Credential Storage Requirements

**Model Endpoint Credentials:**
```bash
# Store SageMaker endpoint credentials
aws secretsmanager create-secret \
  --name "anomaly-detector/model-endpoints/primary" \
  --description "Primary model endpoint configuration" \
  --secret-string '{
    "endpoint_name": "anomaly-detector-model-prod",
    "api_key": "your-secure-api-key",
    "model_version": "v1.2.3",
    "inference_timeout": 30
  }' \
  --profile anomaly-detector-dev

# Store Hugging Face API credentials (if using external models)
aws secretsmanager create-secret \
  --name "anomaly-detector/external-apis/huggingface" \
  --description "Hugging Face API credentials for model access" \
  --secret-string '{
    "api_token": "hf_your_secure_token_here",
    "model_repository": "your-org/security-ner-model"
  }' \
  --profile anomaly-detector-dev

# Store database credentials (if using external storage)
aws secretsmanager create-secret \
  --name "anomaly-detector/database/primary" \
  --description "Database connection for audit storage" \
  --secret-string '{
    "host": "your-rds-endpoint.region.rds.amazonaws.com",
    "port": 5432,
    "database": "anomaly_detector",
    "username": "detector_user",
    "password": "your-secure-password"
  }' \
  --profile anomaly-detector-dev
```

#### Code Integration

**Retrieving Secrets in Application:**
```python
import boto3
from botocore.exceptions import ClientError
import json

def get_secret(secret_name: str, region_name: str = "us-east-1") -> dict:
    """Retrieve secret from AWS Secrets Manager.
    
    Args:
        secret_name: Name of the secret in Secrets Manager
        region_name: AWS region where secret is stored
        
    Returns:
        Dictionary containing secret values
        
    Raises:
        ClientError: If secret cannot be retrieved
    """
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e
    
    secret = get_secret_value_response['SecretString']
    return json.loads(secret)

# Usage in detector code
model_config = get_secret("anomaly-detector/model-endpoints/primary")
endpoint_name = model_config["endpoint_name"]
api_key = model_config["api_key"]
```

**Environment Variables for Secret Names:**
```bash
# Set in your environment or config files
export MODEL_ENDPOINT_SECRET="anomaly-detector/model-endpoints/primary"
export HUGGINGFACE_SECRET="anomaly-detector/external-apis/huggingface"
export DATABASE_SECRET="anomaly-detector/database/primary"
```

#### Secret Rotation and Management

**Automatic Rotation Setup:**
```bash
# Enable automatic rotation for database credentials
aws secretsmanager rotate-secret \
  --secret-id "anomaly-detector/database/primary" \
  --rotation-lambda-arn "arn:aws:lambda:region:account:function:rotate-db-secret" \
  --rotation-rules AutomaticallyAfterDays=30 \
  --profile anomaly-detector-dev
```

**Tagging for Compliance:**
```bash
# Tag secrets for cost tracking and compliance
aws secretsmanager tag-resource \
  --secret-id "anomaly-detector/model-endpoints/primary" \
  --tags '[
    {"Key": "Project", "Value": "anomaly-detector"},
    {"Key": "Environment", "Value": "production"},
    {"Key": "CostCenter", "Value": "security-engineering"},
    {"Key": "DataClassification", "Value": "confidential"}
  ]' \
  --profile anomaly-detector-dev
```

### Mandatory Security Controls
- **VPC-Only Access**: All compute resources deployed in private subnets
- **KMS Encryption**: Customer-managed keys for all data at rest
- **IAM Boundaries**: Least-privilege roles with permission boundaries
- **Audit Trail**: All actions logged to Security Hub and CloudTrail
- **Data Retention**: Configurable retention with immutable policies

### Feature Flags
Control optional components via configuration:
- `enable_training`: Model training infrastructure
- `enable_sagemaker`: SageMaker inference endpoints  
- `enable_vpc_endpoints`: VPC endpoints for enhanced security

### Cost Controls
- Budget guardrails in deployment scripts
- S3 lifecycle policies for cost optimization
- Conditional resource deployment
- Resource tagging for cost allocation

## 📊 Monitoring & Observability

- CloudWatch custom metrics for anomaly rates
- SNS alerting with configurable thresholds
- Structured logging for audit trails
- Dashboard templates for visualization

## 🛠️ Next Steps

See `checklist.md` for the complete implementation roadmap. Current progress: **11% complete (8/75 items)**.

Priority items in progress:
- [ ] NER model integration
- [ ] Security log ingestion pipeline
- [ ] Training data generation
- [ ] CI/CD pipeline setup

## 📖 Documentation

- [**AWS Setup Guide**](docs/AWS_SETUP.md) - Detailed AWS CLI and Secrets Manager setup
- [Configuration Guide](config/README.md)
- [Deployment Checklist](checklist.md)
- [ADR: Architecture Decisions](docs/adr/) *(coming soon)*

## 🤝 Contributing

1. Follow the development workflow using nox sessions
2. Ensure all tests pass and coverage meets thresholds
3. Use dry-run mode for testing deployment scripts
4. Follow security-first principles for all changes
