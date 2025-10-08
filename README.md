# Anomaly Detector

Security log anomaly detector with NER-based entity extraction for AWS environments.

## 🎯 Objective

This project implements an automated security compliance system that:
- Ingests security logs from AWS services (CloudTrail, VPC Flow Logs)
- Extracts entities (IAM roles, IP addresses, KMS keys) using NER models
- Detects anomalies using statistical analysis and rare entity combinations
- Provides actionable recommendations for security compliance
- Maintains audit trails for compliance verification

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
- AWS CLI v2.27.50+
- AWS CDK CLI
- Node.js (for CDK)

### Local Development Setup

1. **Clone and setup environment:**
```bash
cd anomaly-detector
poetry install
poetry shell
```

2. **Configure environment:**
```bash
export ENVIRONMENT=dev
export AWS_PROFILE=your-dev-profile
# For actual deployments (safety flag):
export ALLOW_AWS_DEPLOY=1
```

3. **Run tests:**
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

- [Configuration Guide](config/README.md)
- [Deployment Checklist](checklist.md)
- [ADR: Architecture Decisions](docs/adr/) *(coming soon)*

## 🤝 Contributing

1. Follow the development workflow using nox sessions
2. Ensure all tests pass and coverage meets thresholds
3. Use dry-run mode for testing deployment scripts
4. Follow security-first principles for all changes
