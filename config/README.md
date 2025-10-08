# Configuration Management

This directory contains environment-specific configuration files for the anomaly detector.

## Files

- `dev.yml` - Development environment configuration
- `prod.yml` - Production environment configuration

## Configuration Structure

Each YAML file contains the following sections:

### Core Settings
- `environment` - Environment name (dev/prod)
- `app_name` - Application identifier

### AWS Settings
- `aws.region` - AWS region for deployment
- `aws.profile` - AWS CLI profile to use

### S3 Buckets
- `s3.model_bucket_name` - Bucket for model artifacts
- `s3.data_bucket_name` - Bucket for training/test data
- `s3.log_bucket_name` - Bucket for security logs

### Security
- `kms.key_alias` - KMS key for encryption
- `vpc.*` - VPC configuration for secure deployment

### Model Settings
- `model.ner_model_name` - HuggingFace model for NER
- `model.anomaly_threshold` - Z-score threshold for anomaly detection
- `model.batch_size` - Processing batch size

### Feature Flags
- `features.enable_training` - Enable model training components
- `features.enable_sagemaker` - Enable SageMaker endpoints
- `features.enable_vpc_endpoints` - Enable VPC endpoints for security

### Alerts
- `alerts.sns_topic_name` - SNS topic for notifications
- `alerts.email_endpoints` - Email addresses for alerts

## Usage

The configuration is loaded by `src/detector/config.py` which:
1. Checks for environment variables first
2. Falls back to the appropriate YAML file based on `ENVIRONMENT` env var
3. Defaults to `dev.yml` if no environment is specified

## Required Environment Variables

- `ENVIRONMENT` - Environment name (dev/prod)
- `AWS_PROFILE` - AWS CLI profile (optional, overrides config)
- `ALLOW_AWS_DEPLOY` - Set to "1" to enable actual AWS deployments (safety flag)