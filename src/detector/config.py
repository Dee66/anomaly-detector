"""Configuration management for the anomaly detector.

This module provides a centralized configuration loader that:
1. Checks environment variables first
2. Falls back to YAML configuration files
3. Provides type-safe configuration objects
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field


class AWSConfig(BaseModel):
    """AWS-related configuration."""
    region: str = "us-west-2"
    profile: Optional[str] = None


class S3Config(BaseModel):
    """S3 bucket configuration."""
    model_bucket_name: str
    data_bucket_name: str
    log_bucket_name: str


class KMSConfig(BaseModel):
    """KMS encryption configuration."""
    key_alias: str


class VPCConfig(BaseModel):
    """VPC networking configuration."""
    vpc_id: Optional[str] = None
    private_subnets: List[str] = Field(default_factory=list)


class ModelConfig(BaseModel):
    """Model training and inference configuration."""
    ner_model_name: str = "distilbert-base-uncased"
    anomaly_threshold: float = 3.0
    batch_size: int = 32


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    structured: bool = True


class FeatureFlags(BaseModel):
    """Feature toggles for optional components."""
    enable_training: bool = False
    enable_sagemaker: bool = False
    enable_vpc_endpoints: bool = False


class AlertsConfig(BaseModel):
    """Alerting and notification configuration."""
    sns_topic_name: str
    email_endpoints: List[str] = Field(default_factory=list)


class Config(BaseModel):
    """Main configuration object."""
    environment: str = "dev"
    app_name: str = "anomaly-detector"
    aws: AWSConfig
    s3: S3Config
    kms: KMSConfig
    vpc: VPCConfig
    model: ModelConfig
    logging: LoggingConfig
    features: FeatureFlags
    alerts: AlertsConfig


def load_config(environment: Optional[str] = None) -> Config:
    """Load configuration from environment variables and YAML files.

    Args:
        environment: Environment name (dev/prod). If None, uses ENVIRONMENT env var.

    Returns:
        Loaded configuration object.

    Raises:
        FileNotFoundError: If configuration file doesn't exist.
        ValueError: If configuration is invalid.
    """
    # Determine environment
    env = environment or os.getenv("ENVIRONMENT", "dev")

    # Load base configuration from YAML
    config_dir = Path(__file__).parent.parent.parent / "config"
    config_file = config_dir / f"{env}.yml"

    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_file}")

    with open(config_file, 'r') as f:
        config_data = yaml.safe_load(f)

    # Override with environment variables
    config_data = _apply_env_overrides(config_data)

    return Config(**config_data)


def _apply_env_overrides(config_data: Dict[str, Any]) -> Dict[str, Any]:
    """Apply environment variable overrides to configuration data."""
    # AWS overrides
    if os.getenv("AWS_REGION"):
        config_data.setdefault("aws", {})["region"] = os.getenv("AWS_REGION")
    if os.getenv("AWS_PROFILE"):
        config_data.setdefault("aws", {})["profile"] = os.getenv("AWS_PROFILE")

    # S3 overrides
    if os.getenv("MODEL_BUCKET_NAME"):
        config_data.setdefault("s3", {})["model_bucket_name"] = os.getenv("MODEL_BUCKET_NAME")
    if os.getenv("DATA_BUCKET_NAME"):
        config_data.setdefault("s3", {})["data_bucket_name"] = os.getenv("DATA_BUCKET_NAME")
    if os.getenv("LOG_BUCKET_NAME"):
        config_data.setdefault("s3", {})["log_bucket_name"] = os.getenv("LOG_BUCKET_NAME")

    # KMS overrides
    if os.getenv("KMS_KEY_ALIAS"):
        config_data.setdefault("kms", {})["key_alias"] = os.getenv("KMS_KEY_ALIAS")

    # Model overrides
    anomaly_threshold = os.getenv("ANOMALY_THRESHOLD")
    if anomaly_threshold:
        config_data.setdefault("model", {})["anomaly_threshold"] = float(anomaly_threshold)

    # Feature flag overrides
    enable_training = os.getenv("ENABLE_TRAINING")
    if enable_training:
        config_data.setdefault("features", {})["enable_training"] = (
            enable_training.lower() == "true"
        )
    enable_sagemaker = os.getenv("ENABLE_SAGEMAKER")
    if enable_sagemaker:
        config_data.setdefault("features", {})["enable_sagemaker"] = (
            enable_sagemaker.lower() == "true"
        )

    return config_data


def is_aws_deploy_allowed() -> bool:
    """Check if AWS deployments are allowed (safety flag)."""
    return os.getenv("ALLOW_AWS_DEPLOY", "").lower() in ("1", "true", "yes")
