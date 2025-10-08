import os
from pathlib import Path

import yaml
import pytest
from pydantic import ValidationError

from src.detector.config import load_config, is_aws_deploy_allowed


CONFIG_DIR = Path.cwd() / "config"


def _write_config_file(name: str, data: dict) -> Path:
    CONFIG_DIR.mkdir(exist_ok=True)
    p = CONFIG_DIR / name
    with p.open("w") as f:
        yaml.safe_dump(data, f)
    return p


def test_load_config_happy_path(tmp_path):
    data = {
        "environment": "test",
        "app_name": "anomaly-detector",
        "aws": {"region": "us-west-2", "profile": "dev"},
        "s3": {
            "model_bucket_name": "models-test",
            "data_bucket_name": "data-test",
            "log_bucket_name": "logs-test",
            "compliance_bucket_name": "compliance-test",
        },
        "kms": {"key_alias": "alias/test"},
        "vpc": {"vpc_id": None, "private_subnets": []},
        "model": {"ner_model_name": "m", "anomaly_threshold": 1.0, "batch_size": 1},
        "logging": {"level": "DEBUG", "structured": True},
        "features": {"enable_training": False, "enable_sagemaker": False, "enable_vpc_endpoints": False},
        "alerts": {"sns_topic_name": "topic-test", "email_endpoints": []},
    }

    p = _write_config_file("test.yml", data)
    try:
        cfg = load_config("test")
        assert cfg.environment == "test"
        assert cfg.aws.region == "us-west-2"
        assert cfg.s3.model_bucket_name == "models-test"
        assert cfg.kms.key_alias == "alias/test"
    finally:
        p.unlink()


def test_env_overrides_apply(monkeypatch):
    base = {
        "environment": "test",
        "app_name": "anomaly-detector",
        "aws": {"region": "us-west-2", "profile": "dev"},
        "s3": {
            "model_bucket_name": "models-test",
            "data_bucket_name": "data-test",
            "log_bucket_name": "logs-test",
            "compliance_bucket_name": "compliance-test",
        },
        "kms": {"key_alias": "alias/test"},
        "vpc": {"vpc_id": None, "private_subnets": []},
        "model": {"ner_model_name": "m", "anomaly_threshold": 1.0, "batch_size": 1},
        "logging": {"level": "DEBUG", "structured": True},
        "features": {"enable_training": False, "enable_sagemaker": False, "enable_vpc_endpoints": False},
        "alerts": {"sns_topic_name": "topic-test", "email_endpoints": []},
    }

    p = _write_config_file("test.yml", base)
    try:
        # Set overrides
        monkeypatch.setenv("MODEL_BUCKET_NAME", "env-models")
        monkeypatch.setenv("COMPLIANCE_BUCKET_NAME", "env-compliance")
        monkeypatch.setenv("ENABLE_VPC_ENDPOINTS", "true")
        monkeypatch.setenv("PRIVATE_SUBNETS", "subnet-1, subnet-2")
        monkeypatch.setenv("ALERT_EMAILS", "a@example.com, b@example.com")
        monkeypatch.setenv("SNS_TOPIC_NAME", "env-topic")
        monkeypatch.setenv("AWS_REGION", "eu-central-1")

        cfg = load_config("test")
        assert cfg.s3.model_bucket_name == "env-models"
        assert cfg.s3.compliance_bucket_name == "env-compliance"
        assert cfg.features.enable_vpc_endpoints is True
        assert cfg.vpc.private_subnets == ["subnet-1", "subnet-2"]
        assert cfg.alerts.email_endpoints == ["a@example.com", "b@example.com"]
        assert cfg.alerts.sns_topic_name == "env-topic"
        assert cfg.aws.region == "eu-central-1"
    finally:
        p.unlink()


def test_missing_config_file_raises():
    # ensure file absent
    p = CONFIG_DIR / "doesnotexist.yml"
    if p.exists():
        p.unlink()
    with pytest.raises(FileNotFoundError):
        load_config("doesnotexist")


def test_validation_error_for_incomplete_config():
    # write a config missing required S3 fields
    invalid = {
        "environment": "test",
        "app_name": "anomaly-detector",
        "aws": {"region": "us-west-2"},
        # s3 is intentionally incomplete
        "s3": {},
        "kms": {"key_alias": "alias/test"},
        "vpc": {"vpc_id": None, "private_subnets": []},
        "model": {"ner_model_name": "m", "anomaly_threshold": 1.0, "batch_size": 1},
        "logging": {"level": "DEBUG", "structured": True},
        "features": {"enable_training": False, "enable_sagemaker": False, "enable_vpc_endpoints": False},
        "alerts": {"sns_topic_name": "topic-test", "email_endpoints": []},
    }

    p = _write_config_file("test_invalid.yml", invalid)
    try:
        with pytest.raises(ValidationError):
            load_config("test_invalid")
    finally:
        p.unlink()


def test_is_aws_deploy_allowed(monkeypatch):
    # default off
    monkeypatch.delenv("ALLOW_AWS_DEPLOY", raising=False)
    assert is_aws_deploy_allowed() is False

    monkeypatch.setenv("ALLOW_AWS_DEPLOY", "1")
    assert is_aws_deploy_allowed() is True

    monkeypatch.setenv("ALLOW_AWS_DEPLOY", "true")
    assert is_aws_deploy_allowed() is True
"""Tests for the configuration management system."""

import os

# Import the config module by adding src to path
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detector.config import _apply_env_overrides, is_aws_deploy_allowed, load_config


def test_load_dev_config():
    """Test loading development configuration."""
    config = load_config("dev")

    assert config.environment == "dev"
    assert config.app_name == "anomaly-detector"
    assert config.aws.region == "us-west-2"
    assert config.s3.model_bucket_name == "anomaly-detector-models-dev"
    assert config.features.enable_training is True
    assert config.features.enable_sagemaker is False


def test_load_prod_config():
    """Test loading production configuration."""
    config = load_config("prod")

    assert config.environment == "prod"
    assert config.aws.region == "us-east-1"
    assert config.s3.model_bucket_name == "anomaly-detector-models-prod"
    assert config.features.enable_training is False
    assert config.features.enable_sagemaker is True


def test_env_overrides():
    """Test environment variable overrides."""
    # Test AWS region override
    test_data = {"aws": {"region": "us-west-2"}}

    # Mock environment variable
    original_region = os.getenv("AWS_REGION")
    os.environ["AWS_REGION"] = "eu-west-1"

    try:
        result = _apply_env_overrides(test_data)
        assert result["aws"]["region"] == "eu-west-1"
    finally:
        # Cleanup
        if original_region:
            os.environ["AWS_REGION"] = original_region
        else:
            os.environ.pop("AWS_REGION", None)


def test_env_overrides_model_threshold():
    """Test anomaly threshold override."""
    test_data = {"model": {"anomaly_threshold": 3.0}}

    # Mock environment variable
    original_threshold = os.getenv("ANOMALY_THRESHOLD")
    os.environ["ANOMALY_THRESHOLD"] = "2.5"

    try:
        result = _apply_env_overrides(test_data)
        assert result["model"]["anomaly_threshold"] == 2.5
    finally:
        # Cleanup
        if original_threshold:
            os.environ["ANOMALY_THRESHOLD"] = original_threshold
        else:
            os.environ.pop("ANOMALY_THRESHOLD", None)


def test_aws_deploy_allowed():
    """Test AWS deployment safety flag."""
    # Test default (should be False)
    original_flag = os.getenv("ALLOW_AWS_DEPLOY")

    # Clear the flag first
    os.environ.pop("ALLOW_AWS_DEPLOY", None)
    assert is_aws_deploy_allowed() is False

    # Test with flag set to "1"
    os.environ["ALLOW_AWS_DEPLOY"] = "1"
    assert is_aws_deploy_allowed() is True

    # Test with flag set to "true"
    os.environ["ALLOW_AWS_DEPLOY"] = "true"
    assert is_aws_deploy_allowed() is True

    # Test with flag set to "false"
    os.environ["ALLOW_AWS_DEPLOY"] = "false"
    assert is_aws_deploy_allowed() is False

    # Cleanup
    if original_flag:
        os.environ["ALLOW_AWS_DEPLOY"] = original_flag
    else:
        os.environ.pop("ALLOW_AWS_DEPLOY", None)


def test_config_file_not_found():
    """Test error handling when config file doesn't exist."""
    with pytest.raises(FileNotFoundError):
        load_config("nonexistent")


def test_config_validation():
    """Test configuration validation with invalid data."""
    # Create a temporary invalid config file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        yaml.dump({
            "environment": "test",
            "app_name": "test-app",
            # Missing required fields like aws, s3, etc.
        }, f)
        temp_file = Path(f.name)

    try:
        # This should raise a validation error due to missing required fields
        with pytest.raises(Exception):  # Pydantic validation error
            # We'd need to temporarily modify the config loading to use this file
            # For now, just test that validation works with incomplete data
            from detector.config import Config
            Config(
                environment="test",
                app_name="test-app"
                # Missing required nested objects
            )
    finally:
        temp_file.unlink()  # Clean up temp file
