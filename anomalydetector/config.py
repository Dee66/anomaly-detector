from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field


class S3Config(BaseModel):
    model_bucket_name: str
    data_bucket_name: str
    log_bucket_name: Optional[str] = None


class KMSConfig(BaseModel):
    key_alias: Optional[str] = None


class AppConfig(BaseModel):
    environment: str = Field(...)
    app_name: str = Field(...)
    aws: Dict[str, Any] = Field(default_factory=dict)
    s3: S3Config
    kms: Optional[KMSConfig] = None
    vpc: Dict[str, Any] = Field(default_factory=dict)
    model: Dict[str, Any] = Field(default_factory=dict)
    logging: Dict[str, Any] = Field(default_factory=dict)
    features: Dict[str, Any] = Field(default_factory=dict)
    alerts: Dict[str, Any] = Field(default_factory=dict)


def _load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _env_override(key: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(key, default)


def load_config(env: str = "dev", config_dir: Optional[str] = None) -> AppConfig:
    """Load configuration for the given environment.

    Resolution order:
      1. Explicit environment variables (prefix ANOMALY_)
      2. Values from config/{env}.yml
      3. Defaults defined in the pydantic model
    """
    base = Path(config_dir or Path(__file__).parent.parent / "config")
    cfg_path = base / f"{env}.yml"
    raw = {}
    if cfg_path.exists():
        raw = _load_yaml(cfg_path)

    # Simple env overrides for common keys
    # e.g., ANOMALY_MODEL_BUCKET_NAME, ANOMALY_DATA_BUCKET_NAME
    s3 = raw.get("s3", {})
    model_bucket = _env_override("ANOMALY_MODEL_BUCKET_NAME", s3.get("model_bucket_name"))
    data_bucket = _env_override("ANOMALY_DATA_BUCKET_NAME", s3.get("data_bucket_name"))
    log_bucket = _env_override("ANOMALY_LOG_BUCKET_NAME", s3.get("log_bucket_name"))

    s3_cfg = {
        "model_bucket_name": model_bucket,
        "data_bucket_name": data_bucket,
        "log_bucket_name": log_bucket,
    }

    kms_raw = raw.get("kms") or {}
    kms_cfg = {"key_alias": _env_override("ANOMALY_KMS_ALIAS", kms_raw.get("key_alias"))}

    app = {
        "environment": raw.get("environment", env),
        "app_name": raw.get("app_name", "anomaly-detector"),
        "aws": raw.get("aws", {}),
        "s3": s3_cfg,
        "kms": kms_cfg,
        "vpc": raw.get("vpc", {}),
        "model": raw.get("model", {}),
        "logging": raw.get("logging", {}),
        "features": raw.get("features", {}),
        "alerts": raw.get("alerts", {}),
    }

    return AppConfig(**app)


def load_dev(config_dir: Optional[str] = None) -> AppConfig:
    return load_config("dev", config_dir=config_dir)


def load_prod(config_dir: Optional[str] = None) -> AppConfig:
    return load_config("prod", config_dir=config_dir)
