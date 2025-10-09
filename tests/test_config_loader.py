import os
from pathlib import Path
import pytest

from detector.config import load_config, _apply_env_overrides


def test_apply_env_overrides_sets_values(monkeypatch, tmp_path):
    base = {
        'aws': {'region': 'us-west-2'},
        's3': {'model_bucket_name': 'm', 'data_bucket_name': 'd', 'log_bucket_name': 'l', 'compliance_bucket_name': 'c'},
        'kms': {'key_alias': 'alias/x'},
        'model': {'anomaly_threshold': 3.0},
        'features': {}
    }

    monkeypatch.setenv('AWS_REGION', 'eu-central-1')
    monkeypatch.setenv('MODEL_BUCKET_NAME', 'model-override')
    monkeypatch.setenv('ANOMALY_THRESHOLD', '4.2')
    monkeypatch.setenv('ENABLE_TRAINING', 'true')
    monkeypatch.setenv('PRIVATE_SUBNETS', 'sub-1, sub-2,,')

    out = _apply_env_overrides(dict(base))
    assert out['aws']['region'] == 'eu-central-1'
    assert out['s3']['model_bucket_name'] == 'model-override'
    assert out['model']['anomaly_threshold'] == 4.2
    assert out['features']['enable_training'] is True
    assert out['vpc']['private_subnets'] == ['sub-1', 'sub-2']


def test_load_config_fails_when_file_missing(tmp_path, monkeypatch):
    # point config loader to a non-existent environment
    with pytest.raises(FileNotFoundError):
        load_config('nonexistent_env')
