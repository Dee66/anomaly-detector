from pathlib import Path
import pytest

from scripts.package_model_artifacts import upload_to_s3, create_model_package


class DummyAdapter:
    def upload_file(self, *args, **kwargs):
        return None

    def put_object(self, *args, **kwargs):
        return None


class DummyKmsClient:
    def get_paginator(self, op_name):
        raise RuntimeError("Should not be called in this test")


def make_pkg(tmp_path: Path) -> Path:
    model_dir = tmp_path / "m"
    model_dir.mkdir()
    for name in ("model.bin", "config.json", "tokenizer.json"):
        (model_dir / name).write_text("x")
    out = tmp_path / "dist"
    out.mkdir()
    return create_model_package(model_dir, out, "v1")


def test_upload_requires_cmk(tmp_path):
    pkg = make_pkg(tmp_path)
    config = {
        "s3": {"model_bucket_name": "b"},
        "environment": "dev",
        "aws": {"region": "us-east-1"},
        # no kms key provided
    }

    with pytest.raises(RuntimeError):
        upload_to_s3(pkg, config, "v1", dry_run=False, s3_adapter=DummyAdapter(), kms_client=DummyKmsClient())


def test_upload_allows_explicit_kms_arn(tmp_path):
    pkg = make_pkg(tmp_path)
    config = {
        "s3": {"model_bucket_name": "b"},
        "environment": "dev",
        "aws": {"region": "us-east-1"},
        "kms": {"key_alias": "arn:aws:kms:us-east-1:123456789012:key/abcd-ef01"},
    }

    # Should not raise when an explicit ARN is provided; we pass dummy adapter/client
    s3_uri = upload_to_s3(pkg, config, "v1", dry_run=False, s3_adapter=DummyAdapter(), kms_client=DummyKmsClient())
    assert s3_uri.startswith("s3://")
