import io
from pathlib import Path

import pytest

from scripts.package_model_artifacts import create_model_package, upload_to_s3, validate_model_artifacts


def test_create_model_package(tmp_path: Path):
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    (model_dir / "model.bin").write_bytes(b"weights")
    (model_dir / "config.json").write_text("{}")
    (model_dir / "tokenizer.json").write_text("{}")

    out = create_model_package(model_dir, tmp_path, "v1")
    assert out.exists()


def test_validate_model_artifacts_missing(tmp_path: Path):
    model_dir = tmp_path / "model2"
    model_dir.mkdir()
    (model_dir / "model.bin").write_bytes(b"weights")
    # missing config.json

    with pytest.raises(FileNotFoundError):
        validate_model_artifacts(model_dir)


def test_upload_to_s3_dry_run(tmp_path: Path):
    cfg = {
        "s3": {"model_bucket_name": "b"},
        "environment": "dev",
        "aws": {"region": "us-west-2"},
        # explicit empty kms to indicate test opt-out
        "kms": {}
    }

    package_path = tmp_path / "pkg.zip"
    package_path.write_bytes(b"x")

    uri = upload_to_s3(package_path, cfg, "v1", dry_run=True)
    assert uri.startswith("s3://b/")
