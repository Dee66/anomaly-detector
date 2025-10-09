import tempfile
from pathlib import Path
import shutil
import os
import sys
import types


# Ensure a minimal boto3.s3.transfer.TransferConfig exists for import-time when boto3
# is not installed in the test environment. The tests exercise the dry-run path so
# no real boto3 behavior is required.
if 'boto3' not in sys.modules:
    boto3_mod = types.ModuleType('boto3')
    s3_mod = types.ModuleType('boto3.s3')
    transfer_mod = types.ModuleType('boto3.s3.transfer')

    class TransferConfig:
        def __init__(self, *args, **kwargs):
            pass

    transfer_mod.TransferConfig = TransferConfig
    s3_mod.transfer = transfer_mod
    # Mark modules as packages so Python's import system can treat submodules
    boto3_mod.__path__ = ["<boto3-stub>"]
    s3_mod.__path__ = ["<boto3.s3-stub>"]
    boto3_mod.s3 = s3_mod
    sys.modules['boto3'] = boto3_mod
    sys.modules['boto3.s3'] = s3_mod
    sys.modules['boto3.s3.transfer'] = transfer_mod

from scripts.package_model_artifacts import create_model_package, upload_to_s3, validate_model_artifacts


def make_dummy_model_dir(tmp_path: Path) -> Path:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    # create required files
    for name in ("model.bin", "config.json", "tokenizer.json"):
        p = model_dir / name
        p.write_text("dummy")
    return model_dir


def test_package_dryrun(tmp_path):
    model_dir = make_dummy_model_dir(tmp_path)
    out_dir = tmp_path / "dist"
    out_dir.mkdir()

    # validate artifacts shouldn't raise
    validate_model_artifacts(model_dir)

    # create package
    pkg = create_model_package(model_dir, out_dir, "vtest")
    assert pkg.exists()

    # prepare a minimal config dict expected by upload_to_s3
    config = {
        "s3": {"model_bucket_name": "example-bucket"},
        "environment": "dev",
        "aws": {"region": "us-east-1"},
    }

    # dry-run should return the intended s3 uri and not attempt network calls
    s3_uri = upload_to_s3(pkg, config, "vtest", dry_run=True)
    assert s3_uri.startswith("s3://example-bucket/")
