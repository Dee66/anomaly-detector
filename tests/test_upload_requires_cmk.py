from pathlib import Path
import pytest

from scripts.package_model_artifacts import upload_to_s3


class DummyAdapter:
    def __init__(self):
        self.uploaded = []
        self.puts = []

    def upload_file(self, package_path, bucket, key, extra_args):
        self.uploaded.append((str(package_path), bucket, key, extra_args))

    def put_object(self, bucket, key, body, extra_args=None):
        self.puts.append((bucket, key, body, extra_args))


def test_upload_requires_cmk_raises(tmp_path: Path):
    pkg = tmp_path / "p.zip"
    pkg.write_bytes(b"x")

    cfg = {
        "s3": {"model_bucket_name": "b"},
        "environment": "dev",
        "aws": {"region": "us-west-2"}
        # Note: no 'kms' key present
    }

    with pytest.raises(RuntimeError):
        upload_to_s3(pkg, cfg, "v1", dry_run=False, s3_adapter=DummyAdapter())


def test_upload_with_empty_kms_allowed(tmp_path: Path):
    pkg = tmp_path / "p2.zip"
    pkg.write_bytes(b"x")

    cfg = {
        "s3": {"model_bucket_name": "b"},
        "environment": "dev",
        "aws": {"region": "us-west-2"},
        "kms": {}  # explicit empty dict should opt-out of require_cmk
    }

    adapter = DummyAdapter()
    uri = upload_to_s3(pkg, cfg, "v1", dry_run=False, s3_adapter=adapter)

    assert uri.startswith("s3://b/")
    assert len(adapter.uploaded) == 1
