import os
from pathlib import Path
import zipfile

import boto3
from botocore.stub import Stubber

from detector.config import load_config
from scripts.package_model_artifacts import (
    create_model_package,
    upload_to_s3,
)


def _make_dummy_model_dir(tmp_path: Path) -> Path:
    d = tmp_path / "model"
    d.mkdir()
    for name in ("model.bin", "config.json", "tokenizer.json"):
        p = d / name
        p.write_text("dummy")
    return d


def test_create_package_and_dry_run(tmp_path: Path):
    model_dir = _make_dummy_model_dir(tmp_path)
    out_dir = tmp_path / "dist"
    out_dir.mkdir()

    package = create_model_package(model_dir, out_dir, "v1")
    assert package.exists()

    # Load a config (dev) and run dry-run upload
    cfg = load_config("dev").model_dump()
    uri = upload_to_s3(package, cfg, "v1", dry_run=True)
    assert uri.startswith("s3://")


def test_upload_with_stubbed_kms_and_s3(tmp_path: Path):
    model_dir = _make_dummy_model_dir(tmp_path)
    out_dir = tmp_path / "dist"
    out_dir.mkdir()

    package = create_model_package(model_dir, out_dir, "v2")

    cfg = load_config("dev").model_dump()
    region = cfg["aws"]["region"]

    # Stub KMS: list_aliases -> alias exists -> describe_key returns KeyMetadata with Arn
    kms = boto3.client("kms", region_name=region)
    kms_stubber = Stubber(kms)
    kms_stubber.add_response(
        "list_aliases",
        {"Aliases": [{"AliasName": cfg["kms"]["key_alias"], "TargetKeyId": "1234-abc"}]}
    )
    kms_stubber.add_response(
    "describe_key",
        {"KeyMetadata": {"KeyId": "1234-abc", "Arn": "arn:aws:kms:us-west-2:111111111111:key/1234-abc"}}
    )

    # Stub S3 upload_file (we stub put_object used by put_object) using client stubber
    s3 = boto3.client("s3", region_name=region)
    s3_stubber = Stubber(s3)
    # Put object for current.txt
    # Two put_object calls will be made: one for the package body and one for current.txt
    s3_stubber.add_response(
        "put_object",
        {}
    )
    s3_stubber.add_response(
        "put_object",
        {}
    )

    # Instead of patching boto3.client globally, patch the S3Adapter to use our
    # stubbed clients so upload_file / put_object map to the stubbed s3 client.
    from scripts import s3_adapter as s3_adapter_module

    class TestS3Adapter:
        def __init__(self, region: str | None = None):
            self._client = s3

        def upload_file(self, file_path: Path, bucket: str, key: str, extra_args: dict | None = None):
            # Simulate upload by calling put_object via the stubbed client
            with open(file_path, 'rb') as fh:
                self._client.put_object(Bucket=bucket, Key=key, Body=fh.read(), **(extra_args or {}))

        def put_object(self, bucket: str, key: str, body: bytes, extra_args: dict | None = None):
            params = {'Bucket': bucket, 'Key': key, 'Body': body}
            if extra_args:
                params.update(extra_args)
            self._client.put_object(**params)

    # Create an instance of the test adapter that uses the stubbed s3 client
    test_adapter = TestS3Adapter()

    kms_stubber.activate()
    s3_stubber.activate()

    try:
        uri = upload_to_s3(package, cfg, "v2", dry_run=False, kms_client=kms, s3_adapter=test_adapter)
        assert uri.startswith("s3://")
    finally:
        kms_stubber.deactivate()
        s3_stubber.deactivate()
