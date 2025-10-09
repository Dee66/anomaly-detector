import boto3
from botocore.stub import Stubber
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


def test_upload_to_s3_real_path(tmp_path: Path):
    # Create a fake package file
    pkg = tmp_path / "p.zip"
    pkg.write_bytes(b"x")

    cfg = {
        "s3": {"model_bucket_name": "my-bucket"},
        "environment": "prod",
        "aws": {"region": "us-west-2"},
        "kms": {"key_alias": "alias/my-key"}
    }

    # Stub KMS: list_aliases returns the alias mapping, describe_key returns Arn
    kms = boto3.client('kms', region_name='us-west-2')
    stub = Stubber(kms)
    stub.add_response('list_aliases', {'Aliases': [{'AliasName': 'alias/my-key', 'TargetKeyId': 'k1'}]})
    stub.add_response('describe_key', {'KeyMetadata': {'Arn': 'arn:aws:kms:us-west-2:111:key/k1', 'KeyId': 'k1'}})
    stub.activate()

    adapter = DummyAdapter()

    uri = upload_to_s3(pkg, cfg, 'v1', dry_run=False, s3_adapter=adapter, kms_client=kms)

    assert uri.startswith('s3://my-bucket/')
    assert len(adapter.uploaded) == 1
    assert len(adapter.puts) == 1

    stub.deactivate()
