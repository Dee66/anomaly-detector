import os
from pathlib import Path
from boto3.s3.transfer import TransferConfig

from scripts.s3_adapter import S3Adapter


def _write_file(path: Path, size: int) -> None:
    # Create a file with the requested size (bytes)
    with open(path, 'wb') as f:
        f.write(b"0" * size)


def test_upload_small_file_uses_no_transfer_config(monkeypatch, tmp_path: Path):
    file_path = tmp_path / "small.bin"
    _write_file(file_path, 1024)  # 1 KiB

    called = {}

    class DummyClient:
        def upload_file(self, filename, bucket, key, ExtraArgs=None, Config=None):
            called['filename'] = filename
            called['bucket'] = bucket
            called['key'] = key
            called['extra'] = ExtraArgs
            called['config'] = Config

    adapter = S3Adapter(region=None, multipart_threshold=8 * 1024 * 1024)
    # inject dummy client
    adapter._client = DummyClient()

    adapter.upload_file(file_path, 'test-bucket', 'small/key', extra_args={'Meta': 'x'})

    assert called['filename'].endswith('small.bin')
    assert called['bucket'] == 'test-bucket'
    assert called['key'] == 'small/key'
    # For small file, Config should be None
    assert called['config'] is None


def test_upload_large_file_uses_transfer_config(monkeypatch, tmp_path: Path):
    file_path = tmp_path / "large.bin"
    # Make file slightly larger than a low threshold we'll set on the adapter
    _write_file(file_path, 2 * 1024 * 1024)  # 2 MiB

    called = {}

    class DummyClient:
        def upload_file(self, filename, bucket, key, ExtraArgs=None, Config=None):
            called['filename'] = filename
            called['bucket'] = bucket
            called['key'] = key
            called['extra'] = ExtraArgs
            called['config'] = Config

    # Set a threshold smaller than the file size so TransferConfig path is used
    adapter = S3Adapter(region=None, multipart_threshold=1024 * 1024)
    adapter._client = DummyClient()

    adapter.upload_file(file_path, 'test-bucket', 'large/key', extra_args=None)

    assert called['filename'].endswith('large.bin')
    assert called['bucket'] == 'test-bucket'
    assert called['key'] == 'large/key'
    # For large file, Config should be a TransferConfig instance
    assert isinstance(called['config'], TransferConfig)
