from pathlib import Path
import boto3
from botocore.stub import Stubber

from detector.config import load_config
from scripts.package_model_artifacts import upload_to_s3


class CaptureAdapterInit:
    captured = None

    def __init__(self, *args, **kwargs):
        # Capture construction args for assertions in test
        CaptureAdapterInit.captured = {'args': args, 'kwargs': kwargs}
        # Provide a minimal API expected by upload_to_s3
        class Dummy:
            def upload_file(self, *a, **k):
                return None

            def put_object(self, *a, **k):
                return None

        self._impl = Dummy()
        # Expose expected methods directly so callers can invoke them
        self.upload_file = self._impl.upload_file
        self.put_object = self._impl.put_object


def test_package_respects_transfer_config(tmp_path: Path, monkeypatch):
    # Build minimal model dir
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    for name in ("model.bin", "config.json", "tokenizer.json"):
        (model_dir / name).write_text("x")

    out_dir = tmp_path / "dist"
    out_dir.mkdir()

    package = out_dir / "model_package-test.zip"
    package.write_text("dummy")

    # Load config and modify it to include transfer tuning
    cfg = load_config("dev").model_dump()
    cfg['s3'] = cfg.get('s3', {})
    cfg['s3']['transfer'] = {
        'multipart_threshold': 1024,  # 1 KiB so that small test files trigger multipart path
        'transfer_config_kwargs': {
            'max_concurrency': 3,
            'multipart_chunksize': 64 * 1024
        }
    }
    # Ensure KMS resolution is not attempted in this test
    cfg['kms'] = {}

    # Replace S3Adapter symbol used by package_model_artifacts so we can assert construction args
    monkeypatch.setattr('scripts.package_model_artifacts.S3Adapter', CaptureAdapterInit)

    # Stub KMS (not used in this test but upload_to_s3 may try to use it when apply=True)
    region = cfg['aws']['region']
    kms = boto3.client('kms', region_name=region)
    kms_stubber = Stubber(kms)
    kms_stubber.add_response('list_aliases', {'Aliases': []})
    kms_stubber.activate()

    # Call upload_to_s3 with dry_run=False but provide a test adapter via monkeypatch injection
    try:
        # Call with dry_run=False so the code path constructs the S3Adapter from config.
        # Our monkeypatched S3Adapter returns a dummy implementation so no network calls occur.
        upload_to_s3(package, cfg, 'test', dry_run=False)
    finally:
        kms_stubber.deactivate()

    captured = CaptureAdapterInit.captured
    assert captured is not None
    # ensure our transfer kwargs were forwarded into adapter construction
    kwargs = captured['kwargs']
    assert 'multipart_threshold' in kwargs
    assert kwargs['multipart_threshold'] == 1024
    assert 'transfer_config_kwargs' in kwargs
    assert kwargs['transfer_config_kwargs']['max_concurrency'] == 3
