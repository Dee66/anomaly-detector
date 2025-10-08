"""Thin S3 adapter used by packaging scripts.

This wraps boto3 S3 interactions so we can swap in test adapters during unit tests.
The production adapter uses `upload_file` (which handles multipart uploads) and
`put_object` for small objects.
"""
from pathlib import Path
from typing import Dict, Any

import boto3
from boto3.s3.transfer import TransferConfig


class S3Adapter:
    """Thin S3 adapter used by packaging scripts.

    This wraps boto3 S3 interactions so we can swap in test adapters during unit tests.
    The production adapter uses `upload_file` and will configure a TransferConfig
    for multipart uploads when a file exceeds `multipart_threshold`.
    """

    def __init__(self, region: str | None = None, *, multipart_threshold: int = 8 * 1024 * 1024, transfer_config_kwargs: Dict[str, Any] | None = None):
        """Create an adapter.

        Args:
            region: AWS region for the S3 client.
            multipart_threshold: file size in bytes above which multipart uploads are used.
            transfer_config_kwargs: optional kwargs forwarded to boto3.s3.transfer.TransferConfig.
        """
        self.region = region
        self._client = boto3.client('s3', region_name=region) if region else boto3.client('s3')
        self.multipart_threshold = int(multipart_threshold)
        # Shallow-copy; we'll set multipart_threshold as a default when building the TransferConfig
        self.transfer_config_kwargs = dict(transfer_config_kwargs or {})

    def upload_file(self, file_path: Path, bucket: str, key: str, extra_args: Dict[str, Any] | None = None) -> None:
        """Upload a file to S3 using boto3's upload_file.

        When the file size is >= multipart_threshold a TransferConfig is created and
        passed to `upload_file` to control multipart behavior. For smaller files the
        default upload path is used.
        """
        extra = extra_args or {}
        size = Path(file_path).stat().st_size

        if size >= self.multipart_threshold:
            # Build TransferConfig with provided kwargs but ensure multipart_threshold is set
            cfg_kwargs = dict(self.transfer_config_kwargs)
            cfg_kwargs.setdefault('multipart_threshold', self.multipart_threshold)
            transfer_cfg = TransferConfig(**cfg_kwargs)
            # Pass the TransferConfig as Config to upload_file
            self._client.upload_file(str(file_path), bucket, key, ExtraArgs=extra, Config=transfer_cfg)
        else:
            # Small files - use default upload path
            self._client.upload_file(str(file_path), bucket, key, ExtraArgs=extra)

    def put_object(self, bucket: str, key: str, body: bytes, extra_args: Dict[str, Any] | None = None) -> None:
        params = {'Bucket': bucket, 'Key': key, 'Body': body}
        if extra_args:
            params.update(extra_args)
        self._client.put_object(**params)
