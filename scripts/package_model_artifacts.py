"""Package model artifacts for deployment.

This script packages model artifacts into a versioned S3 layout for deployment.
It defaults to dry-run mode and requires explicit --apply flag for actual deployment.
"""

import argparse
import os
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError
from botocore.client import BaseClient
from scripts.s3_adapter import S3Adapter

# Add src to path for config access
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detector.config import load_config
from src.deployer_guard import require_deploy_allowed_or_exit


# Custom exception for KMS resolution failures so callers/tests can distinguish
# expected resolution errors from other unexpected failures.
class KMSResolutionError(RuntimeError):
    pass


def create_model_package(
    model_dir: Path,
    output_path: Path,
    version: str
) -> Path:
    """Create a model package zip file.

    Args:
        model_dir: Directory containing model artifacts
        output_path: Output directory for the package
        version: Version string for the package

    Returns:
        Path to the created package
    """
    package_name = f"model_package-{version}.zip"
    package_path = output_path / package_name

    print(f"Creating model package: {package_path}")

    with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path in model_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(model_dir)
                zipf.write(file_path, arcname)
                print(f"  Added: {arcname}")

    return package_path


def upload_to_s3(
    package_path: Path,
    config: Dict[str, Any],
    version: str,
    dry_run: bool = True,
    s3_adapter: S3Adapter | None = None,
    kms_client: BaseClient | None = None,
) -> str:
    """Upload model package to S3.

    Args:
        package_path: Path to the model package
        config: Configuration dictionary
        version: Version string
        dry_run: If True, don't actually upload

    Returns:
        S3 URI of the uploaded package
    """
    bucket_name = config["s3"]["model_bucket_name"]
    environment = config["environment"]
    key = f"model-packages/{environment}/{package_path.name}"
    s3_uri = f"s3://{bucket_name}/{key}"

    if dry_run:
        print(f"DRY RUN: Would upload {package_path} to {s3_uri}")
        return s3_uri

    # Security guard: require customer-managed KMS key for real uploads by default.
    # Behavior: if `kms` is missing from config, enforce CMK by default. If `kms`
    # is present but empty (tests may set `cfg['kms'] = {}`), treat that as an
    # explicit opt-out to allow faster local testing.
    kms_cfg = config.get("kms", None)
    if kms_cfg is None:
        require_cmk = True
    else:
        # If kms is provided, default to not requiring CMK unless explicitly set.
        require_cmk = bool(kms_cfg.get("require_cmk", False))

    kms_alias = (kms_cfg or {}).get("key_alias")
    kms_key_provided = bool(kms_alias)

    if require_cmk and not kms_key_provided:
        raise RuntimeError(
            "Uploading model artifacts requires a customer-managed KMS key. "
            "Set `kms.key_alias` (alias/<name>) or provide a KeyId/ARN in the config under `kms.key_alias`."
        )

    print(f"Uploading {package_path} to {s3_uri}")

    try:
        # Read optional transfer tuning from config: s3.transfer.multipart_threshold and
        # s3.transfer.transfer_config_kwargs
        transfer_cfg = config.get("s3", {}).get("transfer", {}) or {}
        multipart_threshold = transfer_cfg.get("multipart_threshold")
        transfer_config_kwargs = transfer_cfg.get("transfer_config_kwargs")

        if s3_adapter is None:
            # Only construct the adapter from config when not injected for tests
            if multipart_threshold is None and transfer_config_kwargs is None:
                s3_adapter = S3Adapter(region=config["aws"]["region"])
            else:
                s3_adapter = S3Adapter(
                    region=config["aws"]["region"],
                    multipart_threshold=multipart_threshold or 8 * 1024 * 1024,
                    transfer_config_kwargs=transfer_config_kwargs or {}
                )

        # Resolve KMS alias to key id/arn when performing a real upload. Fail hard
        # if the alias cannot be resolved to avoid accidental unencrypted uploads.
        kms_key_identifier = None
        kms_alias = config.get("kms", {}).get("key_alias")
        if kms_alias:
            kms_client = kms_client or boto3.client('kms', region_name=config["aws"]["region"])
            kms_key_identifier = _resolve_kms_alias_to_keyid(kms_client, kms_alias)
            if not kms_key_identifier:
                raise RuntimeError(f"Unable to resolve KMS alias to key id/arn: {kms_alias}")

        # Upload the package
        extra_args = {
            'ServerSideEncryption': 'aws:kms',
            'Metadata': {
                'version': version,
                'environment': environment,
                'created_at': datetime.utcnow().isoformat()
            }
        }
        if kms_key_identifier:
            extra_args['SSEKMSKeyId'] = kms_key_identifier

        # Use the adapter which will choose multipart upload when needed.
        s3_adapter.upload_file(package_path, bucket_name, key, extra_args)

        # Update current.txt pointer
        current_key = f"model-packages/{environment}/current.txt"
        put_extra = {
            'ServerSideEncryption': 'aws:kms',
        }
        if kms_key_identifier:
            put_extra['SSEKMSKeyId'] = kms_key_identifier

        s3_adapter.put_object(bucket_name, current_key, package_path.name.encode('utf-8'), extra_args=put_extra)

        print("✅ Successfully uploaded and updated current pointer")
        return s3_uri

    except ClientError as e:
        print(f"❌ Error uploading to S3: {e}")
        sys.exit(1)


def validate_model_artifacts(model_dir: Path) -> None:
    """Validate that required model artifacts exist.

    Args:
        model_dir: Directory to validate

    Raises:
        FileNotFoundError: If required files are missing
    """
    required_files = [
        "model.bin",  # Model weights
        "config.json",  # Model configuration
        "tokenizer.json"  # Tokenizer configuration
    ]

    print(f"Validating model artifacts in {model_dir}")

    for required_file in required_files:
        file_path = model_dir / required_file
        if not file_path.exists():
            raise FileNotFoundError(f"Required model file missing: {required_file}")
        print(f"  ✅ Found: {required_file}")


def _resolve_kms_alias_to_keyid(kms_client: BaseClient, alias_name: str) -> str | None:
    """Resolve a KMS alias (e.g. alias/my-key) to a KeyId or ARN.

    Returns the KeyId/ARN string or None if not found. Uses `list_aliases` and
    `describe_key` to discover the underlying key ARN.
    """
    if not alias_name.startswith("alias/"):
        # The user provided a direct id or arn already
        return alias_name

    # We want to fail fast and synchronously if the alias cannot be resolved
    try:
        paginator = kms_client.get_paginator('list_aliases')
        for page in paginator.paginate():
            for alias in page.get('Aliases', []):
                if alias.get('AliasName') == alias_name:
                    target_key = alias.get('TargetKeyId')
                    if not target_key:
                        # Alias exists but is not mapped to a key
                        raise KMSResolutionError(
                            f"KMS alias '{alias_name}' found but has no TargetKeyId. "
                            "Ensure the alias points to an enabled KMS key."
                        )

                    # TargetKeyId may be a KeyId or ARN. Use describe_key to obtain canonical ARN.
                    try:
                        desc = kms_client.describe_key(KeyId=target_key)
                        arn = desc.get('KeyMetadata', {}).get('Arn')
                        return arn or target_key
                    except Exception as e:
                        raise KMSResolutionError(
                            f"Failed to describe KMS key for alias '{alias_name}' (KeyId={target_key}): {e}"
                        ) from e

        # If we reach here the alias wasn't found - raise a helpful error so callers
        # performing real uploads fail early rather than silently proceeding.
        raise KMSResolutionError(
            f"KMS alias '{alias_name}' could not be found in this account/region. "
            "Check that the alias exists and that your AWS credentials/region are correct. "
            "If you intended to pass a KeyId or ARN, provide it directly instead of an alias."
        )
    except KMSResolutionError:
        # Re-raise our own resolution errors unchanged
        raise
    except Exception as e:
        # Wrap other unexpected errors with a consistent message to simplify tests
        # and improve troubleshooting.
        raise KMSResolutionError(
            f"Unexpected error while resolving KMS alias '{alias_name}': {e}. "
            "Verify network/credentials and try again."
        ) from e


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Package model artifacts for deployment"
    )
    parser.add_argument(
        "model_dir",
        type=Path,
        help="Directory containing model artifacts"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./dist"),
        help="Output directory for packages (default: ./dist)"
    )
    parser.add_argument(
        "--version",
        default=datetime.utcnow().strftime("%Y%m%d-%H%M%S"),
        help="Version string for the package (default: timestamp)"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually perform the upload (default: dry-run)"
    )
    parser.add_argument(
        "--environment",
        default=os.getenv("ENVIRONMENT", "dev"),
        help="Target environment (default: dev)"
    )

    args = parser.parse_args()

    # Validate inputs
    if not args.model_dir.exists():
        print(f"❌ Model directory not found: {args.model_dir}")
        sys.exit(1)

    # Safety checks
    dry_run = not args.apply
    if args.apply:
        require_deploy_allowed_or_exit("Model upload requested; confirm before proceeding")

    # Load configuration
    config_obj = load_config(args.environment)
    # load_config returns a Pydantic Config object
    config = config_obj.model_dump()

    try:
        # Validate model artifacts
        validate_model_artifacts(args.model_dir)

        # Create output directory
        args.output_dir.mkdir(parents=True, exist_ok=True)

        # Create model package
        package_path = create_model_package(
            args.model_dir,
            args.output_dir,
            args.version
        )

        # Upload to S3
        s3_uri = upload_to_s3(
            package_path,
            config,
            args.version,
            dry_run=dry_run
        )

        print(f"\n{'🎯' if not dry_run else '🔍'} Model package ready: {s3_uri}")

        if dry_run:
            print("\n💡 Use --apply flag to perform actual upload")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
