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

# Add src to path for config access
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detector.config import is_aws_deploy_allowed, load_config


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
    dry_run: bool = True
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

    print(f"Uploading {package_path} to {s3_uri}")

    try:
        s3_client = boto3.client('s3', region_name=config["aws"]["region"])

        # Upload the package
        s3_client.upload_file(
            str(package_path),
            bucket_name,
            key,
            ExtraArgs={
                'ServerSideEncryption': 'aws:kms',
                'SSEKMSKeyId': config["kms"]["key_alias"],
                'Metadata': {
                    'version': version,
                    'environment': environment,
                    'created_at': datetime.utcnow().isoformat()
                }
            }
        )

        # Update current.txt pointer
        current_key = f"model-packages/{environment}/current.txt"
        s3_client.put_object(
            Bucket=bucket_name,
            Key=current_key,
            Body=package_path.name.encode('utf-8'),
            ServerSideEncryption='aws:kms',
            SSEKMSKeyId=config["kms"]["key_alias"]
        )

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
    if args.apply and not is_aws_deploy_allowed():
        print("❌ ALLOW_AWS_DEPLOY=1 required for actual deployments")
        sys.exit(1)

    # Load configuration
    config = load_config(args.environment)

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
            config.dict(),
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
