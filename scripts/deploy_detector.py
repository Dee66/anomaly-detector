"""Deploy the anomaly detector infrastructure and services.

This script orchestrates the deployment of the entire anomaly detector system.
It defaults to dry-run mode and requires explicit --apply flag for actual deployment.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

# Add src to path for config access
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detector.config import is_aws_deploy_allowed, load_config
from deployer_guard import require_deploy_allowed_or_exit

# Import packaging helpers so deploy flow can package artifacts before deploy
try:
    from scripts.package_model_artifacts import (
        validate_model_artifacts,
        create_model_package,
        upload_to_s3,
    )
except Exception:
    # If packaging helpers can't be imported (test stubs), we'll raise at runtime when used
    validate_model_artifacts = None
    create_model_package = None
    upload_to_s3 = None


def run_command(cmd: list, dry_run: bool = True, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command with optional dry-run mode.

    Args:
        cmd: Command to run as list of strings
        dry_run: If True, just print the command
        check: If True, raise exception on non-zero exit

    Returns:
        CompletedProcess result
    """
    if dry_run:
        print(f"DRY RUN: {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, 0)

    print(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def cdk_synth(environment: str, dry_run: bool = True) -> None:
    """Synthesize CDK templates.

    Args:
        environment: Target environment
        dry_run: If True, just print what would be done
    """
    print(f"\n📋 Synthesizing CDK templates for {environment}...")

    env = os.environ.copy()
    env["ENVIRONMENT"] = environment

    cmd = [
        "cdk", "synth",
        "--app", "python infra/app.py",
        "--no-staging",
        "--strict"
    ]

    if not dry_run:
        os.environ.update(env)

    result = run_command(cmd, dry_run=dry_run)

    if not dry_run and result.returncode != 0:
        print(f"❌ CDK synth failed: {result.stderr}")
        sys.exit(1)

    print("✅ CDK synthesis complete")


def cdk_deploy(environment: str, dry_run: bool = True) -> None:
    """Deploy CDK stack.

    Args:
        environment: Target environment
        dry_run: If True, just print what would be done
    """
    print(f"\n🚀 Deploying infrastructure for {environment}...")

    env = os.environ.copy()
    env["ENVIRONMENT"] = environment

    cmd = [
        "cdk", "deploy",
        "--app", "python infra/app.py",
        "--require-approval", "never",
        "--strict"
    ]

    if not dry_run:
        os.environ.update(env)

    result = run_command(cmd, dry_run=dry_run)

    if not dry_run and result.returncode != 0:
        print(f"❌ CDK deploy failed: {result.stderr}")
        sys.exit(1)

    print("✅ Infrastructure deployment complete")


def validate_prerequisites(config: Dict[str, Any]) -> None:
    """Validate that prerequisites are met for deployment.

    Args:
        config: Configuration dictionary

    Raises:
        RuntimeError: If prerequisites are not met
    """
    print("🔍 Validating deployment prerequisites...")

    # Check AWS CLI
    try:
        result = subprocess.run(["aws", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("AWS CLI not found")
        print("  ✅ AWS CLI available")
    except FileNotFoundError:
        raise RuntimeError("AWS CLI not installed")

    # Check CDK CLI
    try:
        result = subprocess.run(["cdk", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError("CDK CLI not found")
        print("  ✅ CDK CLI available")
    except FileNotFoundError:
        raise RuntimeError("CDK CLI not installed")

    # Check AWS credentials
    aws_profile = config.get("aws", {}).get("profile")
    if aws_profile:
        env = os.environ.copy()
        env["AWS_PROFILE"] = aws_profile

        try:
            result = subprocess.run(
                ["aws", "sts", "get-caller-identity"],
                env=env,
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                raise RuntimeError(f"AWS credentials not valid for profile: {aws_profile}")
            print(f"  ✅ AWS credentials valid for profile: {aws_profile}")
        except Exception as e:
            raise RuntimeError(f"AWS credentials check failed: {e}")

    print("✅ Prerequisites validation complete")


def check_budget_guardrails(config: Dict[str, Any], dry_run: bool = True) -> None:
    """Check budget and cost guardrails.

    Args:
        config: Configuration dictionary
        dry_run: If True, just print what would be checked
    """
    print("💰 Checking budget guardrails (PaS)...")

    # Determine budget threshold: config override or environment or default
    budget = None
    # Parse budget threshold from config or environment, default to $100/mo
    budget = None
    try:
        bm = config.get("budget_monthly")
        if bm is not None:
            budget = float(bm)
    except Exception:
        budget = None

    if budget is None:
        import os
        try:
            budget = float(os.getenv("BUDGET_THRESHOLD", "100.0"))
        except Exception:
            budget = 100.0

    print(f"  ➤ Budget threshold (monthly estimate): ${budget:.2f}")

    # If dry_run, just estimate and print; otherwise enforce
    try:
        # Instantiate the CDK stack in-process to inspect resources
        from aws_cdk import App, assertions
        from infra.security_detector_stack import SecurityDetectorStack

        app = App()
        # Mirror feature flags if present to capture optional resources in estimate
        stack = SecurityDetectorStack(app, "BudgetEstimateStack", config=config)
        template = assertions.Template.from_stack(stack).to_json()

        # Heuristic per-resource monthly costs (very conservative/sample values)
        cost_map = {
            "AWS::S3::Bucket": 1.0,           # per bucket baseline
            "AWS::KMS::Key": 3.0,            # per CMK
            "AWS::Lambda::Function": 5.0,    # per function baseline
            "AWS::DynamoDB::Table": 20.0,    # on-demand table baseline
            "AWS::SNS::Topic": 1.0,          # topic baseline
            "AWS::EC2::NatGateway": 90.0,    # NAT gateway (expensive)
            "AWS::EC2::VPCEndpoint": 10.0,   # per endpoint
            "AWS::SageMaker::Model": 500.0,  # heavy resource placeholder
        }

        # Count resources
        resources = template.get("Resources", {})
        estimate = 0.0
        counts = {}
        for name, res in resources.items():
            rtype = res.get("Type")
            counts[rtype] = counts.get(rtype, 0) + 1

        for rtype, count in counts.items():
            estimate += cost_map.get(rtype, 0.0) * count

        print("  ➤ Resource counts:")
        for rtype, count in sorted(counts.items()):
            print(f"    - {rtype}: {count}")

        print(f"  ➤ Estimated monthly cost (heuristic): ${estimate:.2f}")

        if estimate > budget:
            msg = f"Estimated monthly cost ${estimate:.2f} exceeds budget ${budget:.2f}"
            if dry_run:
                print(f"WARNING: {msg} (dry-run)")
            else:
                raise RuntimeError(msg)
        else:
            print("  ✅ Estimated cost within budget")

    except Exception as e:
        # If anything goes wrong during estimation, fail closed when not dry-run
        if dry_run:
            print(f"DRY RUN: Budget estimation failed: {e}")
        else:
            raise

    print("✅ Budget guardrails check complete")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Deploy anomaly detector infrastructure and services"
    )
    parser.add_argument(
        "--environment",
        default=os.getenv("ENVIRONMENT", "dev"),
        help="Target environment (default: dev)"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually perform the deployment (default: dry-run)"
    )
    parser.add_argument(
        "--skip-budget-check",
        action="store_true",
        help="Skip budget and cost validation"
    )
    parser.add_argument(
        "--synth-only",
        action="store_true",
        help="Only synthesize templates, don't deploy"
    )
    parser.add_argument(
        "--package-model",
        action="store_true",
        help="Package model artifacts and upload before deployment (dry-run by default)"
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path("./model"),
        help="Directory containing model artifacts to package (default: ./model)"
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Version string for the model package (default: timestamp from packager)"
    )

    args = parser.parse_args()

    # Safety checks
    dry_run = not args.apply
    if args.apply:
        # Require stricter confirmation before allowing real deployments
        require_deploy_allowed_or_exit(
            "Deployment requested. Confirm by setting DEPLOY_CONFIRM=I_ACCEPT_COSTS"
        )

    # Load configuration
    config = load_config(args.environment)

    try:
        print(f"🎯 Deployment target: {args.environment}")
        print(f"🔒 Mode: {'APPLY' if not dry_run else 'DRY-RUN'}")

        # Validate prerequisites
        validate_prerequisites(config.model_dump())

        # Optional packaging step: create and upload model artifacts before deploy
        if args.package_model:
            if create_model_package is None or upload_to_s3 is None or validate_model_artifacts is None:
                raise RuntimeError("Packaging helpers not available; ensure scripts/package_model_artifacts.py is importable")

            # Validate model artifacts
            validate_model_artifacts(args.model_dir)

            # Create package
            out_dir = Path("./dist")
            out_dir.mkdir(parents=True, exist_ok=True)
            version = args.version or None
            package_path = create_model_package(args.model_dir, out_dir, version or "auto")

            # Upload (dry-run unless --apply)
            upload_to_s3(
                package_path,
                config.model_dump(),
                args.version or "auto",
                dry_run=dry_run,
            )

        # Check budget guardrails (unless skipped)
        if not args.skip_budget_check:
            check_budget_guardrails(config.model_dump(), dry_run=dry_run)

        # CDK synthesis
        cdk_synth(args.environment, dry_run=dry_run)

        # CDK deployment (unless synth-only)
        if not args.synth_only:
            cdk_deploy(args.environment, dry_run=dry_run)

        if dry_run:
            print("\n💡 Use --apply flag to perform actual deployment")
        else:
            print("\n🎉 Deployment complete!")

    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
