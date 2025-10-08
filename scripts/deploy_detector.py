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
    print("💰 Checking budget guardrails...")

    if dry_run:
        print("DRY RUN: Would check estimated costs against budget limits")
        print("DRY RUN: Would validate resource quotas and limits")
    else:
        # TODO: Implement actual budget checks
        print("  ⚠️  Budget checks not yet implemented")

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

    args = parser.parse_args()

    # Safety checks
    dry_run = not args.apply
    if args.apply and not is_aws_deploy_allowed():
        print("❌ ALLOW_AWS_DEPLOY=1 required for actual deployments")
        sys.exit(1)

    # Load configuration
    config = load_config(args.environment)

    try:
        print(f"🎯 Deployment target: {args.environment}")
        print(f"🔒 Mode: {'APPLY' if not dry_run else 'DRY-RUN'}")

        # Validate prerequisites
        validate_prerequisites(config.dict())

        # Check budget guardrails (unless skipped)
        if not args.skip_budget_check:
            check_budget_guardrails(config.dict(), dry_run=dry_run)

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
