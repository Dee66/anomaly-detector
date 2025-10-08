"""CDK App entry point for the anomaly detector infrastructure."""

import os
import sys
from pathlib import Path

# Add src to path so we can import our config module
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aws_cdk import App, Environment
from detector.config import is_aws_deploy_allowed, load_config

from infra.security_detector_stack import SecurityDetectorStack


def main():
    """Main CDK app entry point."""
    app = App()

    # Load configuration
    env_name = os.getenv("ENVIRONMENT", "dev")
    config = load_config(env_name)

    # Safety check for AWS deployment
    if not is_aws_deploy_allowed():
        print("WARNING: ALLOW_AWS_DEPLOY not set. This is a dry-run synthesis only.")
        print("Set ALLOW_AWS_DEPLOY=1 to enable actual AWS deployments.")

    # Create environment from config
    env = Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region=config.aws.region
    )

    # Create the main stack
    SecurityDetectorStack(
        app,
        f"AnomalyDetector-{config.environment}",
        config=config.model_dump(),
        enable_training=config.features.enable_training,
        enable_sagemaker=config.features.enable_sagemaker,
        enable_vpc_endpoints=config.features.enable_vpc_endpoints,
        env=env,
        description=f"Anomaly Detector infrastructure for {config.environment} environment"
    )

    app.synth()


if __name__ == "__main__":
    main()
