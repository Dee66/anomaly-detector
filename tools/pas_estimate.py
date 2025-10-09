"""Estimate stack cost by synthesizing the CDK stack and computing resource heuristics.

This script is intended to be run in CI for quick PaS checks. It prints a JSON object with
`estimated_monthly_cost` and `counts` for resource types. It exits 0 on success.
"""
import json
import sys

from aws_cdk import App, assertions

from infra.security_detector_stack import SecurityDetectorStack


def estimate(config):
    app = App()
    stack = SecurityDetectorStack(app, "BudgetEstimateStack", config=config)
    template = assertions.Template.from_stack(stack).to_json()

    cost_map = {
        "AWS::S3::Bucket": 1.0,
        "AWS::KMS::Key": 3.0,
        "AWS::Lambda::Function": 5.0,
        "AWS::DynamoDB::Table": 20.0,
        "AWS::SNS::Topic": 1.0,
        "AWS::EC2::NatGateway": 90.0,
        "AWS::EC2::VPCEndpoint": 10.0,
        "AWS::SageMaker::Model": 500.0,
    }

    resources = template.get("Resources", {})
    counts = {}
    estimate = 0.0
    for name, res in resources.items():
        rtype = res.get("Type")
        counts[rtype] = counts.get(rtype, 0) + 1

    for rtype, count in counts.items():
        estimate += cost_map.get(rtype, 0.0) * count

    out = {"estimated_monthly_cost": estimate, "counts": counts}
    print(json.dumps(out))


if __name__ == "__main__":
    # Expect a JSON string config passed as the first arg; otherwise use a minimal default
    if len(sys.argv) > 1:
        cfg = json.loads(sys.argv[1])
    else:
        cfg = {
            "environment": "ci",
            "app_name": "anomaly-detector-ci",
            "aws": {"region": "us-west-2"},
            "s3": {
                "model_bucket_name": "ci-model-bucket",
                "data_bucket_name": "ci-data-bucket",
                "log_bucket_name": "ci-log-bucket",
                "compliance_bucket_name": "ci-compliance-bucket",
            },
            "kms": {"key_alias": "alias/ci-key"},
            "alerts": {"sns_topic_name": "ci-alerts", "email_endpoints": []},
            "features": {"enable_training": False, "enable_sagemaker": False, "enable_vpc_endpoints": False},
        }

    estimate(cfg)
