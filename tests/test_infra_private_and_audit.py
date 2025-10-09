import json
from aws_cdk import App, assertions

from infra.security_detector_stack import SecurityDetectorStack


def _base_config():
    return {
        "environment": "ci-test",
        "app_name": "ci-test-app",
        "aws": {"region": "us-west-2"},
        "s3": {
            "model_bucket_name": "ci-model",
            "data_bucket_name": "ci-data",
            "log_bucket_name": "ci-log",
            "compliance_bucket_name": "ci-compliance",
        },
        "kms": {"key_alias": "alias/ci"},
        "alerts": {"sns_topic_name": "ci-alerts", "email_endpoints": []},
        "features": {"enable_training": False, "enable_sagemaker": False}
    }


def test_enforce_private_deployment_creates_endpoints_and_no_nat():
    config = _base_config()
    app = App()

    # Force private-only VPC and request endpoints
    stack = SecurityDetectorStack(app, "PrivateStack", config=config, enforce_private_deployment=True, enable_vpc_endpoints=True)
    template = assertions.Template.from_stack(stack)

    # No NAT Gateways should be created in private-only deployments
    template.resource_count_is("AWS::EC2::NatGateway", 0)

    # Expect the set of VPC endpoints to be added (S3 + 4 interface endpoints)
    template.resource_count_is("AWS::EC2::VPCEndpoint", 5)


def test_audit_table_resource_has_condition():
    config = _base_config()
    app = App()
    stack = SecurityDetectorStack(app, "AuditStack", config=config, enable_audit_table=True)
    template = assertions.Template.from_stack(stack)

    # There should be exactly one DynamoDB table resource
    template.resource_count_is("AWS::DynamoDB::Table", 1)

    # Inspect the synthesized template to confirm the table has a Condition key
    tpl = template.to_json()
    # Template.to_json() may return a dict (older/newer versions); handle both
    if isinstance(tpl, dict):
        data = tpl
    else:
        data = json.loads(tpl)
    resources = data.get("Resources", {})
    found = False
    for name, res in resources.items():
        if res.get("Type") == "AWS::DynamoDB::Table":
            assert res.get("Condition") == "AuditTableCondition"
            found = True
    assert found, "No DynamoDB::Table resource found in template"
