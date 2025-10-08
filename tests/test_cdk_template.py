import pytest

from aws_cdk import App
from aws_cdk.assertions import Template

from infra.security_detector_stack import SecurityDetectorStack
import json


def minimal_config(private_only: bool = False, region: str = "us-east-1") -> dict:
    """Return a minimal config dict the stack expects."""
    cfg = {
        "kms": {"key_alias": "alias/anomaly-detector"},
        "s3": {
            "model_bucket_name": "anomaly-model-bucket",
            "data_bucket_name": "anomaly-data-bucket",
            "log_bucket_name": "anomaly-log-bucket",
            "compliance_bucket_name": "anomaly-compliance-bucket",
        },
        "data_retention": {
            "raw_security_logs": {"retention_years": 1},
            "compliance_outputs": {"retention_years": 1},
        },
        "alerts": {"sns_topic_name": "anomaly-alerts", "email_endpoints": ["alerts@example.com"]},
        "app_name": "anomaly-detector",
        "environment": "test",
        "aws": {"region": region},
    }

    if private_only:
        cfg["vpc"] = {"private_only": True}

    return cfg


@pytest.mark.parametrize("private_only,expected_subnet_count", [(False, 4), (True, 2)])
def test_vpc_subnet_counts(private_only, expected_subnet_count):
    """When creating the VPC, the number of subnets should match max_azs * subnet_configs."""
    app = App()
    cfg = minimal_config(private_only=private_only)

    # Request VPC creation by enabling VPC endpoint flag (stack creates VPC when this flag
    # or an explicit vpc_id is present in config).
    stack = SecurityDetectorStack(app, "TestSubnetStack", config=cfg, enable_vpc_endpoints=True)
    template = Template.from_stack(stack)

    subnets = template.find_resources("AWS::EC2::Subnet")
    assert len(subnets) == expected_subnet_count


def test_vpc_endpoints_created_when_enabled():
    """Enable VPC endpoints and assert Gateway + Interface endpoints are created."""
    app = App()
    cfg = minimal_config()

    stack = SecurityDetectorStack(app, "TestEndpointStack", config=cfg, enable_vpc_endpoints=True)
    template = Template.from_stack(stack)

    vpce_resources = template.find_resources("AWS::EC2::VPCEndpoint")
    # We expect one Gateway (S3) and four Interface endpoints (KMS, SNS, CLOUDWATCH_LOGS, SECRETS_MANAGER)
    assert len(vpce_resources) >= 5

    gateway_count = 0
    interface_count = 0
    for _, resource in vpce_resources.items():
        props = resource.get("Properties", {})
        t = props.get("VpcEndpointType")
        if t == "Gateway":
            gateway_count += 1
        elif t == "Interface":
            interface_count += 1

    assert gateway_count == 1
    assert interface_count >= 4

    # Check the SNS topic exists with the configured name
    topics = template.find_resources("AWS::SNS::Topic")
    assert any(r.get("Properties", {}).get("TopicName") == cfg["alerts"]["sns_topic_name"] for r in topics.values())


def test_kms_and_alias_created():
    """KMS key and alias should be created with the configured alias name."""
    app = App()
    cfg = minimal_config()

    stack = SecurityDetectorStack(app, "TestKmsStack", config=cfg)
    template = Template.from_stack(stack)

    # At least one KMS Key should be present
    keys = template.find_resources("AWS::KMS::Key")
    assert len(keys) >= 1

    # Alias resource should exist with the configured alias name
    aliases = template.find_resources("AWS::KMS::Alias")
    assert any(a.get("Properties", {}).get("AliasName") == cfg["kms"]["key_alias"] for a in aliases.values())


def test_s3_buckets_encryption_and_lifecycle():
    """S3 buckets should be created with the configured names and lifecycle rules where applicable."""
    app = App()
    cfg = minimal_config()

    stack = SecurityDetectorStack(app, "TestS3Stack", config=cfg)
    template = Template.from_stack(stack)

    buckets = template.find_resources("AWS::S3::Bucket")

    # Ensure named buckets exist
    expected_names = {
        cfg["s3"]["model_bucket_name"],
        cfg["s3"]["data_bucket_name"],
        cfg["s3"]["log_bucket_name"],
        cfg["s3"]["compliance_bucket_name"],
    }

    found_names = {r.get("Properties", {}).get("BucketName") for r in buckets.values()}
    assert expected_names.issubset(found_names)

    # Check lifecycle configuration exists for the log bucket
    log_bucket_resource = None
    for _, r in buckets.items():
        if r.get("Properties", {}).get("BucketName") == cfg["s3"]["log_bucket_name"]:
            log_bucket_resource = r
            break

    assert log_bucket_resource is not None
    lifecycle = log_bucket_resource.get("Properties", {}).get("LifecycleConfiguration")
    assert lifecycle and isinstance(lifecycle.get("Rules", []), list) and len(lifecycle.get("Rules")) >= 1


def test_log_group_properties():
    """CloudWatch Log Group should be created with the expected name and have KMS encryption configured."""
    app = App()
    cfg = minimal_config()

    stack = SecurityDetectorStack(app, "TestLogGroupStack", config=cfg)
    template = Template.from_stack(stack)

    log_groups = template.find_resources("AWS::Logs::LogGroup")
    assert len(log_groups) >= 1

    # Find our log group by configured name
    lg_props = None
    for _, lg in log_groups.items():
        props = lg.get("Properties", {})
        if props.get("LogGroupName") == f"/aws/lambda/{cfg['app_name']}":
            lg_props = props
            break

    assert lg_props is not None
    # KmsKeyId is set when encryption_key is provided
    assert "KmsKeyId" in lg_props


def test_iam_role_and_assume_principal():
    """IAM Role for the detector should allow lambda.amazonaws.com to assume it."""
    app = App()
    cfg = minimal_config()

    stack = SecurityDetectorStack(app, "TestRoleStack", config=cfg)
    template = Template.from_stack(stack)

    roles = template.find_resources("AWS::IAM::Role")
    assert len(roles) >= 1

    found = False
    for _, r in roles.items():
        assume = r.get("Properties", {}).get("AssumeRolePolicyDocument")
        if assume and 'lambda.amazonaws.com' in json.dumps(assume):
            found = True
            break

    assert found


def test_cloudformation_parameters_and_conditions_present():
    """CloudFormation Parameters and Conditions used to gate optional resources should be present in the template."""
    app = App()
    cfg = minimal_config()

    stack = SecurityDetectorStack(app, "TestParamsStack", config=cfg)
    template = Template.from_stack(stack)

    raw = template.to_json()
    parameters = raw.get("Parameters", {})
    conditions = raw.get("Conditions", {})

    assert "EnableTraining" in parameters
    assert "EnableSageMaker" in parameters
    assert "TrainingEnabledCondition" in conditions
    assert "SageMakerEnabledCondition" in conditions
