from aws_cdk import App, assertions

from infra.security_detector_stack import SecurityDetectorStack


def test_reconciler_permission_boundary_and_schedule():
    app = App()
    cfg = {
        "environment": "test",
        "app_name": "anomaly-reconciler-test",
        "aws": {"region": "us-west-2"},
        "s3": {
            "model_bucket_name": "recon-model-bucket",
            "data_bucket_name": "recon-data-bucket",
            "log_bucket_name": "recon-log-bucket",
            "compliance_bucket_name": "recon-compliance-bucket",
        },
        "kms": {"key_alias": "alias/test-key"},
        "alerts": {"sns_topic_name": "alerts", "email_endpoints": []},
        "features": {"enable_training": False, "enable_sagemaker": False, "enable_vpc_endpoints": False},
    }

    stack = SecurityDetectorStack(app, "AuditStack", config=cfg, enable_audit_table=True)
    template = assertions.Template.from_stack(stack).to_json()

    resources = template.get("Resources", {})

    # Verify there is a role resource (the function role) and that at least one role has a PermissionsBoundary set
    role_with_pb = any(
        res.get("Properties", {}).get("PermissionsBoundary")
        for res in resources.values()
        if res.get("Type") == "AWS::IAM::Role"
    )

    assert role_with_pb, "Expected at least one IAM Role to have a PermissionsBoundary property set"

    # Verify EventBridge Rule exists and is gated by AuditTableCondition
    rule_found = any(
        res.get("Condition") == "AuditTableCondition"
        for res in resources.values()
        if res.get("Type") == "AWS::Events::Rule"
    )

    assert rule_found, "Expected an EventBridge Rule gated by AuditTableCondition"