from aws_cdk import App, assertions

from infra.security_detector_stack import SecurityDetectorStack


def test_reconciler_lambda_gated_by_audit_condition():
    app = App()
    cfg = {
        "environment": "test",
        "app_name": "anomaly-reconciler-test",
        "aws": {"region": "us-west-2"},
        "s3": {
            "model_bucket_name": "recon-model-bucket",
            "data_bucket_name": "recon-data-bucket",
            "log_bucket_name": "recon-log-bucket",
            "compliance_bucket_name": "recon-compliance-bucket"
        },
        "kms": {"key_alias": "alias/test-key"},
        "alerts": {"sns_topic_name": "alerts", "email_endpoints": []},
        "features": {"enable_training": False, "enable_sagemaker": False, "enable_vpc_endpoints": False}
    }

    # By default (enable_audit_table=False) the reconciler function should not be present
    stack = SecurityDetectorStack(app, "NoAuditStack", config=cfg)
    template = assertions.Template.from_stack(stack)

    # Ensure no Lambda function exists whose FunctionName ends with '-reconciler'
    resources = template.to_json().get("Resources", {})
    assert not any(
        res.get("Type") == "AWS::Lambda::Function" and
        res.get("Properties", {}).get("FunctionName", "").endswith("-reconciler")
        for res in resources.values()
    )

    # When enable_audit_table=True the AuditTable and Reconciler should be present but gated by a Condition
    # Use a fresh App to avoid modifying a synthesized construct tree
    app2 = App()
    stack2 = SecurityDetectorStack(app2, "AuditStack", config=cfg, enable_audit_table=True)
    template2 = assertions.Template.from_stack(stack2)

    # The parameter and condition must exist
    template2.has_parameter("EnableAuditTable", {"Type": "String"})
    template2.has_condition("AuditTableCondition", {
        "Fn::Equals": [{"Ref": "EnableAuditTable"}, "true"]
    })

    # The reconciler function should be present as a Lambda with FunctionName containing '-reconciler' and have the Condition set
    resources2 = template2.to_json().get("Resources", {})
    reconciler_found = False
    for name, res in resources2.items():
        if res.get("Type") == "AWS::Lambda::Function":
            fn_name = res.get("Properties", {}).get("FunctionName", "")
            if fn_name.endswith("-reconciler"):
                if res.get("Condition") == "AuditTableCondition":
                    reconciler_found = True

    assert reconciler_found, "Expected a reconciler Lambda resource gated by AuditTableCondition"
