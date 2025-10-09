from aws_cdk import App, assertions

from infra.security_detector_stack import SecurityDetectorStack


def test_audit_table_created_when_enabled():
    config = {
        "environment": "cond-test",
        "app_name": "cond-test-app",
        "aws": {"region": "us-west-2"},
        "s3": {
            "model_bucket_name": "cond-model",
            "data_bucket_name": "cond-data",
            "log_bucket_name": "cond-log",
            "compliance_bucket_name": "cond-compliance",
        },
        "kms": {"key_alias": "alias/cond"},
        "alerts": {"sns_topic_name": "cond-alerts", "email_endpoints": []},
        "features": {"enable_training": False, "enable_sagemaker": False}
    }

    app = App()
    stack = SecurityDetectorStack(app, "CondStack", config=config, enable_audit_table=True)
    template = assertions.Template.from_stack(stack)

    # Parameter and condition exist
    template.has_parameter("EnableAuditTable", {"Type": "String"})
    template.has_condition("AuditTableCondition", {
        "Fn::Equals": [{"Ref": "EnableAuditTable"}, "true"]
    })

    # When explicitly enabled at construction time, a DynamoDB table should be present
    template.resource_count_is("AWS::DynamoDB::Table", 1)
