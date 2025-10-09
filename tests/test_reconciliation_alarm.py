from aws_cdk import App, assertions
import pytest

from infra.security_detector_stack import SecurityDetectorStack


def test_reconciliation_alarm_exists_and_wired_to_sns():
    app = App()
    cfg = {
        "environment": "test",
        "app_name": "anomaly-detector-test",
        "aws": {"region": "us-west-2"},
        "s3": {
            "model_bucket_name": "test-model-bucket",
            "data_bucket_name": "test-data-bucket",
            "log_bucket_name": "test-log-bucket",
            "compliance_bucket_name": "test-compliance-bucket"
        },
        "kms": {"key_alias": "alias/test-key"},
        "alerts": {"sns_topic_name": "test-alerts", "email_endpoints": []},
        "features": {"enable_training": False, "enable_sagemaker": False, "enable_vpc_endpoints": False}
    }

    stack = SecurityDetectorStack(app, "AlarmStack", config=cfg)
    template = assertions.Template.from_stack(stack)

    # There should be an Alarm resource for reconciliation
    template.resource_count_is("AWS::CloudWatch::Alarm", 2)  # ErrorAlarm + ReconciliationMissingAlarm

    # Ensure at least one alarm has non-empty AlarmActions (could be Fn::GetAtt, Ref, or direct ARN)
    resources = template.to_json().get("Resources", {})
    alarm_has_action = False
    for res in resources.values():
        if res.get("Type") == "AWS::CloudWatch::Alarm":
            props = res.get("Properties", {})
            actions = props.get("AlarmActions", []) or []
            if actions:
                alarm_has_action = True

    assert alarm_has_action, "Expected at least one CloudWatch Alarm to have an AlarmAction attached"
