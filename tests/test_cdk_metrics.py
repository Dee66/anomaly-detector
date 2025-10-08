from aws_cdk import App
from aws_cdk.assertions import Template

from infra.security_detector_stack import SecurityDetectorStack


def test_error_metric_filter_and_alarm_present():
    app = App()
    cfg = {
        "kms": {"key_alias": "alias/anomaly-detector"},
        "s3": {
            "model_bucket_name": "anomaly-model-bucket",
            "data_bucket_name": "anomaly-data-bucket",
            "log_bucket_name": "anomaly-log-bucket",
            "compliance_bucket_name": "anomaly-compliance-bucket",
        },
        "alerts": {"sns_topic_name": "anomaly-alerts", "email_endpoints": []},
        "app_name": "anomaly-detector",
        "environment": "test",
        "aws": {"region": "us-east-1"},
    }

    stack = SecurityDetectorStack(app, "TestMetricsStack", config=cfg)
    template = Template.from_stack(stack)

    # Metric filter resource (CloudWatch Logs Metric Filter)
    filters = template.find_resources("AWS::Logs::MetricFilter")
    assert len(filters) >= 1

    # CloudWatch Alarm resource should be present
    alarms = template.find_resources("AWS::CloudWatch::Alarm")
    assert len(alarms) >= 1
