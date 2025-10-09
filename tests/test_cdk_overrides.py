from aws_cdk import App
from aws_cdk.assertions import Template

from infra.security_detector_stack import SecurityDetectorStack


def test_bucket_name_overrides_applied():
    app = App()
    cfg = {
        "kms": {"key_alias": "alias/anomaly-detector"},
        "s3": {
            "model_bucket_name": "default-model",
            "data_bucket_name": "default-data",
            "log_bucket_name": "default-log",
            "compliance_bucket_name": "default-compliance",
        },
        "alerts": {"sns_topic_name": "anomaly-alerts", "email_endpoints": []},
        "app_name": "anomaly-detector",
        "environment": "test",
        "aws": {"region": "us-east-1"},
    }

    # Provide explicit overrides
    stack = SecurityDetectorStack(
        app,
        "TestOverrides",
        config=cfg,
        model_bucket_name="override-model",
        data_bucket_name="override-data",
        log_bucket_name="override-log",
        compliance_bucket_name="override-compliance",
    )

    template = Template.from_stack(stack)
    buckets = template.find_resources("AWS::S3::Bucket")
    names = {r.get("Properties", {}).get("BucketName") for r in buckets.values()}

    assert "override-model" in names
    assert "override-data" in names
    assert "override-log" in names
    assert "override-compliance" in names
