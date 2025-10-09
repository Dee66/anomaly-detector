import os

from scripts.deploy_detector import check_budget_guardrails


def make_minimal_config():
    return {
        "environment": "test",
        "app_name": "anomaly-detector-test",
        "aws": {"region": "us-west-2"},
        "s3": {
            "model_bucket_name": "test-model-bucket",
            "data_bucket_name": "test-data-bucket",
            "log_bucket_name": "test-log-bucket",
            "compliance_bucket_name": "test-compliance-bucket",
        },
        "kms": {"key_alias": "alias/test-key"},
        "alerts": {"sns_topic_name": "test-alerts", "email_endpoints": []},
        "features": {"enable_training": False, "enable_sagemaker": False, "enable_vpc_endpoints": False},
    }


def test_budget_guard_dry_run_prints(capsys):
    config = make_minimal_config()
    config["budget_monthly"] = 0.01
    # Dry-run should not raise but should print a warning
    check_budget_guardrails(config, dry_run=True)
    captured = capsys.readouterr()
    assert "Estimated monthly cost" in captured.out or "DRY RUN: Budget estimation failed" in captured.out


def test_budget_guard_enforce_raises_on_over_budget():
    # Use a very small budget to force fail when not dry-run
    config = make_minimal_config()
    config["budget_monthly"] = 0.01
    raised = False
    try:
        check_budget_guardrails(config, dry_run=False)
    except RuntimeError:
        raised = True

    assert raised, "Expected budget guard to raise RuntimeError when estimated cost exceeds budget"
