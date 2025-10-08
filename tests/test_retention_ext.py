import boto3
from botocore.stub import Stubber
from src.detector.retention import RetentionPolicyManager, DataTier


def test_validate_lifecycle_policy_compliant(monkeypatch):
    # Prepare a fake config with expected retention
    cfg = {
        "data_retention": {
            "raw_security_logs": {
                "retention_years": 1,
                "lifecycle_transitions": [{"days": 30, "storage_class": "STANDARD_IA"}]
            }
        }
    }

    mgr = RetentionPolicyManager(cfg)

    # stub s3 client get_bucket_lifecycle_configuration
    stubber = Stubber(mgr.s3_client)
    lifecycle_resp = {"Rules": [{"Expiration": {"Days": 365 + 30}, "Status": "Enabled", "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}]}]}
    stubber.add_response('get_bucket_lifecycle_configuration', lifecycle_resp, {'Bucket': 'b1'})
    stubber.activate()

    result = mgr._validate_lifecycle_policy('b1', DataTier.RAW_SECURITY_LOGS)
    assert result['compliant'] is True

    stubber.deactivate()
