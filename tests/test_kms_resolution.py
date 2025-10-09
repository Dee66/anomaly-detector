import boto3
from botocore.stub import Stubber
import pytest

from scripts.package_model_artifacts import _resolve_kms_alias_to_keyid


def test_resolve_kms_alias_not_found(monkeypatch):
    kms = boto3.client('kms', region_name='us-west-2')
    stub = Stubber(kms)
    # Return empty list for aliases
    stub.add_response('list_aliases', {'Aliases': []})
    stub.activate()

    from scripts.package_model_artifacts import KMSResolutionError

    with pytest.raises(KMSResolutionError) as exc:
        _resolve_kms_alias_to_keyid(kms, 'alias/does-not-exist')

    assert 'could not be found' in str(exc.value)
    stub.deactivate()


def test_resolve_kms_alias_with_target_but_describe_fails(monkeypatch):
    kms = boto3.client('kms', region_name='us-west-2')
    stub = Stubber(kms)
    stub.add_response('list_aliases', {'Aliases': [{'AliasName': 'alias/bad', 'TargetKeyId': '1234'}]})
    # describe_key will error
    stub.add_client_error('describe_key', service_error_code='NotFoundException')
    stub.activate()

    from scripts.package_model_artifacts import KMSResolutionError

    with pytest.raises(KMSResolutionError) as exc:
        _resolve_kms_alias_to_keyid(kms, 'alias/bad')

    assert 'Failed to describe KMS key' in str(exc.value)
    stub.deactivate()
