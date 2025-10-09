import boto3
import pytest
from botocore.stub import Stubber

from scripts.package_model_artifacts import _resolve_kms_alias_to_keyid


def test_resolve_kms_alias_success():
    kms = boto3.client('kms', region_name='us-west-2')
    stub = Stubber(kms)
    # list_aliases returns matching alias with a TargetKeyId
    stub.add_response('list_aliases', {'Aliases': [{'AliasName': 'alias/my-key', 'TargetKeyId': 'abcd-1234'}]})
    # describe_key returns KeyMetadata with Arn and KeyId (required shape)
    stub.add_response('describe_key', {'KeyMetadata': {'Arn': 'arn:aws:kms:us-west-2:111122223333:key/abcd-1234', 'KeyId': 'abcd-1234'}})
    stub.activate()

    arn = _resolve_kms_alias_to_keyid(kms, 'alias/my-key')
    assert arn == 'arn:aws:kms:us-west-2:111122223333:key/abcd-1234'

    stub.deactivate()


def test_resolve_kms_alias_alias_without_target():
    kms = boto3.client('kms', region_name='us-west-2')
    stub = Stubber(kms)
    # alias exists but lacks TargetKeyId
    stub.add_response('list_aliases', {'Aliases': [{'AliasName': 'alias/no-target'}]})
    stub.activate()

    from scripts.package_model_artifacts import KMSResolutionError

    try:
        with pytest.raises(KMSResolutionError) as exc:
            _resolve_kms_alias_to_keyid(kms, 'alias/no-target')
        assert 'has no TargetKeyId' in str(exc.value)
    finally:
        stub.deactivate()


def test_resolve_kms_alias_passthrough_non_alias():
    # If the input does not start with 'alias/' it should be returned as-is
    kms = boto3.client('kms', region_name='us-west-2')
    val = 'arn:aws:kms:us-west-2:111122223333:key/abcd-1234'
    assert _resolve_kms_alias_to_keyid(kms, val) == val
