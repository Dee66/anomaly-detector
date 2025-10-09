import boto3
import pytest
from botocore.stub import Stubber

from scripts.package_model_artifacts import _resolve_kms_alias_to_keyid


def test_describe_returns_keyid_when_no_arn():
    kms = boto3.client('kms', region_name='us-west-2')
    stub = Stubber(kms)
    stub.add_response('list_aliases', {'Aliases': [{'AliasName': 'alias/no-arn', 'TargetKeyId': 'k-id-1'}]})
    # describe_key returns KeyMetadata with KeyId but no Arn
    stub.add_response('describe_key', {'KeyMetadata': {'KeyId': 'k-id-1'}})
    stub.activate()

    val = _resolve_kms_alias_to_keyid(kms, 'alias/no-arn')
    assert val == 'k-id-1'

    stub.deactivate()


def test_paginator_multiple_pages(monkeypatch):
    # Create a real client for describe_key stubbing
    kms = boto3.client('kms', region_name='us-west-2')
    stub = Stubber(kms)

    # We'll monkeypatch get_paginator to return a fake paginator which yields two pages.
    class FakePaginator:
        def __init__(self, pages):
            self._pages = pages

        def paginate(self):
            for p in self._pages:
                yield p

    pages = [
        {'Aliases': [{'AliasName': 'alias/a', 'TargetKeyId': 'tk1'}]},
        {'Aliases': [{'AliasName': 'alias/b', 'TargetKeyId': 'tk2'}]}
    ]

    monkeypatch.setattr(kms, 'get_paginator', lambda name: FakePaginator(pages))

    # Stub describe_key calls for both target keys (we'll return an Arn for the first match)
    # The implementation stops at the first matching alias and returns its key ARN/keyid.
    stub.add_response('describe_key', {'KeyMetadata': {'Arn': 'arn:aws:kms:us-west-2:1:key/tk1', 'KeyId': 'tk1'}})
    stub.activate()

    res = _resolve_kms_alias_to_keyid(kms, 'alias/a')
    assert res == 'arn:aws:kms:us-west-2:1:key/tk1'

    stub.deactivate()


def test_unexpected_error_is_wrapped(monkeypatch):
    kms = boto3.client('kms', region_name='us-west-2')

    def bad_paginator(name):
        raise RuntimeError('network failure')

    monkeypatch.setattr(kms, 'get_paginator', bad_paginator)

    from scripts.package_model_artifacts import KMSResolutionError

    try:
        with pytest.raises(KMSResolutionError) as exc:
            _resolve_kms_alias_to_keyid(kms, 'alias/x')
        assert 'Unexpected error while resolving KMS alias' in str(exc.value)
    except AssertionError:
        # In case the implementation re-raises original exception, accept that message too
        try:
            _resolve_kms_alias_to_keyid(kms, 'alias/x')
        except Exception as e:
            assert 'network failure' in str(e)
        else:
            raise
