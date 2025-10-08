import gzip
import json
from pathlib import Path

from src.detector.ingestion import S3LogIngester
from src.detector.schemas import CloudTrailEvent, VPCFlowLogRecord
import pytest


def test_parse_cloudtrail_logs_invalid_json():
    from src.detector.ingestion import S3LogIngester
    ing = S3LogIngester.__new__(S3LogIngester)
    # invalid JSON should result in empty event list
    events = S3LogIngester.parse_cloudtrail_logs(ing, "not a json")
    assert events == []


def test_parse_vpc_flow_logs_insufficient_fields():
    content = "1 123456789012 eni-123 10.0.0.1 10.0.0.2 80 443 6 10 100 1600000000 1600003600 ACCEPT OK\nshort line"
    ing = S3LogIngester.__new__(S3LogIngester)
    # call parse_vpc_flow_logs directly
    records = S3LogIngester.parse_vpc_flow_logs(ing, content)
    assert isinstance(records, list)
    # first record parsed, second line insufficient -> only 1 record
    assert len(records) == 1


def test_gzipped_content_handling(tmp_path):
    # create gzipped cloudtrail-like JSON
    records = [{
        "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/test"},
        "eventTime": "2023-01-01T00:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "StartInstances",
        "awsRegion": "us-west-2",
        "requestID": "req-1",
        "eventID": "evt-1",
        "eventType": "AwsApiEvent",
        "recipientAccountId": "123456789012"
    }]

    raw = json.dumps({"Records": records}).encode('utf-8')
    gz = tmp_path / "test.json.gz"
    with gzip.open(str(gz), 'wb') as f:
        f.write(raw)

    # read and decode using gzip module directly to simulate S3 read
    with gzip.open(str(gz), 'rb') as f:
        content = f.read().decode('utf-8')

    from src.detector.ingestion import S3LogIngester
    # use parse_cloudtrail_logs directly
    ing = S3LogIngester.__new__(S3LogIngester)
    events = S3LogIngester.parse_cloudtrail_logs(ing, content)
    assert len(events) == 1
