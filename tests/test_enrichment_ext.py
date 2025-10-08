from datetime import datetime

from src.enrichment.handler import EnrichmentHandler
from src.detector.schemas import CloudTrailEvent


def make_simple_ct_event():
    return CloudTrailEvent(
        eventVersion="1.08",
        userIdentity={"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/test"},
        eventTime="2023-01-01T00:00:00Z",
        eventSource="ec2.amazonaws.com",
        eventName="StartInstances",
        awsRegion="us-west-2",
        requestID="req-1",
        eventID="evt-1",
        eventType="AwsApiEvent",
        recipientAccountId="123456789012"
    )


def test_process_cloudtrail_event_basic():
    handler = EnrichmentHandler()
    event = make_simple_ct_event()
    out = handler.process_cloudtrail_event(event)
    assert out.log_id == event.eventID
    assert out.event_source.value == 'cloudtrail'
    assert isinstance(out.processed_at, datetime)
    # Recommendations always present (at least one entry)
    assert out.recommendations
