"""Tests for security log schemas and data models."""

# Add src to path for imports
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detector.schemas import (
    AnomalyScore,
    CloudTrailEvent,
    CloudTrailUserIdentity,
    ComplianceOutput,
    EntityType,
    EventSource,
    ExtractedEntity,
    ProcessingResult,
    RiskLevel,
    VPCFlowLogRecord,
    get_all_entity_patterns,
    get_entity_patterns,
)


class TestCloudTrailEvent:
    """Test CloudTrail event parsing and validation."""

    def test_cloudtrail_event_basic(self):
        """Test basic CloudTrail event creation."""
        user_identity = CloudTrailUserIdentity(
            type="IAMUser",
            principalId="AIDACKCEVSQ6C2EXAMPLE",
            arn="arn:aws:iam::123456789012:user/johndoe",
            accountId="123456789012",
            userName="johndoe"
        )

        event = CloudTrailEvent(
            eventVersion="1.08",
            userIdentity=user_identity,
            eventTime=datetime.now(timezone.utc),
            eventSource="s3.amazonaws.com",
            eventName="GetObject",
            awsRegion="us-east-1",
            sourceIPAddress="203.0.113.12",
            requestID="12345678-1234-1234-1234-123456789012",
            eventID="87654321-4321-4321-4321-210987654321",
            eventType="AwsApiCall",
            recipientAccountId="123456789012"
        )

        assert event.eventName == "GetObject"
        assert event.userIdentity.userName == "johndoe"
        assert event.awsRegion == "us-east-1"
        assert event.sourceIPAddress == "203.0.113.12"

    def test_cloudtrail_event_from_json(self):
        """Test parsing CloudTrail event from JSON."""
        json_data = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROACKCEVSQ6C2EXAMPLE:session-name",
                "arn": "arn:aws:sts::123456789012:assumed-role/ExampleRole/session-name",
                "accountId": "123456789012"
            },
            "eventTime": "2023-01-01T12:00:00Z",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "RunInstances",
            "awsRegion": "us-west-2",
            "sourceIPAddress": "10.0.1.100",
            "requestID": "12345678-1234-1234-1234-123456789012",
            "eventID": "87654321-4321-4321-4321-210987654321",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012"
        }

        event = CloudTrailEvent(**json_data)
        assert event.eventName == "RunInstances"
        assert event.userIdentity.type == "AssumedRole"
        assert isinstance(event.eventTime, datetime)


class TestVPCFlowLogRecord:
    """Test VPC Flow Log parsing and validation."""

    def test_vpc_flow_log_basic(self):
        """Test basic VPC Flow Log creation."""
        flow_log = VPCFlowLogRecord(
            version=2,
            account_id="123456789012",
            interface_id="eni-1235b8ca123456789",
            srcaddr="172.31.16.139",
            dstaddr="172.31.16.21",
            srcport=20641,
            dstport=22,
            protocol=6,
            packets=20,
            bytes=4249,
            windowstart=datetime.now(timezone.utc),
            windowend=datetime.now(timezone.utc),
            action="ACCEPT",
            flowlogstatus="OK"
        )

        assert flow_log.srcaddr == "172.31.16.139"
        assert flow_log.dstport == 22
        assert flow_log.action == "ACCEPT"

    def test_vpc_flow_log_timestamp_parsing(self):
        """Test parsing VPC Flow Log with Unix timestamps."""
        flow_data = {
            "version": 2,
            "account_id": "123456789012",
            "interface_id": "eni-1235b8ca123456789",
            "srcaddr": "172.31.16.139",
            "dstaddr": "172.31.16.21",
            "srcport": 20641,
            "dstport": 22,
            "protocol": 6,
            "packets": 20,
            "bytes": 4249,
            "windowstart": 1672531200,  # Unix timestamp
            "windowend": 1672531260,    # Unix timestamp
            "action": "ACCEPT",
            "flowlogstatus": "OK"
        }

        flow_log = VPCFlowLogRecord(**flow_data)
        assert isinstance(flow_log.windowstart, datetime)
        assert isinstance(flow_log.windowend, datetime)


class TestExtractedEntity:
    """Test entity extraction data models."""

    def test_extracted_entity_creation(self):
        """Test creating an extracted entity."""
        entity = ExtractedEntity(
            entity_id="arn:aws:iam::123456789012:role/MyRole",
            entity_type=EntityType.IAM_ROLE_ARN,
            confidence=0.95,
            context="User assumed role arn:aws:iam::123456789012:role/MyRole for access",
            source_field="userIdentity.arn"
        )

        assert entity.entity_type == EntityType.IAM_ROLE_ARN
        assert entity.confidence == 0.95
        assert "MyRole" in entity.entity_id

    def test_entity_confidence_validation(self):
        """Test that confidence score is validated."""
        with pytest.raises(ValueError):
            ExtractedEntity(
                entity_id="test",
                entity_type=EntityType.IP_ADDRESS,
                confidence=1.5,  # Invalid: > 1.0
                context="test",
                source_field="test"
            )


class TestAnomalyScore:
    """Test anomaly scoring data models."""

    def test_anomaly_score_creation(self):
        """Test creating an anomaly score."""
        score = AnomalyScore(
            score=7.5,
            factors=["unusual_time", "external_ip", "privilege_escalation"],
            threshold=3.0,
            is_anomaly=True
        )

        assert score.score == 7.5
        assert score.is_anomaly is True
        assert len(score.factors) == 3

    def test_anomaly_score_validation(self):
        """Test anomaly score validation."""
        with pytest.raises(ValueError):
            AnomalyScore(
                score=15.0,  # Invalid: > 10.0
                factors=[],
                threshold=3.0,
                is_anomaly=True
            )


class TestComplianceOutput:
    """Test compliance output data model."""

    def test_compliance_output_complete(self):
        """Test creating a complete compliance output."""
        entity = ExtractedEntity(
            entity_id="10.0.1.100",
            entity_type=EntityType.IP_ADDRESS,
            confidence=0.99,
            context="Source IP: 10.0.1.100",
            source_field="sourceIPAddress"
        )

        anomaly = AnomalyScore(
            score=5.5,
            factors=["external_access"],
            threshold=3.0,
            is_anomaly=True
        )

        output = ComplianceOutput(
            log_id="event-12345",
            event_source=EventSource.CLOUDTRAIL,
            timestamp=datetime.now(timezone.utc),
            entities=[entity],
            risk_score=6.0,
            risk_level=RiskLevel.MEDIUM,
            anomaly_scores=[anomaly],
            recommendations=["Review external IP access"],
            requires_attention=True
        )

        assert output.risk_level == RiskLevel.MEDIUM
        assert len(output.entities) == 1
        assert len(output.anomaly_scores) == 1
        assert output.requires_attention is True


class TestEntityPatterns:
    """Test entity regex patterns."""

    def test_iam_role_arn_patterns(self):
        """Test IAM role ARN pattern matching."""
        patterns = get_entity_patterns(EntityType.IAM_ROLE_ARN)
        assert len(patterns) > 0

        # Test pattern exists for IAM roles
        iam_pattern = patterns[0]
        assert "arn:aws:iam" in iam_pattern
        assert "role" in iam_pattern

    def test_ip_address_patterns(self):
        """Test IP address pattern matching."""
        patterns = get_entity_patterns(EntityType.IP_ADDRESS)
        assert len(patterns) >= 2  # IPv4 and IPv6

    def test_get_all_patterns(self):
        """Test getting all entity patterns."""
        all_patterns = get_all_entity_patterns()

        # Should have patterns for all entity types
        assert EntityType.IAM_ROLE_ARN in all_patterns
        assert EntityType.IP_ADDRESS in all_patterns
        assert EntityType.VPC_ID in all_patterns
        assert EntityType.S3_BUCKET in all_patterns

        # Each entity type should have at least one pattern
        for entity_type, patterns in all_patterns.items():
            assert len(patterns) > 0

    def test_vpc_id_pattern(self):
        """Test VPC ID pattern matching."""
        patterns = get_entity_patterns(EntityType.VPC_ID)
        vpc_pattern = patterns[0]

        # Should match VPC ID format
        import re
        assert re.match(vpc_pattern, "vpc-12345678")
        assert re.match(vpc_pattern, "vpc-1234567890abcdef")

    def test_s3_bucket_patterns(self):
        """Test S3 bucket pattern matching."""
        patterns = get_entity_patterns(EntityType.S3_BUCKET)
        assert len(patterns) >= 2  # ARN and DNS formats

        # Test different S3 formats are covered
        pattern_text = " ".join(patterns)
        assert "arn:aws:s3" in pattern_text
        assert "amazonaws\\.com" in pattern_text or "amazonaws.com" in pattern_text


class TestEnumValues:
    """Test enum value consistency."""

    def test_event_source_values(self):
        """Test EventSource enum values."""
        assert EventSource.CLOUDTRAIL == "cloudtrail"
        assert EventSource.VPC_FLOW == "vpc_flow"
        assert EventSource.S3_ACCESS == "s3_access"
        assert EventSource.IAM == "iam"

    def test_entity_type_values(self):
        """Test EntityType enum values."""
        assert EntityType.IAM_ROLE_ARN == "iam_role_arn"
        assert EntityType.IP_ADDRESS == "ip_address"
        assert EntityType.VPC_ID == "vpc_id"
        assert EntityType.KMS_KEY_ID == "kms_key_id"

    def test_risk_level_values(self):
        """Test RiskLevel enum values."""
        assert RiskLevel.LOW == "low"
        assert RiskLevel.MEDIUM == "medium"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.CRITICAL == "critical"


class TestProcessingResult:
    """Test processing result data model."""

    def test_processing_result_creation(self):
        """Test creating a processing result."""
        result = ProcessingResult(
            batch_id="batch-12345",
            total_events=100,
            entities_extracted=250,
            anomalies_detected=5,
            high_risk_events=2,
            processing_time_seconds=45.5,
            compliance_outputs=[],
            errors=[],
            warnings=["Some non-critical warning"]
        )

        assert result.batch_id == "batch-12345"
        assert result.total_events == 100
        assert result.anomalies_detected == 5
        assert len(result.warnings) == 1
        assert len(result.errors) == 0

    def test_processing_result_with_outputs(self):
        """Test processing result with compliance outputs."""
        compliance_output = ComplianceOutput(
            log_id="event-1",
            event_source=EventSource.CLOUDTRAIL,
            timestamp=datetime.now(timezone.utc),
            entities=[],
            risk_score=2.0,
            risk_level=RiskLevel.LOW,
            anomaly_scores=[],
            recommendations=[],
            requires_attention=False
        )

        result = ProcessingResult(
            batch_id="batch-12345",
            total_events=1,
            entities_extracted=0,
            anomalies_detected=0,
            high_risk_events=0,
            processing_time_seconds=1.0,
            compliance_outputs=[compliance_output]
        )

        assert len(result.compliance_outputs) == 1
        assert result.compliance_outputs[0].risk_level == RiskLevel.LOW
