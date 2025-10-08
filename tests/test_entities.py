"""Tests for entity extraction functionality."""

from datetime import datetime
from pathlib import Path

import pytest

# Add paths for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detector.entities import EntityExtractor, extract_entities_from_batch
from detector.schemas import (
    EntityType,
    EventSource,
    CloudTrailEvent,
    CloudTrailUserIdentity,
    VPCFlowLogRecord
)


class TestEntityExtractor:
    """Test entity extraction functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = EntityExtractor()
    
    def test_initialization(self):
        """Test extractor initialization."""
        assert len(self.extractor.patterns) > 0
        assert len(self.extractor.compiled_patterns) > 0
        assert EntityType.IAM_ROLE_ARN in self.extractor.patterns
        assert EntityType.IP_ADDRESS in self.extractor.patterns
    
    def test_extract_from_text_iam_arn(self):
        """Test extracting IAM ARNs from text."""
        # Test IAM user ARN
        text = "User arn:aws:iam::123456789012:user/test-user performed action"
        
        entities = self.extractor.extract_from_text(text, [EntityType.IAM_USER_ARN])
        
        assert len(entities) > 0
        arn_entity = next((e for e in entities if "arn:aws:iam" in e.entity_id), None)
        assert arn_entity is not None
        assert arn_entity.entity_type == EntityType.IAM_USER_ARN
        assert arn_entity.confidence >= 0.7
        
        # Test IAM role ARN
        role_text = "AssumedRole arn:aws:iam::123456789012:role/TestRole was used"
        
        role_entities = self.extractor.extract_from_text(role_text, [EntityType.IAM_ROLE_ARN])
        
        assert len(role_entities) > 0
        role_entity = next((e for e in role_entities if "arn:aws:iam" in e.entity_id), None)
        assert role_entity is not None
        assert role_entity.entity_type == EntityType.IAM_ROLE_ARN
        assert role_entity.confidence >= 0.7
    
    def test_extract_from_text_ip_address(self):
        """Test extracting IP addresses from text."""
        text = "Request from 192.168.1.100 to 10.0.0.50 was blocked"
        
        entities = self.extractor.extract_from_text(text, [EntityType.IP_ADDRESS])
        
        assert len(entities) == 2
        ip_addresses = {e.entity_id for e in entities}
        assert "192.168.1.100" in ip_addresses
        assert "10.0.0.50" in ip_addresses
        
        for entity in entities:
            assert entity.entity_type == EntityType.IP_ADDRESS
            assert entity.confidence >= 0.7
    
    def test_extract_from_text_vpc_id(self):
        """Test extracting VPC IDs from text."""
        text = "Instance in vpc-12345678 and subnet subnet-abcdef12"
        
        entities = self.extractor.extract_from_text(text, [EntityType.VPC_ID])
        
        vpc_entity = next((e for e in entities if e.entity_id == "vpc-12345678"), None)
        assert vpc_entity is not None
        assert vpc_entity.entity_type == EntityType.VPC_ID
        assert vpc_entity.confidence >= 0.7
    
    def test_extract_from_text_confidence_threshold(self):
        """Test confidence threshold filtering."""
        text = "arn:aws:iam::123456789012:user/test-user"
        
        # High threshold should filter out lower confidence matches
        high_threshold_entities = self.extractor.extract_from_text(
            text, confidence_threshold=0.95
        )
        
        # Low threshold should include more matches
        low_threshold_entities = self.extractor.extract_from_text(
            text, confidence_threshold=0.5
        )
        
        assert len(low_threshold_entities) >= len(high_threshold_entities)
    
    def test_extract_from_text_deduplication(self):
        """Test that duplicate entities are removed."""
        text = "User 192.168.1.1 and source 192.168.1.1 performed action"
        
        entities = self.extractor.extract_from_text(text, [EntityType.IP_ADDRESS])
        
        # Should only get one entity despite IP appearing twice
        ip_entities = [e for e in entities if e.entity_id == "192.168.1.1"]
        assert len(ip_entities) == 1
    
    def test_extract_from_cloudtrail_event_basic(self):
        """Test extracting entities from a basic CloudTrail event."""
        user_identity = CloudTrailUserIdentity(
            type="IAMUser",
            principalId="AIDACKCEVSQ6C2EXAMPLE",
            arn="arn:aws:iam::123456789012:user/test-user",
            accountId="123456789012",
            userName="test-user"
        )
        
        event = CloudTrailEvent(
            eventVersion="1.08",
            userIdentity=user_identity,
            eventTime=datetime.fromisoformat("2024-01-01T12:00:00+00:00"),
            eventSource="s3.amazonaws.com",
            eventName="GetObject",
            awsRegion="us-east-1",
            sourceIPAddress="203.0.113.12",
            userAgent="aws-cli/2.0.55",
            requestParameters={"bucketName": "test-bucket"},
            responseElements=None,
            requestID="87654321",
            eventID="12345678",
            eventType="AwsApiCall",
            recipientAccountId="123456789012"
        )
        
        entities = self.extractor.extract_from_cloudtrail_event(event)
        
        assert len(entities) > 0
        
        # Check for ARN extraction
        arn_entities = [e for e in entities if e.entity_type == EntityType.IAM_USER_ARN]
        assert len(arn_entities) > 0
        arn_entity = arn_entities[0]
        assert arn_entity.entity_id == "arn:aws:iam::123456789012:user/test-user"
        assert arn_entity.source_field == "userIdentity.arn"
        
        # Check for IP address extraction
        ip_entities = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ip_entities) > 0
        ip_entity = ip_entities[0]
        assert ip_entity.entity_id == "203.0.113.12"
        assert ip_entity.source_field == "sourceIPAddress"
    
    def test_extract_from_cloudtrail_event_with_request_params(self):
        """Test extracting entities from CloudTrail event with request parameters."""
        user_identity = CloudTrailUserIdentity(
            type="Root",
            principalId="123456789012",
            arn="arn:aws:iam::123456789012:root",
            accountId="123456789012"
        )
        
        event = CloudTrailEvent(
            eventVersion="1.08",
            userIdentity=user_identity,
            eventTime=datetime.fromisoformat("2024-01-01T12:00:00+00:00"),
            eventSource="ec2.amazonaws.com",
            eventName="RunInstances",
            awsRegion="us-east-1",
            sourceIPAddress="10.0.0.1",
            userAgent="console.aws.amazon.com",
            requestParameters={
                "instanceId": "i-1234567890abcdef0",
                "vpcId": "vpc-12345678",
                "subnetId": "subnet-abcdef12"
            },
            responseElements=None,
            requestID="87654321",
            eventID="12345678",
            eventType="AwsApiCall",
            recipientAccountId="123456789012"
        )
        
        entities = self.extractor.extract_from_cloudtrail_event(event)
        
        # Should extract VPC ID from request parameters
        vpc_entities = [e for e in entities if e.entity_type == EntityType.VPC_ID]
        assert len(vpc_entities) > 0
        vpc_entity = vpc_entities[0]
        assert vpc_entity.entity_id == "vpc-12345678"
        assert "requestParameters" in vpc_entity.source_field
    
    def test_extract_from_vpc_flow_log(self):
        """Test extracting entities from a VPC Flow Log record."""
        record = VPCFlowLogRecord(
            version=2,
            account_id="123456789012",
            interface_id="eni-1235b8ca",
            srcaddr="172.31.16.139",
            dstaddr="172.31.16.21",
            srcport=20641,
            dstport=22,
            protocol=6,
            packets=20,
            bytes=4249,
            windowstart=datetime.fromtimestamp(1418530010),
            windowend=datetime.fromtimestamp(1418530070),
            action="ACCEPT",
            flowlogstatus="OK"
        )
        
        entities = self.extractor.extract_from_vpc_flow_log(record)
        
        assert len(entities) > 0
        
        # Check for IP address extraction
        ip_entities = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ip_entities) == 2  # Source and destination
        
        ip_addresses = {e.entity_id for e in ip_entities}
        assert "172.31.16.139" in ip_addresses
        assert "172.31.16.21" in ip_addresses
        
        # Check source fields
        src_entities = [e for e in ip_entities if e.source_field == "srcaddr"]
        dst_entities = [e for e in ip_entities if e.source_field == "dstaddr"]
        assert len(src_entities) == 1
        assert len(dst_entities) == 1
        
        # Check for account ID extraction
        account_entities = [e for e in entities if e.entity_id == "123456789012"]
        assert len(account_entities) > 0
    
    def test_is_valid_account_id(self):
        """Test AWS account ID validation."""
        assert self.extractor._is_valid_account_id("123456789012") is True
        assert self.extractor._is_valid_account_id("123456789") is False  # Too short
        assert self.extractor._is_valid_account_id("1234567890123") is False  # Too long
        assert self.extractor._is_valid_account_id("12345678901a") is False  # Non-numeric
    
    def test_is_valid_ip(self):
        """Test IP address validation."""
        assert self.extractor._is_valid_ip("192.168.1.1") is True
        assert self.extractor._is_valid_ip("10.0.0.0") is True
        assert self.extractor._is_valid_ip("255.255.255.255") is True
        assert self.extractor._is_valid_ip("192.168.1.256") is False  # Out of range
        assert self.extractor._is_valid_ip("192.168.1") is False  # Incomplete
        assert self.extractor._is_valid_ip("not.an.ip.address") is False  # Invalid format
    
    def test_calculate_confidence_arn(self):
        """Test confidence calculation for ARNs."""
        import re
        
        # High confidence for well-formed ARN
        arn = "arn:aws:iam::123456789012:user/test-user"
        match = re.search(r'arn:aws:.*', arn)
        if match:
            confidence = self.extractor._calculate_confidence(
                EntityType.IAM_ROLE_ARN, arn, f"User {arn} performed action", match
            )
            assert confidence >= 0.9
        
        # Lower confidence for malformed ARN
        bad_arn = "arn:something:weird"
        match = re.search(r'arn:.*', bad_arn)
        if match:
            confidence = self.extractor._calculate_confidence(
                EntityType.IAM_ROLE_ARN, bad_arn, f"Text {bad_arn} here", match
            )
            assert confidence < 0.9
    
    def test_calculate_confidence_ip(self):
        """Test confidence calculation for IP addresses."""
        import re
        
        # High confidence for valid IP
        ip = "192.168.1.1"
        match = re.search(r'\d+\.\d+\.\d+\.\d+', ip)
        if match:
            confidence = self.extractor._calculate_confidence(
                EntityType.IP_ADDRESS, ip, f"Source IP {ip} accessed", match
            )
            assert confidence >= 0.9
    
    def test_calculate_confidence_context_boost(self):
        """Test confidence boost from contextual clues."""
        import re
        
        # IP with contextual clues should get boosted confidence
        text = "Source IP address 192.168.1.1 made request"
        ip = "192.168.1.1"
        match = re.search(r'\d+\.\d+\.\d+\.\d+', text)
        if match:
            confidence = self.extractor._calculate_confidence(
                EntityType.IP_ADDRESS, ip, text, match
            )
            
            # Should be higher due to "IP address" context
            assert confidence >= 0.95
    
    def test_deduplicate_entities(self):
        """Test entity deduplication logic."""
        from detector.schemas import ExtractedEntity
        
        entities = [
            ExtractedEntity(
                entity_type=EntityType.IP_ADDRESS,
                entity_id="192.168.1.1",
                confidence=0.8,
                context="First occurrence",
                source_field="field1"
            ),
            ExtractedEntity(
                entity_type=EntityType.IP_ADDRESS,
                entity_id="192.168.1.1",
                confidence=0.9,  # Higher confidence
                context="Second occurrence",
                source_field="field2"
            ),
            ExtractedEntity(
                entity_type=EntityType.VPC_ID,
                entity_id="vpc-12345",
                confidence=0.8,
                context="VPC ID",
                source_field="field3"
            )
        ]
        
        deduplicated = self.extractor._deduplicate_entities(entities)
        
        assert len(deduplicated) == 2  # Two unique entities
        
        # Should keep the higher confidence IP entity
        ip_entity = next(e for e in deduplicated if e.entity_type == EntityType.IP_ADDRESS)
        assert ip_entity.confidence == 0.9
        assert ip_entity.source_field == "field2"
    
    def test_extract_batch_cloudtrail(self):
        """Test batch extraction from CloudTrail events."""
        events = [
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/user1",
                    "accountId": "123456789012",
                    "userName": "user1"
                },
                "eventTime": "2024-01-01T12:00:00Z",
                "eventSource": "s3.amazonaws.com",
                "eventName": "GetObject",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.168.1.1",
                "userAgent": "aws-cli/2.0.55",
                "requestParameters": {},
                "responseElements": None,
                "requestID": "87654321",
                "eventID": "12345678",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012"
            },
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "Root",
                    "principalId": "987654321098",
                    "arn": "arn:aws:iam::987654321098:root",
                    "accountId": "987654321098"
                },
                "eventTime": "2024-01-01T12:01:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "10.0.0.1",
                "userAgent": "console.aws.amazon.com",
                "requestParameters": {},
                "responseElements": None,
                "requestID": "87654322",
                "eventID": "12345679",
                "eventType": "AwsApiCall",
                "recipientAccountId": "987654321098"
            }
        ]
        
        entities = self.extractor.extract_batch(events, EventSource.CLOUDTRAIL)
        
        assert len(entities) > 0
        
        # Should have entities from both events
        ip_entities = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ip_entities) >= 2
        
        ip_addresses = {e.entity_id for e in ip_entities}
        assert "192.168.1.1" in ip_addresses
        assert "10.0.0.1" in ip_addresses
    
    def test_extract_batch_vpc_flow(self):
        """Test batch extraction from VPC Flow Log events."""
        events = [
            {
                "version": 2,
                "account_id": "123456789012",
                "interface_id": "eni-1235b8ca",
                "srcaddr": "172.31.16.139",
                "dstaddr": "172.31.16.21",
                "srcport": 20641,
                "dstport": 22,
                "protocol": 6,
                "packets": 20,
                "bytes": 4249,
                "windowstart": 1418530010,
                "windowend": 1418530070,
                "action": "ACCEPT",
                "flowlogstatus": "OK"
            },
            {
                "version": 2,
                "account_id": "123456789012",
                "interface_id": "eni-abcdef12",
                "srcaddr": "10.0.0.1",
                "dstaddr": "203.0.113.50",
                "srcport": 443,
                "dstport": 80,
                "protocol": 6,
                "packets": 15,
                "bytes": 2048,
                "windowstart": 1418530015,
                "windowend": 1418530075,
                "action": "REJECT",
                "flowlogstatus": "OK"
            }
        ]
        
        entities = self.extractor.extract_batch(events, EventSource.VPC_FLOW)
        
        assert len(entities) > 0
        
        # Should have IP entities from both records
        ip_entities = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ip_entities) >= 4  # 2 IPs per record
        
        ip_addresses = {e.entity_id for e in ip_entities}
        assert "172.31.16.139" in ip_addresses
        assert "10.0.0.1" in ip_addresses
        assert "203.0.113.50" in ip_addresses
    
    def test_extract_batch_invalid_event(self):
        """Test batch extraction with invalid events."""
        events = [
            {
                "eventVersion": "1.08",
                # Missing required fields
                "eventTime": "2024-01-01T12:00:00Z",
            },
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "Root",
                    "principalId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:root",
                    "accountId": "123456789012"
                },
                "eventTime": "2024-01-01T12:01:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-west-2",
                "sourceIPAddress": "10.0.0.1",
                "userAgent": "console.aws.amazon.com",
                "requestParameters": {},
                "responseElements": None,
                "requestID": "87654322",
                "eventID": "12345679",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012"
            }
        ]
        
        # Should handle invalid events gracefully
        entities = self.extractor.extract_batch(events, EventSource.CLOUDTRAIL)
        
        # Should still extract entities from valid events
        assert len(entities) > 0


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_extract_entities_from_batch_cloudtrail(self):
        """Test convenience function for CloudTrail batch extraction."""
        events = [
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "Root",
                    "principalId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:root",
                    "accountId": "123456789012"
                },
                "eventTime": "2024-01-01T12:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "192.168.1.1",
                "userAgent": "console.aws.amazon.com",
                "requestParameters": {},
                "responseElements": None,
                "requestID": "87654321",
                "eventID": "12345678",
                "eventType": "AwsApiCall",
                "recipientAccountId": "123456789012"
            }
        ]
        
        entities = extract_entities_from_batch(events, EventSource.CLOUDTRAIL)
        
        assert len(entities) > 0
        ip_entities = [e for e in entities if e.entity_type == EntityType.IP_ADDRESS]
        assert len(ip_entities) > 0