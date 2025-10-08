"""Tests for the enrichment handler module."""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from detector.schemas import CloudTrailEvent, CloudTrailUserIdentity, ExtractedEntity, EntityType
from enrichment.handler import EnrichmentHandler


class TestEnrichmentHandler:
    """Test cases for the EnrichmentHandler class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.handler = EnrichmentHandler()
        
        # Sample CloudTrail event for testing
        self.sample_event = CloudTrailEvent(
            eventVersion="1.08",
            userIdentity=CloudTrailUserIdentity(
                type="IAMUser",
                principalId="AIDACKCEVSQ6C2EXAMPLE",
                arn="arn:aws:iam::123456789012:user/test-user",
                accountId="123456789012",
                userName="test-user"
            ),
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
    
    def test_handler_initialization(self):
        """Test handler initializes correctly."""
        handler = EnrichmentHandler()
        assert handler is not None
        assert handler.entity_extractor is not None
        assert handler.config == {}
        
        # Test with config
        config = {"threshold": 0.8}
        handler_with_config = EnrichmentHandler(config)
        assert handler_with_config.config == config
    
    @patch('enrichment.handler.EntityExtractor')
    def test_process_cloudtrail_event_success(self, mock_extractor_class):
        """Test successful CloudTrail event processing."""
        # Mock the entity extractor
        mock_extractor = Mock()
        mock_extractor.extract_from_cloudtrail_event.return_value = [
            ExtractedEntity(
                entity_id="arn:aws:iam::123456789012:user/test-user",
                entity_type=EntityType.IAM_USER_ARN,
                confidence=0.95,
                context="userIdentity",
                source_field="userIdentity.arn"
            ),
            ExtractedEntity(
                entity_id="203.0.113.12",
                entity_type=EntityType.IP_ADDRESS,
                confidence=0.90,
                context="sourceIPAddress",
                source_field="sourceIPAddress"
            )
        ]
        mock_extractor_class.return_value = mock_extractor
        
        # Create handler with mocked extractor
        handler = EnrichmentHandler()
        handler.entity_extractor = mock_extractor
        
        # Process event
        result = handler.process_cloudtrail_event(self.sample_event)
        
        # Verify results
        assert result.log_id == "12345678"
        assert result.event_source.value == "cloudtrail"
        assert result.timestamp == self.sample_event.eventTime
        assert len(result.entities) == 2
        assert len(result.anomaly_scores) == 2
        assert result.risk_level in ["low", "medium", "high", "critical"]
        assert len(result.recommendations) > 0
        assert isinstance(result.requires_attention, bool)
        
        # Verify entity extractor was called
        mock_extractor.extract_from_cloudtrail_event.assert_called_once_with(self.sample_event)
    
    def test_determine_risk_level_empty_scores(self):
        """Test risk level determination with empty scores."""
        risk_level = self.handler._determine_risk_level([])
        assert risk_level == "low"
    
    def test_determine_risk_level_various_scores(self):
        """Test risk level determination with various score combinations."""
        from detector.schemas import AnomalyScore
        
        # Low risk scores
        low_scores = [
            AnomalyScore(score=1.0, factors=[], threshold=5.0, is_anomaly=False),
            AnomalyScore(score=2.0, factors=[], threshold=5.0, is_anomaly=False)
        ]
        assert self.handler._determine_risk_level(low_scores) == "low"
        
        # Medium risk scores
        medium_scores = [
            AnomalyScore(score=4.0, factors=[], threshold=5.0, is_anomaly=False),
            AnomalyScore(score=6.0, factors=[], threshold=5.0, is_anomaly=True)
        ]
        assert self.handler._determine_risk_level(medium_scores) == "medium"
        
        # High risk scores
        high_scores = [
            AnomalyScore(score=8.0, factors=[], threshold=5.0, is_anomaly=True),
            AnomalyScore(score=9.0, factors=[], threshold=5.0, is_anomaly=True)
        ]
        assert self.handler._determine_risk_level(high_scores) == "high"
    
    def test_generate_recommendations_empty_inputs(self):
        """Test recommendation generation with empty inputs."""
        recommendations = self.handler._generate_recommendations([], [])
        assert len(recommendations) == 1
        assert "No immediate compliance actions required" in recommendations[0]
    
    def test_generate_recommendations_with_entities(self):
        """Test recommendation generation with various entities."""
        entities = [
            ExtractedEntity(
                entity_id="arn:aws:iam::123456789012:role/test-role",
                entity_type=EntityType.IAM_ROLE_ARN,
                confidence=0.95,
                context="test",
                source_field="test"
            ),
            ExtractedEntity(
                entity_id="203.0.113.12",
                entity_type=EntityType.IP_ADDRESS,
                confidence=0.90,
                context="test",
                source_field="test"
            )
        ]
        
        from detector.schemas import AnomalyScore
        scores = [
            AnomalyScore(score=8.0, factors=[], threshold=5.0, is_anomaly=True)
        ]
        
        recommendations = self.handler._generate_recommendations(entities, scores)
        
        # Should have recommendations for high risk and specific entity types
        assert len(recommendations) >= 3
        assert any("high-risk entities" in rec for rec in recommendations)
        assert any("IAM role permissions" in rec for rec in recommendations)
        assert any("source IP addresses" in rec for rec in recommendations)
    
    def test_vpc_flow_log_processing_not_implemented(self):
        """Test that VPC flow log processing raises NotImplementedError."""
        from detector.schemas import VPCFlowLogRecord
        
        vpc_log = VPCFlowLogRecord(
            version=2,
            account_id="123456789012",
            interface_id="eni-12345678",
            srcaddr="10.0.1.5",
            dstaddr="10.0.2.10",
            srcport=443,
            dstport=80,
            protocol=6,
            packets=10,
            bytes=1500,
            windowstart=datetime.utcnow(),
            windowend=datetime.utcnow(),
            action="ACCEPT",
            flowlogstatus="OK"
        )
        
        with pytest.raises(NotImplementedError):
            self.handler.process_vpc_flow_log(vpc_log)
    
    @patch('enrichment.handler.EntityExtractor')
    def test_process_cloudtrail_event_error_handling(self, mock_extractor_class):
        """Test error handling in CloudTrail event processing."""
        # Mock the entity extractor to raise an exception
        mock_extractor = Mock()
        mock_extractor.extract_from_cloudtrail_event.side_effect = Exception("Test error")
        mock_extractor_class.return_value = mock_extractor
        
        handler = EnrichmentHandler()
        handler.entity_extractor = mock_extractor
        
        with pytest.raises(Exception) as exc_info:
            handler.process_cloudtrail_event(self.sample_event)
        
        assert "Test error" in str(exc_info.value)


class TestLambdaHandler:
    """Test cases for the Lambda handler function."""
    
    @patch('enrichment.handler.EnrichmentHandler')
    def test_lambda_handler_sqs_batch(self, mock_handler_class):
        """Test Lambda handler with SQS batch processing."""
        from enrichment.handler import lambda_handler
        from detector.schemas import ComplianceOutput, EventSource, RiskLevel
        
        # Mock handler
        mock_handler = Mock()
        mock_result = ComplianceOutput(
            log_id="test-123",
            event_source=EventSource.CLOUDTRAIL,
            timestamp=datetime.utcnow(),
            entities=[],
            risk_score=2.5,
            risk_level=RiskLevel.LOW,
            anomaly_scores=[],
            recommendations=["Test recommendation"],
            requires_attention=False
        )
        mock_handler.process_cloudtrail_event.return_value = mock_result
        mock_handler_class.return_value = mock_handler
        
        # Test event with SQS Records
        event = {
            "Records": [
                {
                    "body": '{"eventSource": "s3.amazonaws.com", "eventID": "test-123", "eventVersion": "1.08", "userIdentity": {"type": "IAMUser"}, "eventTime": "2024-01-01T12:00:00Z", "eventName": "GetObject", "awsRegion": "us-east-1", "requestID": "test", "eventType": "AwsApiCall", "recipientAccountId": "123456789012"}'
                }
            ]
        }
        
        result = lambda_handler(event, None)
        
        assert result["statusCode"] == 200
        response_body = result["body"]
        assert "processed" in response_body
        assert "results" in response_body
    
    def test_lambda_handler_invalid_event(self):
        """Test Lambda handler with invalid event format."""
        from enrichment.handler import lambda_handler
        
        # Invalid event without Records or log_data
        event = {"invalid": "event"}
        
        result = lambda_handler(event, None)
        
        assert result["statusCode"] == 400
        assert "Invalid event format" in result["body"]
    
    def test_lambda_handler_error_handling(self):
        """Test Lambda handler error handling."""
        from enrichment.handler import lambda_handler
        
        # Event that will cause an error during processing
        event = {
            "log_data": {
                "eventSource": "s3.amazonaws.com",
                "invalid_field": "this will cause validation error"
            }
        }
        
        result = lambda_handler(event, None)
        
        assert result["statusCode"] == 500
        assert "error" in result["body"]