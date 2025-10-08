"""Simplified tests for anomaly scoring functionality."""

import pytest
import numpy as np
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from typing import List, Dict, Any, Optional

from src.detector.scoring import (
    AnomalyScoringEngine,
    StatisticalAnomalyDetector,
    BehavioralAnomalyDetector,
    RareEntityCombinationDetector,
    PrivilegeEscalationDetector,
    AnomalyType
)
from src.detector.schemas import (
    CloudTrailEvent,
    CloudTrailUserIdentity,
    ExtractedEntity,
    AnomalyScore,
    EntityType
)


def create_test_cloudtrail_event(
    event_name: str = "AssumeRole",
    user_type: str = "IAMUser",
    principal_id: str = "AIDACKCEVSQ6C2EXAMPLE",
    arn: str = "arn:aws:iam::123456789012:user/testuser",
    user_name: str = "testuser",
    source_ip: str = "192.168.1.1",
    aws_region: str = "us-east-1",
    event_time: Optional[datetime] = None,
    request_params: Optional[Dict[str, Any]] = None,
    response_elements: Optional[Dict[str, Any]] = None
) -> CloudTrailEvent:
    """Create a valid CloudTrail event for testing."""
    if event_time is None:
        event_time = datetime.utcnow()
    
    if request_params is None:
        request_params = {}
    
    if response_elements is None:
        response_elements = {}
    
    return CloudTrailEvent(
        eventVersion="1.08",
        userIdentity=CloudTrailUserIdentity(
            type=user_type,
            principalId=principal_id,
            arn=arn,
            userName=user_name,
            accountId="123456789012"
        ),
        eventTime=event_time,
        eventSource="iam.amazonaws.com",
        eventName=event_name,
        awsRegion=aws_region,
        sourceIPAddress=source_ip,
        userAgent="aws-cli/1.18.69 Python/3.8.0 Linux/4.14.133-113.105.amzn2.x86_64 botocore/1.17.12",
        requestParameters=request_params,
        responseElements=response_elements,
        requestID="12345678-1234-1234-1234-123456789abc",
        eventID="abcdef01-2345-6789-abcd-ef0123456789",
        eventType="AwsApiCall",
        recipientAccountId="123456789012"
    )


def create_test_extracted_entity(
    entity_id: str = "arn:aws:iam::123456789012:user/testuser",
    entity_type: EntityType = EntityType.IAM_USER_ARN,
    confidence: float = 0.9,
    context: str = "IAM user authentication",
    source_field: str = "userIdentity.arn"
) -> ExtractedEntity:
    """Create a valid ExtractedEntity for testing."""
    return ExtractedEntity(
        entity_id=entity_id,
        entity_type=entity_type,
        confidence=confidence,
        context=context,
        source_field=source_field
    )


class TestStatisticalAnomalyDetector:
    """Test cases for StatisticalAnomalyDetector."""

    def test_statistical_detector_initialization(self):
        """Test detector initialization with default parameters."""
        detector = StatisticalAnomalyDetector()
        assert detector.threshold == 2.5
        assert detector.use_modified_zscore is True

    def test_standard_zscore_calculation(self):
        """Test standard Z-score calculation."""
        detector = StatisticalAnomalyDetector(use_modified_zscore=False)
        values = [1.0, 2.0, 3.0, 100.0]  # 100 is clearly an outlier
        anomalies = detector.detect_anomalies(values)
        
        # Should detect the outlier
        assert len(anomalies) > 0
        assert anomalies[0][0] == 3  # Index of outlier
        assert abs(anomalies[0][1]) > detector.threshold  # Score should exceed threshold

    def test_empty_dataset(self):
        """Test behavior with empty dataset."""
        detector = StatisticalAnomalyDetector()
        anomalies = detector.detect_anomalies([])
        assert len(anomalies) == 0

    def test_small_dataset(self):
        """Test behavior with small dataset."""
        detector = StatisticalAnomalyDetector()
        anomalies = detector.detect_anomalies([1.0, 2.0])
        assert len(anomalies) == 0


class TestBehavioralAnomalyDetector:
    """Test cases for BehavioralAnomalyDetector."""

    def test_behavioral_detector_initialization(self):
        """Test detector initialization."""
        detector = BehavioralAnomalyDetector()
        assert detector.lookback_days == 30
        assert detector.min_events == 10
        assert len(detector.entity_profiles) == 0

    def test_entity_profile_creation(self):
        """Test entity profile creation and updates."""
        detector = BehavioralAnomalyDetector()
        
        # Create test event using helper
        event = create_test_cloudtrail_event(
            event_name="AssumeRole",
            user_name="testuser",
            source_ip="192.168.1.100"
        )
        
        entities = [
            create_test_extracted_entity(
                entity_id="testuser",
                entity_type=EntityType.IAM_USER_ARN,
                context="IAM user authentication",
                source_field="userIdentity.userName"
            )
        ]

        # Update profiles
        detector.update_entity_profile(event, entities)
        
        # Check profile was created
        assert len(detector.entity_profiles) > 0


class TestRareEntityCombinationDetector:
    """Test cases for RareEntityCombinationDetector."""

    def test_combination_detector_initialization(self):
        """Test detector initialization."""
        detector = RareEntityCombinationDetector()
        assert detector.rarity_threshold == 0.01
        assert detector.min_observations == 100
        assert len(detector.combination_counts) == 0
        assert detector.total_combinations == 0


class TestPrivilegeEscalationDetector:
    """Test cases for PrivilegeEscalationDetector."""

    def test_privilege_detector_initialization(self):
        """Test detector initialization."""
        detector = PrivilegeEscalationDetector()
        assert detector.lookback_minutes == 30
        assert len(detector.escalation_patterns) > 0


class TestAnomalyScoringEngine:
    """Test cases for AnomalyScoringEngine."""

    def test_scoring_engine_initialization(self):
        """Test scoring engine initialization."""
        config = {"anomaly_threshold": 2.5}
        engine = AnomalyScoringEngine(config)
        assert engine.statistical_detector is not None
        assert engine.behavioral_detector is not None
        assert engine.rare_combo_detector is not None
        assert engine.privilege_detector is not None

    def test_score_event(self):
        """Test event scoring."""
        config = {"anomaly_threshold": 2.5}
        engine = AnomalyScoringEngine(config)
        
        # Create test data
        event = create_test_cloudtrail_event(
            event_name="CreateRole",
            user_name="suspicious_user",
            source_ip="192.168.1.100"
        )
        
        entities = [
            create_test_extracted_entity(
                entity_id="suspicious_user",
                entity_type=EntityType.IAM_USER_ARN
            )
        ]
        
        # Score the event
        result = engine.score_event(event, entities)
        
        # Verify result structure
        assert isinstance(result, list)


class TestAnomalyScoreSchema:
    """Test cases for AnomalyScore schema."""

    def test_anomaly_score_creation(self):
        """Test AnomalyScore model creation."""
        score = AnomalyScore(
            score=7.5,
            factors=["high_zscore", "unusual_time"],
            threshold=3.0,
            is_anomaly=True
        )
        
        assert score.score == 7.5
        assert len(score.factors) == 2
        assert score.is_anomaly is True

    def test_anomaly_score_validation(self):
        """Test AnomalyScore validation."""
        # Score should be between 0 and 10
        with pytest.raises(Exception):
            AnomalyScore(
                score=15.0,  # Invalid - too high
                factors=[],
                threshold=3.0,
                is_anomaly=True
            )