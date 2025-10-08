"""Tests for anomaly scoring functionality.

This module contains comprehensive tests for the anomaly scoring engine,
including statistical detection, behavioral analysis, rare entity combinations,
and privilege escalation detection.
"""

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
    AnomalyType,
    AnomalyResult,
    EntityBehaviorProfile
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
    
    return create_test_cloudtrail_event()
            
            entities = [
                create_test_extracted_entity(entity_id="testuser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
                )
            ]
            
            detector.update_entity_profile(event, entities)
        
        # Create anomalous event at unusual time (2 AM)
        anomalous_event = create_test_cloudtrail_event()
        
        entities = [
            create_test_extracted_entity(entity_id="testuser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
            )
        ]
        
        # Detect anomalies
        anomalies = detector.detect_behavioral_anomalies(anomalous_event, entities)
        
        # Should detect time pattern anomaly
        assert len(anomalies) > 0
        time_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.TIME_PATTERN_ANOMALY]
        assert len(time_anomalies) > 0
    
    def test_new_action_detection(self):
        """Test detection of new actions for an entity."""
        detector = BehavioralAnomalyDetector(min_events=5)
        
        # Create baseline with specific actions
        base_time = datetime.now()
        baseline_actions = ["ListUsers", "GetUser", "DescribeInstances"]
        
        for i, action in enumerate(baseline_actions * 3):  # 9 events total
            event = create_test_cloudtrail_event()
            
            entities = [
                create_test_extracted_entity(entity_id="testuser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
                )
            ]
            
            detector.update_entity_profile(event, entities)
        
        # Test with new action
        new_action_event = create_test_cloudtrail_event()
        
        entities = [
            create_test_extracted_entity(entity_id="testuser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
            )
        ]
        
        # Detect anomalies
        anomalies = detector.detect_behavioral_anomalies(new_action_event, entities)
        
        # Should detect behavioral deviation
        assert len(anomalies) > 0
        action_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.BEHAVIORAL_DEVIATION]
        assert len(action_anomalies) > 0


class TestRareEntityCombinationDetector:
    """Test rare entity combination detection."""
    
    def test_combination_detector_initialization(self):
        """Test combination detector initialization."""
        detector = RareEntityCombinationDetector()
        assert detector.rarity_threshold == 0.01
        assert detector.min_observations == 100
        assert len(detector.combination_counts) == 0
        assert detector.total_combinations == 0
    
    def test_combination_counting(self):
        """Test combination counting functionality."""
        detector = RareEntityCombinationDetector(min_observations=5)
        
        # Create test event
        event = create_test_cloudtrail_event()
        
        entities = [
            create_test_extracted_entity(entity_id="testuser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
            ),
            create_test_extracted_entity(entity_id="192.168.1.100", entity_type=EntityType.IP_ADDRESS, confidence=0.95
            )
        ]
        
        # Update combinations
        detector.update_combination_counts(entities, event)
        
        # Check combinations were recorded
        assert detector.total_combinations == 1
        assert len(detector.combination_counts) > 0
        
        # Should have entity type combination
        user_ip_combo = "types:('IP', 'USER')"
        assert user_ip_combo in detector.combination_counts
    
    def test_rare_combination_detection(self):
        """Test detection of rare entity combinations."""
        detector = RareEntityCombinationDetector(
            rarity_threshold=0.1,  # 10% threshold for testing
            min_observations=10
        )
        
        # Create common combinations
        common_entities = [
            create_test_extracted_entity(entity_id="user1", entity_type=EntityType.IAM_USER_ARN, confidence=0.9),
            create_test_extracted_entity(entity_id="ip1", entity_type=EntityType.IP_ADDRESS, confidence=0.9)
        ]
        
        common_event = create_test_cloudtrail_event()
        
        # Add common combinations multiple times
        for _ in range(15):
            detector.update_combination_counts(common_entities, common_event)
        
        # Create rare combination
        rare_entities = [
            create_test_extracted_entity(entity_id="admin", entity_type=EntityType.IAM_USER_ARN, confidence=0.9),
            create_test_extracted_entity(entity_id="role123", entity_type=EntityType.IAM_ROLE_ARN, confidence=0.9)
        ]
        
        rare_event = create_test_cloudtrail_event()
        
        # Add rare combination once
        detector.update_combination_counts(rare_entities, rare_event)
        
        # Test detection
        anomalies = detector.detect_rare_combinations(rare_entities, rare_event)
        
        # Should detect rare combination
        assert len(anomalies) > 0
        rare_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.RARE_ENTITY_COMBO]
        assert len(rare_anomalies) > 0


class TestPrivilegeEscalationDetector:
    """Test privilege escalation detection."""
    
    def test_privilege_detector_initialization(self):
        """Test privilege escalation detector initialization."""
        detector = PrivilegeEscalationDetector()
        assert detector.lookback_minutes == 30
        assert len(detector.escalation_patterns) > 0
        assert len(detector.recent_events) == 0
    
    def test_privilege_escalation_pattern_detection(self):
        """Test detection of privilege escalation patterns."""
        detector = PrivilegeEscalationDetector()
        
        base_time = datetime.now()
        user_arn = "arn:aws:iam::123456789012:user/testuser"
        
        # Create sequence of events that match escalation pattern
        escalation_actions = ["CreateRole", "AttachRolePolicy", "AssumeRole"]
        
        events = []
        for i, action in enumerate(escalation_actions):
            event = create_test_cloudtrail_event()
            events.append(event)
        
        entities = [
            create_test_extracted_entity(entity_id="testuser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
            )
        ]
        
        # Process events sequentially
        anomalies_detected = []
        for event in events:
            anomalies = detector.detect_privilege_escalation(event, entities)
            anomalies_detected.extend(anomalies)
        
        # Should detect privilege escalation pattern
        assert len(anomalies_detected) > 0
        escalation_anomalies = [a for a in anomalies_detected if a.anomaly_type == AnomalyType.PRIVILEGE_ESCALATION]
        assert len(escalation_anomalies) > 0
    
    def test_user_key_extraction(self):
        """Test user key extraction from events."""
        detector = PrivilegeEscalationDetector()
        
        # Test with ARN
        event_with_arn = create_test_cloudtrail_event()
        
        user_key = detector._get_user_key(event_with_arn)
        assert user_key == "arn:aws:iam::123456789012:user/testuser"
        
        # Test with username only
        event_with_username = create_test_cloudtrail_event()
        
        user_key = detector._get_user_key(event_with_username)
        assert user_key == "testuser"


class TestAnomalyScoringEngine:
    """Test the main anomaly scoring engine."""
    
    def test_scoring_engine_initialization(self):
        """Test scoring engine initialization."""
        config = {
            'anomaly_threshold': 5.0,
            'statistical_threshold': 2.5
        }
        
        engine = AnomalyScoringEngine(config)
        assert engine.config == config
        assert engine.statistical_detector is not None
        assert engine.behavioral_detector is not None
        assert engine.rare_combo_detector is not None
        assert engine.privilege_detector is not None
    
    def test_event_scoring(self):
        """Test end-to-end event scoring."""
        config = {
            'anomaly_threshold': 5.0,
            'statistical_threshold': 2.5
        }
        
        engine = AnomalyScoringEngine(config)
        
        # Create test event
        event = create_test_cloudtrail_event()
        
        entities = [
            create_test_extracted_entity(entity_id="testuser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
            ),
            create_test_extracted_entity(entity_id="192.168.1.100", entity_type=EntityType.IP_ADDRESS, confidence=0.95
            )
        ]
        
        # Score the event
        anomaly_scores = engine.score_event(event, entities)
        
        # Should return list of AnomalyScore objects
        assert isinstance(anomaly_scores, list)
        
        for score in anomaly_scores:
            assert isinstance(score, AnomalyScore)
            assert isinstance(score.score, (int, float))
            assert isinstance(score.factors, list)
            assert isinstance(score.is_anomaly, bool)
    
    def test_aggregate_score_calculation(self):
        """Test aggregate score calculation."""
        config = {'anomaly_threshold': 5.0}
        engine = AnomalyScoringEngine(config)
        
        # Test with no scores
        assert engine.calculate_aggregate_score([]) == 0.0
        
        # Test with single score
        scores = [AnomalyScore(score=7.0, factors=[], threshold=5.0, is_anomaly=True)]
        assert engine.calculate_aggregate_score(scores) == 7.0
        
        # Test with multiple scores
        scores = [
            AnomalyScore(score=6.0, factors=[], threshold=5.0, is_anomaly=True),
            AnomalyScore(score=8.0, factors=[], threshold=5.0, is_anomaly=True),
            AnomalyScore(score=3.0, factors=[], threshold=5.0, is_anomaly=False)
        ]
        
        aggregate = engine.calculate_aggregate_score(scores)
        assert aggregate >= 8.0  # Should be at least the max score
        assert aggregate <= 10.0  # Should not exceed maximum
    
    def test_scoring_summary(self):
        """Test scoring engine summary functionality."""
        config = {'anomaly_threshold': 5.0}
        engine = AnomalyScoringEngine(config)
        
        summary = engine.get_scoring_summary()
        
        assert isinstance(summary, dict)
        assert 'total_entity_profiles' in summary
        assert 'total_combinations_observed' in summary
        assert 'unique_combinations' in summary
        assert 'active_users_tracked' in summary
        assert 'detector_weights' in summary
        
        # All values should be non-negative
        for key, value in summary.items():
            if isinstance(value, (int, float)):
                assert value >= 0


class TestAnomalyScoreSchema:
    """Test the AnomalyScore schema and validation."""
    
    def test_anomaly_score_creation(self):
        """Test AnomalyScore object creation."""
        score = AnomalyScore(
            score=7.5,
            factors=["Unusual time", "New action"],
            threshold=5.0,
            is_anomaly=True
        )
        
        assert score.score == 7.5
        assert score.factors == ["Unusual time", "New action"]
        assert score.threshold == 5.0
        assert score.is_anomaly is True
    
    def test_anomaly_score_validation(self):
        """Test AnomalyScore validation logic."""
        # Score above threshold should be anomaly
        score = AnomalyScore(
            score=8.0,
            factors=["High risk action"],
            threshold=5.0,
            is_anomaly=True
        )
        assert score.is_anomaly is True
        
        # Score below threshold should not be anomaly
        score = AnomalyScore(
            score=3.0,
            factors=[],
            threshold=5.0,
            is_anomaly=False
        )
        assert score.is_anomaly is False


@pytest.mark.integration
class TestIntegratedAnomalyDetection:
    """Integration tests for the complete anomaly detection system."""
    
    def test_full_anomaly_detection_pipeline(self):
        """Test the complete anomaly detection pipeline."""
        config = {
            'anomaly_threshold': 5.0,
            'statistical_threshold': 2.5
        }
        
        engine = AnomalyScoringEngine(config)
        
        # Create a series of events to establish patterns
        base_time = datetime.now() - timedelta(days=1)
        events_and_entities = []
        
        # Normal events during business hours
        for i in range(20):
            event = create_test_cloudtrail_event()
            
            entities = [
                create_test_extracted_entity(entity_id="normaluser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
                )
            ]
            
            events_and_entities.append((event, entities))
        
        # Process normal events to establish baseline
        normal_scores = []
        for event, entities in events_and_entities:
            scores = engine.score_event(event, entities)
            aggregate = engine.calculate_aggregate_score(scores)
            normal_scores.append(aggregate)
        
        # Create anomalous event (unusual time + new action)
        anomalous_event = create_test_cloudtrail_event()
        
        anomalous_entities = [
            create_test_extracted_entity(entity_id="normaluser", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
            ),
            create_test_extracted_entity(entity_id="203.0.113.1", entity_type=EntityType.IP_ADDRESS, confidence=0.95
            )
        ]
        
        # Score anomalous event
        anomaly_scores = engine.score_event(anomalous_event, anomalous_entities)
        anomaly_aggregate = engine.calculate_aggregate_score(anomaly_scores)
        
        # Anomalous event should have higher score than normal events
        max_normal_score = max(normal_scores) if normal_scores else 0
        assert anomaly_aggregate > max_normal_score
        
        # Should detect at least one anomaly
        anomalous_scores = [score for score in anomaly_scores if score.is_anomaly]
        assert len(anomalous_scores) > 0
        
        # Check that factors are provided
        for score in anomalous_scores:
            assert len(score.factors) > 0
    
    def test_performance_with_large_dataset(self):
        """Test performance with larger dataset."""
        config = {'anomaly_threshold': 5.0}
        engine = AnomalyScoringEngine(config)
        
        # Generate 100 events
        events = []
        for i in range(100):
            event = create_test_cloudtrail_event(),
                awsRegion="us-east-1",
                sourceIPAddress=f"192.168.1.{100 + i%10}",
                userAgent="aws-cli/2.0.0",
                requestParameters={},
                responseElements={}
            )
            
            entities = [
                create_test_extracted_entity(entity_id=f"user{i%5}", entity_type=EntityType.IAM_USER_ARN, confidence=0.9
                )
            ]
            
            events.append((event, entities))
        
        # Process all events and measure basic performance
        start_time = datetime.now()
        
        for event, entities in events:
            scores = engine.score_event(event, entities)
            aggregate = engine.calculate_aggregate_score(scores)
        
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        # Should process 100 events in reasonable time (< 10 seconds)
        assert processing_time < 10.0
        
        # Should have built up some behavioral profiles
        summary = engine.get_scoring_summary()
        assert summary['total_entity_profiles'] > 0