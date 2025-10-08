"""Anomaly Scoring Engine for Security Event Analysis.

This module implements sophisticated anomaly detection algorithms that analyze
security events and entity patterns to identify potential threats and compliance
violations. It combines statistical analysis, behavioral baselines, and rare
entity combination detection.
"""

import logging
import math
import statistics
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum

import numpy as np
from scipy import stats
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN

from detector.schemas import ExtractedEntity, CloudTrailEvent, ComplianceOutput, AnomalyScore

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    """Types of anomalies detected."""
    STATISTICAL_OUTLIER = "statistical_outlier"
    RARE_ENTITY_COMBO = "rare_entity_combination"
    BEHAVIORAL_DEVIATION = "behavioral_deviation"
    TIME_PATTERN_ANOMALY = "time_pattern_anomaly"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class EntityBehaviorProfile:
    """Behavioral profile for an entity (user, role, IP, etc.)."""
    entity_id: str
    entity_type: str
    first_seen: datetime
    last_seen: datetime
    total_events: int
    unique_actions: Set[str]
    unique_sources: Set[str]
    time_patterns: Dict[int, int]  # hour -> count
    geo_patterns: Dict[str, int]   # region -> count
    baseline_score: float
    risk_factors: List[str]


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""
    entity_id: str
    entity_type: str
    anomaly_type: AnomalyType
    score: float
    confidence: float
    factors: List[str]
    baseline_deviation: float
    context: Dict[str, Any]
    timestamp: datetime


class StatisticalAnomalyDetector:
    """Statistical anomaly detection using Z-score and modified Z-score."""
    
    def __init__(self, threshold: float = 2.5, use_modified_zscore: bool = True):
        """Initialize statistical detector.
        
        Args:
            threshold: Z-score threshold for anomaly detection
            use_modified_zscore: Use modified Z-score (more robust to outliers)
        """
        self.threshold = threshold
        self.use_modified_zscore = use_modified_zscore
    
    def detect_anomalies(self, values: List[float]) -> List[Tuple[int, float]]:
        """Detect statistical anomalies in a series of values.
        
        Args:
            values: List of numerical values to analyze
            
        Returns:
            List of (index, score) tuples for anomalous values
        """
        if len(values) < 3:
            return []
        
        if self.use_modified_zscore:
            scores = self._modified_zscore(values)
        else:
            scores = self._standard_zscore(values)
        
        anomalies = []
        for i, score in enumerate(scores):
            if abs(score) > self.threshold:
                anomalies.append((i, score))
        
        return anomalies
    
    def _standard_zscore(self, values: List[float]) -> List[float]:
        """Calculate standard Z-score."""
        mean_val = statistics.mean(values)
        std_val = statistics.stdev(values) if len(values) > 1 else 1.0
        
        if std_val == 0:
            return [0.0] * len(values)
        
        return [(val - mean_val) / std_val for val in values]
    
    def _modified_zscore(self, values: List[float]) -> List[float]:
        """Calculate modified Z-score using median absolute deviation."""
        median_val = statistics.median(values)
        deviations = [abs(val - median_val) for val in values]
        mad = statistics.median(deviations)
        
        if mad == 0:
            return [0.0] * len(values)
        
        # Modified Z-score formula
        return [0.6745 * (val - median_val) / mad for val in values]


class BehavioralAnomalyDetector:
    """Behavioral anomaly detection based on user/entity patterns."""
    
    def __init__(self, lookback_days: int = 30, min_events: int = 10):
        """Initialize behavioral detector.
        
        Args:
            lookback_days: Number of days to look back for baseline
            min_events: Minimum events required to establish baseline
        """
        self.lookback_days = lookback_days
        self.min_events = min_events
        self.entity_profiles: Dict[str, EntityBehaviorProfile] = {}
    
    def update_entity_profile(self, event: CloudTrailEvent, entities: List[ExtractedEntity]) -> None:
        """Update behavioral profiles for entities in the event."""
        for entity in entities:
            profile_key = f"{entity.entity_type}:{entity.entity_id}"
            
            if profile_key not in self.entity_profiles:
                self.entity_profiles[profile_key] = EntityBehaviorProfile(
                    entity_id=entity.entity_id,
                    entity_type=entity.entity_type,
                    first_seen=event.eventTime,
                    last_seen=event.eventTime,
                    total_events=0,
                    unique_actions=set(),
                    unique_sources=set(),
                    time_patterns=defaultdict(int),
                    geo_patterns=defaultdict(int),
                    baseline_score=0.0,
                    risk_factors=[]
                )
            
            profile = self.entity_profiles[profile_key]
            profile.last_seen = event.eventTime
            profile.total_events += 1
            profile.unique_actions.add(event.eventName)
            
            if event.sourceIPAddress:
                profile.unique_sources.add(event.sourceIPAddress)
            
            # Update time patterns
            hour = event.eventTime.hour
            profile.time_patterns[hour] += 1
            
            # Update geo patterns (simplified - would use actual geolocation)
            profile.geo_patterns[event.awsRegion] += 1
    
    def detect_behavioral_anomalies(
        self, 
        event: CloudTrailEvent, 
        entities: List[ExtractedEntity]
    ) -> List[AnomalyResult]:
        """Detect behavioral anomalies for entities in the event."""
        anomalies = []
        
        for entity in entities:
            profile_key = f"{entity.entity_type}:{entity.entity_id}"
            
            if profile_key not in self.entity_profiles:
                continue
            
            profile = self.entity_profiles[profile_key]
            
            # Skip if insufficient data for baseline
            if profile.total_events < self.min_events:
                continue
            
            # Detect time-based anomalies
            time_anomaly = self._detect_time_anomaly(event, profile)
            if time_anomaly:
                anomalies.append(time_anomaly)
            
            # Detect action anomalies
            action_anomaly = self._detect_action_anomaly(event, profile)
            if action_anomaly:
                anomalies.append(action_anomaly)
            
            # Detect source anomalies
            source_anomaly = self._detect_source_anomaly(event, profile)
            if source_anomaly:
                anomalies.append(source_anomaly)
        
        return anomalies
    
    def _detect_time_anomaly(
        self, 
        event: CloudTrailEvent, 
        profile: EntityBehaviorProfile
    ) -> Optional[AnomalyResult]:
        """Detect time-based behavioral anomalies."""
        hour = event.eventTime.hour
        total_events = sum(profile.time_patterns.values())
        
        if total_events == 0:
            return None
        
        # Calculate expected frequency for this hour
        expected_freq = profile.time_patterns.get(hour, 0) / total_events
        
        # If this hour has very low historical activity (< 5%), flag as anomaly
        if expected_freq < 0.05 and profile.time_patterns.get(hour, 0) < 2:
            score = 8.0 - (expected_freq * 100)  # Higher score for rarer times
            
            return AnomalyResult(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type=AnomalyType.TIME_PATTERN_ANOMALY,
                score=min(score, 10.0),
                confidence=0.8,
                factors=[f"Unusual activity hour: {hour:02d}:00", f"Historical frequency: {expected_freq:.1%}"],
                baseline_deviation=1.0 - expected_freq,
                context={"hour": hour, "expected_frequency": expected_freq},
                timestamp=event.eventTime
            )
        
        return None
    
    def _detect_action_anomaly(
        self, 
        event: CloudTrailEvent, 
        profile: EntityBehaviorProfile
    ) -> Optional[AnomalyResult]:
        """Detect action-based behavioral anomalies."""
        if event.eventName not in profile.unique_actions:
            # New action for this entity
            risk_score = self._calculate_action_risk(event.eventName)
            
            return AnomalyResult(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type=AnomalyType.BEHAVIORAL_DEVIATION,
                score=risk_score,
                confidence=0.7,
                factors=[f"New action: {event.eventName}", "No historical precedent"],
                baseline_deviation=1.0,
                context={"new_action": event.eventName, "known_actions": len(profile.unique_actions)},
                timestamp=event.eventTime
            )
        
        return None
    
    def _detect_source_anomaly(
        self, 
        event: CloudTrailEvent, 
        profile: EntityBehaviorProfile
    ) -> Optional[AnomalyResult]:
        """Detect source-based behavioral anomalies."""
        if not event.sourceIPAddress:
            return None
        
        if event.sourceIPAddress not in profile.unique_sources:
            # New source IP for this entity
            score = 6.0  # Moderate risk for new IP
            
            return AnomalyResult(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                anomaly_type=AnomalyType.BEHAVIORAL_DEVIATION,
                score=score,
                confidence=0.6,
                factors=[f"New source IP: {event.sourceIPAddress}", "No historical precedent"],
                baseline_deviation=1.0,
                context={"new_source_ip": event.sourceIPAddress, "known_sources": len(profile.unique_sources)},
                timestamp=event.eventTime
            )
        
        return None
    
    def _calculate_action_risk(self, action: str) -> float:
        """Calculate risk score for an action."""
        high_risk_actions = {
            "CreateRole", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
            "CreateUser", "DeleteRole", "DeleteUser", "CreateAccessKey",
            "AssumeRole", "GetCredentialsForIdentity", "CreateLoginProfile"
        }
        
        medium_risk_actions = {
            "ListUsers", "ListRoles", "GetUser", "GetRole", "ListAttachedUserPolicies",
            "ListAttachedRolePolicies", "DescribeInstances", "DescribeImages"
        }
        
        if action in high_risk_actions:
            return 9.0
        elif action in medium_risk_actions:
            return 6.0
        else:
            return 4.0  # Default for unknown new actions


class RareEntityCombinationDetector:
    """Detector for rare entity combinations that may indicate threats."""
    
    def __init__(self, rarity_threshold: float = 0.01, min_observations: int = 100):
        """Initialize rare combination detector.
        
        Args:
            rarity_threshold: Threshold below which combinations are considered rare
            min_observations: Minimum total observations before calculating rarity
        """
        self.rarity_threshold = rarity_threshold
        self.min_observations = min_observations
        self.combination_counts: Dict[str, int] = defaultdict(int)
        self.total_combinations = 0
    
    def update_combination_counts(self, entities: List[ExtractedEntity], event: CloudTrailEvent) -> None:
        """Update combination statistics."""
        if len(entities) < 2:
            return
        
        # Create combinations of entity types and actions
        entity_types = [entity.entity_type for entity in entities]
        entity_ids = [entity.entity_id for entity in entities]
        
        # Entity type combinations
        for i in range(len(entity_types)):
            for j in range(i + 1, len(entity_types)):
                combo = tuple(sorted([entity_types[i], entity_types[j]]))
                self.combination_counts[f"types:{combo}"] += 1
        
        # Entity + action combinations
        for entity_type in entity_types:
            combo = f"action:{entity_type}:{event.eventName}"
            self.combination_counts[combo] += 1
        
        # Specific entity + action combinations (more specific)
        for entity_id in entity_ids:
            combo = f"entity_action:{entity_id}:{event.eventName}"
            self.combination_counts[combo] += 1
        
        self.total_combinations += 1
    
    def detect_rare_combinations(
        self, 
        entities: List[ExtractedEntity], 
        event: CloudTrailEvent
    ) -> List[AnomalyResult]:
        """Detect rare entity combinations."""
        if self.total_combinations < self.min_observations:
            return []
        
        anomalies = []
        
        # Check entity type combinations
        entity_types = [entity.entity_type for entity in entities]
        
        for i in range(len(entity_types)):
            for j in range(i + 1, len(entity_types)):
                combo = tuple(sorted([entity_types[i], entity_types[j]]))
                combo_key = f"types:{combo}"
                
                count = self.combination_counts.get(combo_key, 0)
                frequency = count / self.total_combinations
                
                if frequency < self.rarity_threshold and count > 0:
                    score = 10.0 * (1 - frequency / self.rarity_threshold)
                    
                    anomalies.append(AnomalyResult(
                        entity_id=f"{combo[0]}+{combo[1]}",
                        entity_type="combination",
                        anomaly_type=AnomalyType.RARE_ENTITY_COMBO,
                        score=min(score, 10.0),
                        confidence=0.7,
                        factors=[f"Rare entity type combination: {combo}", f"Frequency: {frequency:.4f}"],
                        baseline_deviation=1.0 - frequency,
                        context={"combination": combo, "frequency": frequency, "count": count},
                        timestamp=event.eventTime
                    ))
        
        return anomalies


class PrivilegeEscalationDetector:
    """Detector for privilege escalation patterns."""
    
    def __init__(self):
        """Initialize privilege escalation detector."""
        self.escalation_patterns = {
            # IAM privilege escalation patterns
            "iam_policy_creation": ["CreateRole", "AttachRolePolicy", "AssumeRole"],
            "user_privilege_grant": ["CreateUser", "AttachUserPolicy", "CreateAccessKey"],
            "admin_access": ["AttachUserPolicy", "AttachRolePolicy"],
            # Cross-account patterns
            "cross_account_assume": ["AssumeRole", "GetCredentialsForIdentity"],
        }
        
        self.recent_events: Dict[str, List[CloudTrailEvent]] = defaultdict(list)
        self.lookback_minutes = 30
    
    def detect_privilege_escalation(
        self, 
        event: CloudTrailEvent, 
        entities: List[ExtractedEntity]
    ) -> List[AnomalyResult]:
        """Detect privilege escalation patterns."""
        anomalies = []
        
        # Track events by user identity
        user_key = self._get_user_key(event)
        if not user_key:
            return anomalies
        
        # Clean old events
        cutoff_time = event.eventTime - timedelta(minutes=self.lookback_minutes)
        self.recent_events[user_key] = [
            e for e in self.recent_events[user_key] 
            if e.eventTime > cutoff_time
        ]
        
        # Add current event
        self.recent_events[user_key].append(event)
        
        # Check for escalation patterns
        recent_actions = [e.eventName for e in self.recent_events[user_key]]
        
        for pattern_name, pattern_actions in self.escalation_patterns.items():
            if self._matches_pattern(recent_actions, pattern_actions):
                score = self._calculate_escalation_score(pattern_name, recent_actions)
                
                anomalies.append(AnomalyResult(
                    entity_id=user_key,
                    entity_type="user_behavior",
                    anomaly_type=AnomalyType.PRIVILEGE_ESCALATION,
                    score=score,
                    confidence=0.8,
                    factors=[f"Privilege escalation pattern: {pattern_name}", f"Recent actions: {recent_actions[-5:]}"],
                    baseline_deviation=1.0,
                    context={
                        "pattern": pattern_name,
                        "actions": recent_actions,
                        "time_window_minutes": self.lookback_minutes
                    },
                    timestamp=event.eventTime
                ))
        
        return anomalies
    
    def _get_user_key(self, event: CloudTrailEvent) -> Optional[str]:
        """Get user key for tracking."""
        if event.userIdentity.arn:
            return event.userIdentity.arn
        elif event.userIdentity.userName:
            return event.userIdentity.userName
        return None
    
    def _matches_pattern(self, recent_actions: List[str], pattern_actions: List[str]) -> bool:
        """Check if recent actions match escalation pattern."""
        # Check if all pattern actions appear in recent actions
        for pattern_action in pattern_actions:
            if pattern_action not in recent_actions:
                return False
        return True
    
    def _calculate_escalation_score(self, pattern_name: str, actions: List[str]) -> float:
        """Calculate escalation risk score."""
        base_scores = {
            "iam_policy_creation": 9.0,
            "user_privilege_grant": 8.5,
            "admin_access": 9.5,
            "cross_account_assume": 8.0
        }
        
        base_score = base_scores.get(pattern_name, 7.0)
        
        # Increase score for rapid succession
        if len(actions) >= 3:
            base_score += 1.0
        
        return min(base_score, 10.0)


class AnomalyScoringEngine:
    """Main anomaly scoring engine that orchestrates all detectors."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the anomaly scoring engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.statistical_detector = StatisticalAnomalyDetector(
            threshold=config.get("anomaly_threshold", 2.5)
        )
        self.behavioral_detector = BehavioralAnomalyDetector()
        self.rare_combo_detector = RareEntityCombinationDetector()
        self.privilege_detector = PrivilegeEscalationDetector()
        
        # Scoring weights
        self.detector_weights = {
            AnomalyType.STATISTICAL_OUTLIER: 0.2,
            AnomalyType.RARE_ENTITY_COMBO: 0.25,
            AnomalyType.BEHAVIORAL_DEVIATION: 0.3,
            AnomalyType.TIME_PATTERN_ANOMALY: 0.2,
            AnomalyType.PRIVILEGE_ESCALATION: 0.4,
            AnomalyType.LATERAL_MOVEMENT: 0.35
        }
    
    def score_event(
        self, 
        event: CloudTrailEvent, 
        entities: List[ExtractedEntity]
    ) -> List[AnomalyScore]:
        """Score an event for anomalies.
        
        Args:
            event: CloudTrail event to score
            entities: Extracted entities from the event
            
        Returns:
            List of anomaly scores
        """
        all_anomalies = []
        
        # Update behavioral profiles
        self.behavioral_detector.update_entity_profile(event, entities)
        self.rare_combo_detector.update_combination_counts(entities, event)
        
        # Run behavioral detection
        behavioral_anomalies = self.behavioral_detector.detect_behavioral_anomalies(event, entities)
        all_anomalies.extend(behavioral_anomalies)
        
        # Run rare combination detection
        combo_anomalies = self.rare_combo_detector.detect_rare_combinations(entities, event)
        all_anomalies.extend(combo_anomalies)
        
        # Run privilege escalation detection
        escalation_anomalies = self.privilege_detector.detect_privilege_escalation(event, entities)
        all_anomalies.extend(escalation_anomalies)
        
        # Convert to AnomalyScore objects
        anomaly_scores = []
        for anomaly in all_anomalies:
            # Apply detector weight
            weighted_score = anomaly.score * self.detector_weights.get(anomaly.anomaly_type, 1.0)
            
            anomaly_score = AnomalyScore(
                score=min(weighted_score, 10.0),
                factors=anomaly.factors,
                threshold=self.config.get("anomaly_threshold", 5.0),
                is_anomaly=weighted_score >= self.config.get("anomaly_threshold", 5.0)
            )
            anomaly_scores.append(anomaly_score)
        
        return anomaly_scores
    
    def calculate_aggregate_score(self, anomaly_scores: List[AnomalyScore]) -> float:
        """Calculate aggregate anomaly score for an event.
        
        Args:
            anomaly_scores: List of individual anomaly scores
            
        Returns:
            Aggregate score (0-10)
        """
        if not anomaly_scores:
            return 0.0
        
        # Use max score as primary indicator
        max_score = max(score.score for score in anomaly_scores)
        
        # Apply penalty for multiple anomalies
        num_anomalies = len([s for s in anomaly_scores if s.is_anomaly])
        if num_anomalies > 1:
            multiplier = 1.0 + (num_anomalies - 1) * 0.2  # 20% increase per additional anomaly
            max_score *= multiplier
        
        return min(max_score, 10.0)
    
    def get_scoring_summary(self) -> Dict[str, Any]:
        """Get summary of scoring engine state."""
        return {
            "total_entity_profiles": len(self.behavioral_detector.entity_profiles),
            "total_combinations_observed": self.rare_combo_detector.total_combinations,
            "unique_combinations": len(self.rare_combo_detector.combination_counts),
            "active_users_tracked": len(self.privilege_detector.recent_events),
            "detector_weights": self.detector_weights
        }