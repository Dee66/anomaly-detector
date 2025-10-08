"""Real-time enrichment handler for security logs.

This module implements the core enrichment logic that processes incoming
security logs, extracts entities, calculates anomaly scores, and generates
actionable compliance recommendations.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from detector.entities import EntityExtractor
from detector.schemas import (
    CloudTrailEvent,
    VPCFlowLogRecord,
    ComplianceOutput,
    ExtractedEntity,
    AnomalyScore,
    EventSource,
    RiskLevel
)

logger = logging.getLogger(__name__)


class EnrichmentHandler:
    """Main enrichment handler for real-time log processing."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the enrichment handler.
        
        Args:
            config: Configuration dictionary containing model paths,
                   thresholds, and service endpoints.
        """
        self.config = config or {}
        self.entity_extractor = EntityExtractor()
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure structured logging for audit trail."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def process_cloudtrail_event(
        self, 
        event: CloudTrailEvent
    ) -> ComplianceOutput:
        """Process a CloudTrail event and generate compliance output.
        
        Args:
            event: CloudTrail event to process
            
        Returns:
            ComplianceOutput with entities, scores, and recommendations
        """
        try:
            # Extract entities from the event
            entities = self.entity_extractor.extract_from_cloudtrail_event(event)
            
            # Calculate anomaly scores
            anomaly_scores = self._calculate_anomaly_scores(entities, event)
            
            # Generate compliance output
            compliance_output = ComplianceOutput(
                log_id=event.eventID,
                event_source=EventSource.CLOUDTRAIL,
                timestamp=event.eventTime,
                entities=entities,
                risk_score=max((score.score for score in anomaly_scores), default=0.0),
                risk_level=RiskLevel(self._determine_risk_level(anomaly_scores)),
                anomaly_scores=anomaly_scores,
                recommendations=self._generate_recommendations(entities, anomaly_scores),
                requires_attention=any(score.score >= 7.0 for score in anomaly_scores),
                processed_at=datetime.utcnow()
            )
            
            logger.info(f"Processed CloudTrail event {event.eventID} with {len(entities)} entities")
            return compliance_output
            
        except Exception as e:
            logger.error(f"Error processing CloudTrail event {event.eventID}: {str(e)}")
            raise
    
    def process_vpc_flow_log(
        self,
        log: VPCFlowLogRecord
    ) -> ComplianceOutput:
        """Process a VPC Flow Log and generate compliance output.
        
        Args:
            log: VPC Flow Log to process
            
        Returns:
            ComplianceOutput with entities, scores, and recommendations
        """
        # TODO: Implement VPC Flow Log processing
        # This will be similar to CloudTrail processing but with
        # VPC-specific entity extraction and scoring logic
        raise NotImplementedError("VPC Flow Log processing not yet implemented")
    
    def _calculate_anomaly_scores(
        self,
        entities: List[ExtractedEntity],
        event: CloudTrailEvent
    ) -> List[AnomalyScore]:
        """Calculate anomaly scores for extracted entities.
        
        Args:
            entities: List of extracted entities
            event: Original CloudTrail event for context
            
        Returns:
            List of anomaly scores
        """
        scores = []
        
        for entity in entities:
            # Basic anomaly scoring - this will be enhanced with
            # statistical models and historical data analysis
            base_score = 0.5  # Default neutral score
            
            # Adjust score based on entity type and context
            if entity.entity_type == 'iam_role':
                # Higher score for unknown or rarely used roles
                base_score = self._score_iam_role(entity, event)
            elif entity.entity_type == 'ip_address':
                # Higher score for external or suspicious IPs
                base_score = self._score_ip_address(entity, event)
            elif entity.entity_type == 'vpc_id':
                # Score based on VPC configuration and usage patterns
                base_score = self._score_vpc_id(entity, event)
            
            score = AnomalyScore(
                score=base_score,
                factors=['entity_rarity', 'context_analysis'],
                threshold=5.0,  # Default threshold
                is_anomaly=base_score >= 5.0
            )
            scores.append(score)
        
        return scores
    
    def _score_iam_role(self, entity: ExtractedEntity, event: CloudTrailEvent) -> float:
        """Score IAM role entities for anomalies."""
        # TODO: Implement IAM role scoring logic
        # Consider: role usage patterns, permissions, creation date
        return 0.3  # Placeholder
    
    def _score_ip_address(self, entity: ExtractedEntity, event: CloudTrailEvent) -> float:
        """Score IP address entities for anomalies."""
        # TODO: Implement IP address scoring logic
        # Consider: geolocation, reputation, usage patterns
        return 0.4  # Placeholder
    
    def _score_vpc_id(self, entity: ExtractedEntity, event: CloudTrailEvent) -> float:
        """Score VPC ID entities for anomalies."""
        # TODO: Implement VPC scoring logic
        # Consider: VPC configuration, network patterns
        return 0.2  # Placeholder
    
    def _determine_risk_level(self, scores: List[AnomalyScore]) -> str:
        """Determine overall risk level based on anomaly scores."""
        if not scores:
            return 'low'
        
        max_score = max(score.score for score in scores)
        avg_score = sum(score.score for score in scores) / len(scores)
        
        if max_score >= 8.0 or avg_score >= 6.0:
            return 'high'
        elif max_score >= 6.0 or avg_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(
        self,
        entities: List[ExtractedEntity],
        scores: List[AnomalyScore]
    ) -> List[str]:
        """Generate actionable compliance recommendations."""
        recommendations = []
        
        high_risk_scores = [s for s in scores if s.score >= 0.7]
        
        if high_risk_scores:
            recommendations.append(
                "Review high-risk entities for potential security violations"
            )
        
        # Entity-specific recommendations
        iam_entities = [e for e in entities if e.entity_type in ['iam_role_arn', 'iam_user_arn']]
        if iam_entities:
            recommendations.append(
                "Verify IAM role permissions align with least-privilege principles"
            )
        
        ip_entities = [e for e in entities if e.entity_type == 'ip_address']
        if ip_entities:
            recommendations.append(
                "Validate source IP addresses against allowed network ranges"
            )
        
        if not recommendations:
            recommendations.append("No immediate compliance actions required")
        
        return recommendations


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda entry point for enrichment processing.
    
    This function serves as the main entry point when deployed as
    an AWS Lambda function for real-time log processing.
    """
    try:
        handler = EnrichmentHandler()
        
        # Parse incoming event (from SQS, EventBridge, etc.)
        if 'Records' in event:
            # SQS batch processing
            results = []
            for record in event['Records']:
                log_data = json.loads(record['body'])
                # Process based on log type
                if log_data.get('eventSource'):
                    # CloudTrail event
                    ct_event = CloudTrailEvent(**log_data)
                    result = handler.process_cloudtrail_event(ct_event)
                    results.append(result.model_dump())
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'processed': len(results),
                    'results': results
                }, default=str)
            }
        
        else:
            # Direct invocation
            log_data = event.get('log_data', {})
            if log_data.get('eventSource'):
                ct_event = CloudTrailEvent(**log_data)
                result = handler.process_cloudtrail_event(ct_event)
                return {
                    'statusCode': 200,
                    'body': json.dumps(result.model_dump(), default=str)
                }
        
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid event format'})
        }
        
    except Exception as e:
        logger.error(f"Lambda handler error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }