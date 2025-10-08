"""Entity extraction for security logs using regex patterns.

This module extracts entities (IAM roles, IP addresses, resource IDs, etc.)
from security log events using predefined regex patterns. It provides
confidence scoring and validation for extracted entities.
"""

import re
import logging
from typing import List, Dict, Any, Tuple, Optional, Set
from datetime import datetime

from .schemas import (
    ExtractedEntity,
    EntityType,
    EventSource,
    CloudTrailEvent,
    VPCFlowLogRecord,
    get_entity_patterns,
    get_all_entity_patterns
)

logger = logging.getLogger(__name__)


class EntityExtractor:
    """Extracts entities from security log events using regex patterns."""
    
    def __init__(self):
        """Initialize the entity extractor with compiled regex patterns."""
        self.patterns = get_all_entity_patterns()
        self.compiled_patterns = {}
        
        # Compile all regex patterns for better performance
        for entity_type, patterns in self.patterns.items():
            self.compiled_patterns[entity_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        
        logger.info(f"Initialized EntityExtractor with patterns for {len(self.patterns)} entity types")
    
    def extract_from_text(self, text: str, 
                         entity_types: Optional[List[EntityType]] = None,
                         confidence_threshold: float = 0.7) -> List[ExtractedEntity]:
        """Extract entities from arbitrary text using regex patterns.
        
        Args:
            text: Text to extract entities from
            entity_types: Specific entity types to look for (None = all types)
            confidence_threshold: Minimum confidence score for entities
            
        Returns:
            List of extracted entities with confidence scores
        """
        if entity_types is None:
            entity_types = list(EntityType)
        
        entities = []
        seen_entities = set()  # Deduplicate identical entities
        
        for entity_type in entity_types:
            if entity_type not in self.compiled_patterns:
                continue
                
            for pattern in self.compiled_patterns[entity_type]:
                matches = pattern.finditer(text)
                
                for match in matches:
                    entity_id = match.group(0)
                    
                    # Skip if we've already found this exact entity
                    entity_key = (entity_type, entity_id)
                    if entity_key in seen_entities:
                        continue
                    seen_entities.add(entity_key)
                    
                    # Calculate confidence based on pattern specificity and context
                    confidence = self._calculate_confidence(
                        entity_type, entity_id, text, match
                    )
                    
                    if confidence >= confidence_threshold:
                        entity = ExtractedEntity(
                            entity_type=entity_type,
                            entity_id=entity_id,
                            confidence=confidence,
                            context=text[max(0, match.start()-20):match.end()+20],
                            source_field="text_content"
                        )
                        entities.append(entity)
        
        logger.debug(f"Extracted {len(entities)} entities from text")
        return entities
    
    def extract_from_cloudtrail_event(self, event: CloudTrailEvent) -> List[ExtractedEntity]:
        """Extract entities from a CloudTrail event.
        
        Args:
            event: Parsed CloudTrail event
            
        Returns:
            List of extracted entities with source field information
        """
        entities = []
        
        # Extract from user identity
        if event.userIdentity:
            if event.userIdentity.arn:
                arn_entities = self._extract_from_arn(
                    event.userIdentity.arn, "userIdentity.arn"
                )
                entities.extend(arn_entities)
            
            if event.userIdentity.userName:
                user_entities = self.extract_from_text(
                    event.userIdentity.userName, [EntityType.IAM_USER_ARN]
                )
                for entity in user_entities:
                    entity.source_field = "userIdentity.userName"
                entities.extend(user_entities)
        
        # Extract from source IP
        if event.sourceIPAddress:
            ip_entities = self.extract_from_text(
                event.sourceIPAddress, [EntityType.IP_ADDRESS]
            )
            for entity in ip_entities:
                entity.source_field = "sourceIPAddress"
            entities.extend(ip_entities)
        
        # Extract from request parameters
        if event.requestParameters:
            for key, value in event.requestParameters.items():
                if isinstance(value, str):
                    param_entities = self.extract_from_text(value)
                    for entity in param_entities:
                        entity.source_field = f"requestParameters.{key}"
                    entities.extend(param_entities)
        
        # Extract from response elements
        if event.responseElements:
            for key, value in event.responseElements.items():
                if isinstance(value, str):
                    response_entities = self.extract_from_text(value)
                    for entity in response_entities:
                        entity.source_field = f"responseElements.{key}"
                    entities.extend(response_entities)
        
        # Extract from event name (might contain service info)
        service_entities = self._extract_service_info(event.eventName, "eventName")
        entities.extend(service_entities)
        
        # Deduplicate entities
        entities = self._deduplicate_entities(entities)
        
        logger.debug(f"Extracted {len(entities)} entities from CloudTrail event {event.eventID}")
        return entities
    
    def extract_from_vpc_flow_log(self, record: VPCFlowLogRecord) -> List[ExtractedEntity]:
        """Extract entities from a VPC Flow Log record.
        
        Args:
            record: Parsed VPC Flow Log record
            
        Returns:
            List of extracted entities
        """
        entities = []
        
        # Extract source and destination IP addresses
        for ip_field, field_name in [
            (record.srcaddr, "srcaddr"),
            (record.dstaddr, "dstaddr")
        ]:
            ip_entities = self.extract_from_text(ip_field, [EntityType.IP_ADDRESS])
            for entity in ip_entities:
                entity.source_field = field_name
            entities.extend(ip_entities)
        
        # Extract network interface ID
        if record.interface_id:
            eni_entities = self.extract_from_text(
                record.interface_id, [EntityType.EC2_INSTANCE_ID]  # ENI patterns
            )
            for entity in eni_entities:
                entity.source_field = "interface_id"
            entities.extend(eni_entities)
        
        # Extract account ID
        if record.account_id:
            # Account IDs are a special case - validate format
            if self._is_valid_account_id(record.account_id):
                entity = ExtractedEntity(
                    entity_type=EntityType.IAM_ROLE_ARN,  # Use as proxy for account
                    entity_id=record.account_id,
                    confidence=0.95,
                    context=f"AWS Account: {record.account_id}",
                    source_field="account_id"
                )
                entities.append(entity)
        
        entities = self._deduplicate_entities(entities)
        
        logger.debug(f"Extracted {len(entities)} entities from VPC Flow Log")
        return entities
    
    def _extract_from_arn(self, arn: str, source_field: str) -> List[ExtractedEntity]:
        """Extract entities from an AWS ARN with high confidence.
        
        Args:
            arn: AWS ARN string
            source_field: Field name where ARN was found
            
        Returns:
            List of extracted entities
        """
        entities = []
        
        # Determine ARN type and extract accordingly
        if ":user/" in arn:
            # IAM User ARN
            user_entities = self.extract_from_text(arn, [EntityType.IAM_USER_ARN])
            for entity in user_entities:
                entity.source_field = source_field
                entity.confidence = min(0.95, entity.confidence + 0.1)  # Boost confidence
            entities.extend(user_entities)
        elif ":role/" in arn or ":assumed-role/" in arn:
            # IAM Role ARN
            role_entities = self.extract_from_text(arn, [EntityType.IAM_ROLE_ARN])
            for entity in role_entities:
                entity.source_field = source_field
                entity.confidence = min(0.95, entity.confidence + 0.1)  # Boost confidence
            entities.extend(role_entities)
        else:
            # Generic ARN - try both types
            arn_entities = self.extract_from_text(arn, [EntityType.IAM_ROLE_ARN, EntityType.IAM_USER_ARN])
            for entity in arn_entities:
                entity.source_field = source_field
                entity.confidence = min(0.95, entity.confidence + 0.1)  # Boost confidence
            entities.extend(arn_entities)
        
        return entities
    
    def _extract_service_info(self, event_name: str, source_field: str) -> List[ExtractedEntity]:
        """Extract AWS service information from event names.
        
        Args:
            event_name: CloudTrail event name
            source_field: Field name where event name was found
            
        Returns:
            List of service-related entities
        """
        entities = []
        
        # For now, we don't extract API call names as entities since we don't have
        # a dedicated entity type for them. This prevents false positives where
        # event names like "GetObject" get classified as IP addresses.
        # Future: Add API_CALL or AWS_SERVICE entity type if needed.
        
        logger.debug(f"Skipping service extraction for event: {event_name}")
        return entities
    
    def _calculate_confidence(self, entity_type: EntityType, entity_id: str, 
                            full_text: str, match: re.Match) -> float:
        """Calculate confidence score for an extracted entity.
        
        Args:
            entity_type: Type of entity extracted
            entity_id: The extracted entity ID
            full_text: Full text where entity was found
            match: Regex match object
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = 0.7
        
        # Boost confidence for well-formed entities
        if entity_type == EntityType.IAM_ROLE_ARN and entity_id.startswith('arn:aws:'):
            base_confidence = 0.95
        elif entity_type == EntityType.VPC_ID and entity_id.startswith('vpc-'):
            base_confidence = 0.9
        elif entity_type == EntityType.S3_BUCKET and len(entity_id) >= 3:
            base_confidence = 0.85
        elif entity_type == EntityType.KMS_KEY_ID and len(entity_id) == 36:  # UUID format
            base_confidence = 0.9
        elif entity_type == EntityType.EC2_INSTANCE_ID and entity_id.startswith('i-'):
            base_confidence = 0.9
        elif entity_type == EntityType.IP_ADDRESS:
            # Check if it's a valid IP format
            if self._is_valid_ip(entity_id):
                base_confidence = 0.95
        
        # Reduce confidence for very short matches (likely false positives)
        if len(entity_id) < 3:
            base_confidence *= 0.5
        
        # Boost confidence if entity appears in a structured context
        context_window = 50
        start = max(0, match.start() - context_window)
        end = min(len(full_text), match.end() + context_window)
        context = full_text[start:end].lower()
        
        # Look for contextual clues
        if entity_type == EntityType.IAM_ROLE_ARN:
            if any(keyword in context for keyword in ['role', 'user', 'policy', 'arn']):
                base_confidence = min(1.0, base_confidence + 0.05)
        elif entity_type == EntityType.IP_ADDRESS:
            if any(keyword in context for keyword in ['ip', 'address', 'source', 'destination']):
                base_confidence = min(1.0, base_confidence + 0.05)
        
        return round(base_confidence, 3)
    
    def _is_valid_account_id(self, account_id: str) -> bool:
        """Check if a string is a valid AWS account ID.
        
        Args:
            account_id: String to validate
            
        Returns:
            True if valid AWS account ID format
        """
        return len(account_id) == 12 and account_id.isdigit()
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if a string is a valid IP address.
        
        Args:
            ip_str: String to validate
            
        Returns:
            True if valid IP address format
        """
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not (0 <= int(part) <= 255):
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    def _deduplicate_entities(self, entities: List[ExtractedEntity]) -> List[ExtractedEntity]:
        """Remove duplicate entities, keeping the one with highest confidence.
        
        Args:
            entities: List of extracted entities
            
        Returns:
            Deduplicated list of entities
        """
        entity_map = {}
        
        for entity in entities:
            key = (entity.entity_type, entity.entity_id)
            
            if key not in entity_map or entity.confidence > entity_map[key].confidence:
                entity_map[key] = entity
        
        return list(entity_map.values())
    
    def extract_batch(self, events: List[Dict[str, Any]], 
                     event_source: EventSource) -> List[ExtractedEntity]:
        """Extract entities from a batch of events.
        
        Args:
            events: List of event dictionaries
            event_source: Type of events in the batch
            
        Returns:
            Combined list of all extracted entities
        """
        all_entities = []
        
        for event_data in events:
            try:
                if event_source == EventSource.CLOUDTRAIL:
                    event = CloudTrailEvent(**event_data)
                    entities = self.extract_from_cloudtrail_event(event)
                elif event_source == EventSource.VPC_FLOW:
                    record = VPCFlowLogRecord(**event_data)
                    entities = self.extract_from_vpc_flow_log(record)
                else:
                    logger.warning(f"Unsupported event source: {event_source}")
                    continue
                
                all_entities.extend(entities)
                
            except Exception as e:
                logger.error(f"Failed to extract entities from event: {e}")
                continue
        
        # Global deduplication across all events
        all_entities = self._deduplicate_entities(all_entities)
        
        logger.info(f"Extracted {len(all_entities)} unique entities from {len(events)} events")
        return all_entities


def extract_entities_from_batch(events: List[Dict[str, Any]], 
                               event_source: EventSource) -> List[ExtractedEntity]:
    """Convenience function to extract entities from a batch of events.
    
    Args:
        events: List of event dictionaries
        event_source: Type of events in the batch
        
    Returns:
        List of extracted entities
    """
    extractor = EntityExtractor()
    return extractor.extract_batch(events, event_source)