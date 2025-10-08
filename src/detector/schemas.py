"""Security log schemas for CloudTrail and VPC Flow Logs.

This module defines Pydantic models for parsing and validating security logs
from various AWS services. These schemas ensure consistent data processing
and enable type-safe entity extraction.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class EventSource(str, Enum):
    """AWS service event sources."""
    CLOUDTRAIL = "cloudtrail"
    VPC_FLOW = "vpc_flow"
    S3_ACCESS = "s3_access"
    IAM = "iam"


class EntityType(str, Enum):
    """Security-relevant entity types for NER extraction."""
    IAM_ROLE_ARN = "iam_role_arn"
    IAM_USER_ARN = "iam_user_arn"
    IP_ADDRESS = "ip_address"
    VPC_ID = "vpc_id"
    SUBNET_ID = "subnet_id"
    KMS_KEY_ID = "kms_key_id"
    S3_BUCKET = "s3_bucket"
    EC2_INSTANCE_ID = "ec2_instance_id"
    SECURITY_GROUP_ID = "security_group_id"


class RiskLevel(str, Enum):
    """Risk level classifications."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CloudTrailUserIdentity(BaseModel):
    """CloudTrail user identity information."""
    type: str
    principalId: Optional[str] = None
    arn: Optional[str] = None
    accountId: Optional[str] = None
    userName: Optional[str] = None
    sessionContext: Optional[Dict[str, Any]] = None


class CloudTrailEvent(BaseModel):
    """CloudTrail event record schema."""
    eventVersion: str
    userIdentity: CloudTrailUserIdentity
    eventTime: datetime
    eventSource: str
    eventName: str
    awsRegion: str
    sourceIPAddress: Optional[str] = None
    userAgent: Optional[str] = None
    requestParameters: Optional[Dict[str, Any]] = None
    responseElements: Optional[Dict[str, Any]] = None
    requestID: str
    eventID: str
    eventType: str
    recipientAccountId: str
    serviceEventDetails: Optional[Dict[str, Any]] = None
    sharedEventID: Optional[str] = None
    vpcEndpointId: Optional[str] = None

    @field_validator('eventTime', mode='before')
    @classmethod
    def parse_event_time(cls, v: str) -> datetime:
        """Parse CloudTrail timestamp format."""
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        return v


class VPCFlowLogRecord(BaseModel):
    """VPC Flow Log record schema."""
    version: int
    account_id: str
    interface_id: str
    srcaddr: str
    dstaddr: str
    srcport: int
    dstport: int
    protocol: int
    packets: int
    bytes: int
    windowstart: datetime
    windowend: datetime
    action: str  # ACCEPT or REJECT
    flowlogstatus: str  # OK, NODATA, SKIPDATA

    @field_validator('windowstart', 'windowend', mode='before')
    @classmethod
    def parse_timestamps(cls, v):
        """Parse VPC Flow Log Unix timestamps."""
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v)
        return v


class ExtractedEntity(BaseModel):
    """Extracted security entity with metadata."""
    entity_id: str = Field(..., description="The actual entity value (ARN, IP, etc.)")
    entity_type: EntityType = Field(..., description="Type of entity extracted")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Extraction confidence score")
    context: str = Field(..., description="Surrounding text context")
    source_field: str = Field(..., description="Original log field containing the entity")


class AnomalyScore(BaseModel):
    """Anomaly detection score for an entity or event."""
    score: float = Field(..., ge=0.0, le=10.0, description="Anomaly score (0-10, higher = more anomalous)")
    factors: List[str] = Field(default_factory=list, description="Contributing factors to the score")
    threshold: float = Field(..., description="Threshold used for anomaly detection")
    is_anomaly: bool = Field(..., description="Whether this exceeds the anomaly threshold")


class ComplianceOutput(BaseModel):
    """Final compliance and risk assessment output."""
    log_id: str = Field(..., description="Unique identifier for the source log entry")
    event_source: EventSource = Field(..., description="Source of the security log")
    timestamp: datetime = Field(..., description="When the event occurred")

    # Extracted entities
    entities: List[ExtractedEntity] = Field(default_factory=list, description="All extracted entities")

    # Risk assessment
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Overall risk score for this event")
    risk_level: RiskLevel = Field(..., description="Risk level classification")
    anomaly_scores: List[AnomalyScore] = Field(default_factory=list, description="Anomaly scores for entities/patterns")

    # Recommendations
    recommendations: List[str] = Field(default_factory=list, description="Actionable security recommendations")
    requires_attention: bool = Field(..., description="Whether this event requires immediate attention")

    # Audit trail
    processed_at: datetime = Field(default_factory=datetime.utcnow, description="When this analysis was performed")
    processor_version: str = Field(default="1.0.0", description="Version of the analysis engine")


class SecurityLogBatch(BaseModel):
    """Batch of security logs for processing."""
    batch_id: str = Field(..., description="Unique batch identifier")
    source_bucket: str = Field(..., description="S3 bucket containing the logs")
    source_key: str = Field(..., description="S3 key/path to the log file")
    event_source: EventSource = Field(..., description="Type of logs in this batch")
    log_count: int = Field(..., ge=0, description="Number of log entries in the batch")
    size_bytes: int = Field(..., ge=0, description="Size of the log file in bytes")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When the batch was created")


class ProcessingResult(BaseModel):
    """Result of processing a batch of security logs."""
    batch_id: str = Field(..., description="Reference to the source batch")
    total_events: int = Field(..., ge=0, description="Total events processed")
    entities_extracted: int = Field(..., ge=0, description="Total entities extracted")
    anomalies_detected: int = Field(..., ge=0, description="Number of anomalies found")
    high_risk_events: int = Field(..., ge=0, description="Number of high/critical risk events")
    processing_time_seconds: float = Field(..., ge=0.0, description="Time taken to process the batch")
    compliance_outputs: List[ComplianceOutput] = Field(default_factory=list, description="Detailed analysis results")

    # Error handling
    errors: List[str] = Field(default_factory=list, description="Any errors encountered during processing")
    warnings: List[str] = Field(default_factory=list, description="Non-fatal warnings")

    processed_at: datetime = Field(default_factory=datetime.utcnow, description="When processing completed")


# Common entity patterns for regex-based extraction
ENTITY_PATTERNS = {
    EntityType.IAM_ROLE_ARN: [
        r"arn:aws:iam::\d{12}:role/[\w+=,.@-]+",
        r"arn:aws:sts::\d{12}:assumed-role/[\w+=,.@-]+/[\w+=,.@-]+"
    ],
    EntityType.IAM_USER_ARN: [
        r"arn:aws:iam::\d{12}:user/[\w+=,.@-]+"
    ],
    EntityType.IP_ADDRESS: [
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"  # IPv6
    ],
    EntityType.VPC_ID: [
        r"vpc-[0-9a-f]{8,17}"
    ],
    EntityType.SUBNET_ID: [
        r"subnet-[0-9a-f]{8,17}"
    ],
    EntityType.KMS_KEY_ID: [
        r"arn:aws:kms:[\w-]+:\d{12}:key/[0-9a-f-]{36}",
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"  # Key ID
    ],
    EntityType.S3_BUCKET: [
        r"arn:aws:s3:::[\w.-]+",
        r"[\w.-]+\.s3\.amazonaws\.com",
        r"s3://[\w.-]+"
    ],
    EntityType.EC2_INSTANCE_ID: [
        r"i-[0-9a-f]{8,17}"
    ],
    EntityType.SECURITY_GROUP_ID: [
        r"sg-[0-9a-f]{8,17}"
    ]
}


def get_entity_patterns(entity_type: EntityType) -> List[str]:
    """Get regex patterns for a specific entity type."""
    return ENTITY_PATTERNS.get(entity_type, [])


def get_all_entity_patterns() -> Dict[EntityType, List[str]]:
    """Get all entity extraction patterns."""
    return ENTITY_PATTERNS.copy()
