"""Data retention and lifecycle management for security logs.

This module implements automated data retention policies, lifecycle management,
and immutability controls for security logs in compliance with regulatory
requirements (SOC 2, PCI DSS, GDPR).
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class DataTier(str, Enum):
    """Data tier classifications for retention policies."""
    RAW_SECURITY_LOGS = "raw_security_logs"
    COMPLIANCE_OUTPUTS = "compliance_outputs"
    MODEL_ARTIFACTS = "model_artifacts"
    OPERATIONAL_LOGS = "operational_logs"


class StorageClass(str, Enum):
    """S3 Storage classes for lifecycle transitions."""
    STANDARD = "STANDARD"
    STANDARD_IA = "STANDARD_IA"
    GLACIER = "GLACIER"
    DEEP_ARCHIVE = "DEEP_ARCHIVE"


class RetentionPolicyManager:
    """Manages data retention policies and lifecycle enforcement."""
    
    def __init__(self, config: Dict[str, Any], aws_profile: Optional[str] = None):
        """Initialize the retention policy manager.
        
        Args:
            config: Configuration dictionary containing retention policies
            aws_profile: AWS profile to use for API calls
        """
        self.config = config
        self.retention_config = config.get("data_retention", {})
        
        # Initialize AWS clients
        session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
        self.s3_client = session.client('s3')
        self.cloudwatch_client = session.client('cloudwatch')
        
    def apply_retention_policies(self, bucket_name: str, data_tier: DataTier) -> bool:
        """Apply retention policies to an S3 bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            data_tier: Data tier classification
            
        Returns:
            True if policies were applied successfully
        """
        try:
            tier_config = self.retention_config.get(data_tier.value, {})
            
            # Apply lifecycle policy
            self._apply_lifecycle_policy(bucket_name, tier_config)
            
            # Apply object lock if required
            if tier_config.get("immutable", False):
                self._enable_object_lock(bucket_name, tier_config)
            
            # Configure bucket notifications
            self._configure_bucket_notifications(bucket_name, data_tier)
            
            logger.info(f"Applied retention policies to bucket {bucket_name} for tier {data_tier}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply retention policies to {bucket_name}: {str(e)}")
            return False
    
    def _apply_lifecycle_policy(self, bucket_name: str, tier_config: Dict[str, Any]) -> None:
        """Apply S3 lifecycle policy to bucket."""
        retention_years = tier_config.get("retention_years", 7)
        transitions = tier_config.get("lifecycle_transitions", [])
        
        # Build lifecycle rules
        rules = []
        
        # Main lifecycle rule
        transitions_list = []
        for transition in transitions:
            transitions_list.append({
                'Days': transition["days"],
                'StorageClass': transition["storage_class"]
            })
        
        rule = {
            'ID': f'RetentionPolicy-{bucket_name}',
            'Status': 'Enabled',
            'Filter': {'Prefix': ''},  # Apply to all objects
            'Transitions': transitions_list,
            'Expiration': {
                'Days': retention_years * 365 + 30  # Add grace period
            }
        }
        
        # Add incomplete multipart upload cleanup
        rule['AbortIncompleteMultipartUpload'] = {'DaysAfterInitiation': 7}
        
        rules.append(rule)
        
        # Apply lifecycle configuration
        lifecycle_config = {'Rules': rules}
        
        self.s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
        
        logger.info(f"Applied lifecycle policy to {bucket_name}: {len(transitions)} transitions, "
                   f"{retention_years} year retention")
    
    def _enable_object_lock(self, bucket_name: str, tier_config: Dict[str, Any]) -> None:
        """Enable Object Lock for immutability."""
        retention_years = tier_config.get("retention_years", 7)
        
        try:
            # Set default object lock retention
            self.s3_client.put_object_lock_configuration(
                Bucket=bucket_name,
                ObjectLockConfiguration={
                    'ObjectLockEnabled': 'Enabled',
                    'Rule': {
                        'DefaultRetention': {
                            'Mode': 'GOVERNANCE',  # Allows privileged deletion
                            'Years': retention_years
                        }
                    }
                }
            )
            
            logger.info(f"Enabled Object Lock on {bucket_name} with {retention_years} year retention")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidBucketState':
                logger.warning(f"Object Lock must be enabled at bucket creation for {bucket_name}")
            else:
                raise
    
    def _configure_bucket_notifications(self, bucket_name: str, data_tier: DataTier) -> None:
        """Configure bucket notifications for compliance monitoring."""
        # This would configure SNS/SQS notifications for:
        # - Object creation events
        # - Lifecycle transition events
        # - Deletion attempts
        # - Restoration requests
        pass
    
    def validate_retention_compliance(self, bucket_name: str, data_tier: DataTier) -> Dict[str, Any]:
        """Validate that retention policies are properly applied and enforced.
        
        Args:
            bucket_name: Name of the S3 bucket to validate
            data_tier: Data tier classification
            
        Returns:
            Compliance validation report
        """
        report = {
            "bucket_name": bucket_name,
            "data_tier": data_tier.value,
            "validation_time": datetime.utcnow().isoformat(),
            "compliant": True,
            "issues": [],
            "metrics": {}
        }
        
        try:
            # Check lifecycle policy
            lifecycle_compliance = self._validate_lifecycle_policy(bucket_name, data_tier)
            report["lifecycle_compliant"] = lifecycle_compliance["compliant"]
            if not lifecycle_compliance["compliant"]:
                report["issues"].extend(lifecycle_compliance["issues"])
                report["compliant"] = False
            
            # Check object lock configuration
            object_lock_compliance = self._validate_object_lock(bucket_name, data_tier)
            report["object_lock_compliant"] = object_lock_compliance["compliant"]
            if not object_lock_compliance["compliant"]:
                report["issues"].extend(object_lock_compliance["issues"])
                report["compliant"] = False
            
            # Check encryption
            encryption_compliance = self._validate_encryption(bucket_name)
            report["encryption_compliant"] = encryption_compliance["compliant"]
            if not encryption_compliance["compliant"]:
                report["issues"].extend(encryption_compliance["issues"])
                report["compliant"] = False
            
            # Collect storage metrics
            report["metrics"] = self._collect_storage_metrics(bucket_name)
            
        except Exception as e:
            report["compliant"] = False
            report["issues"].append(f"Validation error: {str(e)}")
            logger.error(f"Failed to validate retention compliance for {bucket_name}: {str(e)}")
        
        return report
    
    def _validate_lifecycle_policy(self, bucket_name: str, data_tier: DataTier) -> Dict[str, Any]:
        """Validate lifecycle policy configuration."""
        result = {"compliant": True, "issues": []}
        tier_config = self.retention_config.get(data_tier.value, {})
        
        try:
            response = self.s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            rules = response.get('Rules', [])
            
            if not rules:
                result["compliant"] = False
                result["issues"].append("No lifecycle rules configured")
                return result
            
            # Validate retention period
            expected_retention = tier_config.get("retention_years", 7) * 365
            for rule in rules:
                if 'Expiration' in rule:
                    actual_retention = rule['Expiration'].get('Days', 0)
                    if actual_retention < expected_retention:
                        result["compliant"] = False
                        result["issues"].append(
                            f"Retention period {actual_retention} days is less than required "
                            f"{expected_retention} days"
                        )
            
            # Validate transitions
            expected_transitions = tier_config.get("lifecycle_transitions", [])
            if expected_transitions:
                for rule in rules:
                    transitions = rule.get('Transitions', [])
                    if len(transitions) < len(expected_transitions):
                        result["compliant"] = False
                        result["issues"].append("Missing expected lifecycle transitions")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                result["compliant"] = False
                result["issues"].append("No lifecycle configuration found")
            else:
                raise
        
        return result
    
    def _validate_object_lock(self, bucket_name: str, data_tier: DataTier) -> Dict[str, Any]:
        """Validate Object Lock configuration."""
        result = {"compliant": True, "issues": []}
        tier_config = self.retention_config.get(data_tier.value, {})
        
        if not tier_config.get("immutable", False):
            return result  # Object Lock not required for this tier
        
        try:
            response = self.s3_client.get_object_lock_configuration(Bucket=bucket_name)
            lock_config = response.get('ObjectLockConfiguration', {})
            
            if lock_config.get('ObjectLockEnabled') != 'Enabled':
                result["compliant"] = False
                result["issues"].append("Object Lock not enabled")
            
            # Validate retention settings
            rule = lock_config.get('Rule', {})
            default_retention = rule.get('DefaultRetention', {})
            
            if default_retention:
                retention_years = default_retention.get('Years', 0)
                expected_years = tier_config.get("retention_years", 7)
                
                if retention_years < expected_years:
                    result["compliant"] = False
                    result["issues"].append(
                        f"Object Lock retention {retention_years} years is less than "
                        f"required {expected_years} years"
                    )
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ObjectLockConfigurationNotFoundError':
                result["compliant"] = False
                result["issues"].append("Object Lock configuration not found")
            else:
                raise
        
        return result
    
    def _validate_encryption(self, bucket_name: str) -> Dict[str, Any]:
        """Validate bucket encryption configuration."""
        result = {"compliant": True, "issues": []}
        
        try:
            response = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            encryption_config = response.get('ServerSideEncryptionConfiguration', {})
            rules = encryption_config.get('Rules', [])
            
            if not rules:
                result["compliant"] = False
                result["issues"].append("No encryption configuration found")
                return result
            
            # Check for KMS encryption
            kms_found = False
            for rule in rules:
                sse_config = rule.get('ApplyServerSideEncryptionByDefault', {})
                if sse_config.get('SSEAlgorithm') == 'aws:kms':
                    kms_found = True
                    break
            
            if not kms_found:
                result["compliant"] = False
                result["issues"].append("KMS encryption not configured")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                result["compliant"] = False
                result["issues"].append("No encryption configuration found")
            else:
                raise
        
        return result
    
    def _collect_storage_metrics(self, bucket_name: str) -> Dict[str, Any]:
        """Collect storage metrics for cost and compliance reporting."""
        metrics = {
            "total_objects": 0,
            "total_size_bytes": 0,
            "storage_class_distribution": {},
            "cost_estimate_monthly": 0.0
        }
        
        try:
            # Get CloudWatch metrics for the bucket
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            
            # Storage metrics
            response = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/S3',
                MetricName='BucketSizeBytes',
                Dimensions=[
                    {'Name': 'BucketName', 'Value': bucket_name},
                    {'Name': 'StorageType', 'Value': 'StandardStorage'}
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average']
            )
            
            if response['Datapoints']:
                latest_datapoint = max(response['Datapoints'], key=lambda x: x['Timestamp'])
                metrics["total_size_bytes"] = int(latest_datapoint['Average'])
            
            # Object count
            response = self.cloudwatch_client.get_metric_statistics(
                Namespace='AWS/S3',
                MetricName='NumberOfObjects',
                Dimensions=[
                    {'Name': 'BucketName', 'Value': bucket_name},
                    {'Name': 'StorageType', 'Value': 'AllStorageTypes'}
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average']
            )
            
            if response['Datapoints']:
                latest_datapoint = max(response['Datapoints'], key=lambda x: x['Timestamp'])
                metrics["total_objects"] = int(latest_datapoint['Average'])
            
            # Estimate monthly cost (simplified calculation)
            size_gb = metrics["total_size_bytes"] / (1024**3)
            metrics["cost_estimate_monthly"] = size_gb * 0.023  # $0.023/GB for Standard storage
            
        except Exception as e:
            logger.warning(f"Failed to collect storage metrics for {bucket_name}: {str(e)}")
        
        return metrics
    
    def generate_compliance_report(self, bucket_names: List[str]) -> Dict[str, Any]:
        """Generate comprehensive compliance report for multiple buckets.
        
        Args:
            bucket_names: List of bucket names to include in the report
            
        Returns:
            Comprehensive compliance report
        """
        report = {
            "report_timestamp": datetime.utcnow().isoformat(),
            "total_buckets": len(bucket_names),
            "compliant_buckets": 0,
            "total_cost_monthly": 0.0,
            "total_size_tb": 0.0,
            "bucket_reports": [],
            "summary": {
                "compliance_rate": 0.0,
                "critical_issues": [],
                "recommendations": []
            }
        }
        
        # Data tier mapping (this would typically come from config)
        tier_mapping = {
            "logs": DataTier.RAW_SECURITY_LOGS,
            "compliance": DataTier.COMPLIANCE_OUTPUTS,
            "models": DataTier.MODEL_ARTIFACTS
        }
        
        for bucket_name in bucket_names:
            # Determine data tier from bucket name
            data_tier = DataTier.RAW_SECURITY_LOGS  # Default
            for key, tier in tier_mapping.items():
                if key in bucket_name:
                    data_tier = tier
                    break
            
            bucket_report = self.validate_retention_compliance(bucket_name, data_tier)
            report["bucket_reports"].append(bucket_report)
            
            if bucket_report["compliant"]:
                report["compliant_buckets"] += 1
            else:
                # Collect critical issues
                for issue in bucket_report["issues"]:
                    if any(keyword in issue.lower() for keyword in ["encryption", "retention", "object lock"]):
                        report["summary"]["critical_issues"].append(f"{bucket_name}: {issue}")
            
            # Aggregate metrics
            metrics = bucket_report.get("metrics", {})
            report["total_cost_monthly"] += metrics.get("cost_estimate_monthly", 0.0)
            report["total_size_tb"] += metrics.get("total_size_bytes", 0) / (1024**4)
        
        # Calculate compliance rate
        if report["total_buckets"] > 0:
            report["summary"]["compliance_rate"] = report["compliant_buckets"] / report["total_buckets"]
        
        # Generate recommendations
        if report["summary"]["compliance_rate"] < 1.0:
            report["summary"]["recommendations"].append(
                "Review and address compliance issues in non-compliant buckets"
            )
        
        if report["total_cost_monthly"] > 1000:  # $1000/month threshold
            report["summary"]["recommendations"].append(
                "Consider cost optimization for high storage costs"
            )
        
        return report


def validate_bucket_compliance(bucket_name: str, config: Dict[str, Any]) -> bool:
    """Convenience function to validate a single bucket's compliance.
    
    Args:
        bucket_name: Name of the S3 bucket to validate
        config: Configuration dictionary
        
    Returns:
        True if bucket is compliant with retention policies
    """
    manager = RetentionPolicyManager(config)
    
    # Determine data tier from bucket name
    if "logs" in bucket_name:
        data_tier = DataTier.RAW_SECURITY_LOGS
    elif "compliance" in bucket_name:
        data_tier = DataTier.COMPLIANCE_OUTPUTS
    elif "models" in bucket_name:
        data_tier = DataTier.MODEL_ARTIFACTS
    else:
        data_tier = DataTier.OPERATIONAL_LOGS
    
    report = manager.validate_retention_compliance(bucket_name, data_tier)
    return report["compliant"]


def apply_retention_policies_to_bucket(bucket_name: str, data_tier: DataTier, config: Dict[str, Any]) -> bool:
    """Convenience function to apply retention policies to a bucket.
    
    Args:
        bucket_name: Name of the S3 bucket
        data_tier: Data tier classification
        config: Configuration dictionary
        
    Returns:
        True if policies were applied successfully
    """
    manager = RetentionPolicyManager(config)
    return manager.apply_retention_policies(bucket_name, data_tier)