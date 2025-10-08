"""Tests for data retention and lifecycle management."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from detector.retention import (
    RetentionPolicyManager,
    DataTier,
    StorageClass,
    validate_bucket_compliance,
    apply_retention_policies_to_bucket
)


class TestRetentionPolicyManager:
    """Test cases for the RetentionPolicyManager class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            "data_retention": {
                "raw_security_logs": {
                    "retention_years": 7,
                    "immutable": True,
                    "mfa_delete": True,
                    "lifecycle_transitions": [
                        {"days": 30, "storage_class": "STANDARD_IA"},
                        {"days": 365, "storage_class": "GLACIER"},
                        {"days": 1095, "storage_class": "DEEP_ARCHIVE"}
                    ]
                },
                "compliance_outputs": {
                    "retention_years": 5,
                    "immutable": True,
                    "lifecycle_transitions": [
                        {"days": 90, "storage_class": "STANDARD_IA"},
                        {"days": 730, "storage_class": "GLACIER"}
                    ]
                },
                "model_artifacts": {
                    "retention_years": 3,
                    "immutable": False,
                    "lifecycle_transitions": [
                        {"days": 30, "storage_class": "STANDARD_IA"},
                        {"days": 90, "storage_class": "GLACIER"}
                    ]
                }
            }
        }
    
    @patch('detector.retention.boto3.Session')
    def test_initialization(self, mock_session):
        """Test RetentionPolicyManager initialization."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        manager = RetentionPolicyManager(self.config)
        
        assert manager.config == self.config
        assert manager.retention_config == self.config["data_retention"]
        mock_session.assert_called_once()
    
    @patch('detector.retention.boto3.Session')
    def test_initialization_with_profile(self, mock_session):
        """Test initialization with AWS profile."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        manager = RetentionPolicyManager(self.config, aws_profile="test-profile")
        
        mock_session.assert_called_once_with(profile_name="test-profile")
    
    @patch('detector.retention.boto3.Session')
    def test_apply_lifecycle_policy(self, mock_session):
        """Test applying lifecycle policy to bucket."""
        mock_s3_client = Mock()
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_s3_client
        mock_session.return_value = mock_session_instance
        
        manager = RetentionPolicyManager(self.config)
        manager.s3_client = mock_s3_client
        
        # Test applying policy to raw security logs
        tier_config = self.config["data_retention"]["raw_security_logs"]
        manager._apply_lifecycle_policy("test-bucket", tier_config)
        
        # Verify lifecycle configuration was applied
        mock_s3_client.put_bucket_lifecycle_configuration.assert_called_once()
        call_args = mock_s3_client.put_bucket_lifecycle_configuration.call_args
        
        assert call_args[1]['Bucket'] == 'test-bucket'
        lifecycle_config = call_args[1]['LifecycleConfiguration']
        
        # Check rule configuration
        rules = lifecycle_config['Rules']
        assert len(rules) == 1
        
        rule = rules[0]
        assert rule['ID'] == 'RetentionPolicy-test-bucket'
        assert rule['Status'] == 'Enabled'
        assert len(rule['Transitions']) == 3
        assert rule['Expiration']['Days'] == 7 * 365 + 30  # 7 years + grace period
    
    @patch('detector.retention.boto3.Session')
    def test_enable_object_lock(self, mock_session):
        """Test enabling Object Lock for immutability."""
        mock_s3_client = Mock()
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_s3_client
        mock_session.return_value = mock_session_instance
        
        manager = RetentionPolicyManager(self.config)
        manager.s3_client = mock_s3_client
        
        tier_config = self.config["data_retention"]["raw_security_logs"]
        manager._enable_object_lock("test-bucket", tier_config)
        
        # Verify Object Lock configuration was applied
        mock_s3_client.put_object_lock_configuration.assert_called_once()
        call_args = mock_s3_client.put_object_lock_configuration.call_args
        
        assert call_args[1]['Bucket'] == 'test-bucket'
        lock_config = call_args[1]['ObjectLockConfiguration']
        
        assert lock_config['ObjectLockEnabled'] == 'Enabled'
        assert lock_config['Rule']['DefaultRetention']['Mode'] == 'GOVERNANCE'
        assert lock_config['Rule']['DefaultRetention']['Years'] == 7
    
    @patch('detector.retention.boto3.Session')
    def test_validate_lifecycle_policy_compliant(self, mock_session):
        """Test validation of compliant lifecycle policy."""
        mock_s3_client = Mock()
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_s3_client
        mock_session.return_value = mock_session_instance
        
        # Mock successful lifecycle configuration response
        mock_s3_client.get_bucket_lifecycle_configuration.return_value = {
            'Rules': [
                {
                    'ID': 'TestRule',
                    'Status': 'Enabled',
                    'Expiration': {'Days': 2555},  # 7 years
                    'Transitions': [
                        {'Days': 30, 'StorageClass': 'STANDARD_IA'},
                        {'Days': 365, 'StorageClass': 'GLACIER'},
                        {'Days': 1095, 'StorageClass': 'DEEP_ARCHIVE'}
                    ]
                }
            ]
        }
        
        manager = RetentionPolicyManager(self.config)
        manager.s3_client = mock_s3_client
        
        result = manager._validate_lifecycle_policy("test-bucket", DataTier.RAW_SECURITY_LOGS)
        
        assert result["compliant"] is True
        assert len(result["issues"]) == 0
    
    @patch('detector.retention.boto3.Session')
    def test_validate_lifecycle_policy_non_compliant(self, mock_session):
        """Test validation of non-compliant lifecycle policy."""
        mock_s3_client = Mock()
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_s3_client
        mock_session.return_value = mock_session_instance
        
        # Mock lifecycle configuration with insufficient retention
        mock_s3_client.get_bucket_lifecycle_configuration.return_value = {
            'Rules': [
                {
                    'ID': 'TestRule',
                    'Status': 'Enabled',
                    'Expiration': {'Days': 365},  # Only 1 year
                    'Transitions': []
                }
            ]
        }
        
        manager = RetentionPolicyManager(self.config)
        manager.s3_client = mock_s3_client
        
        result = manager._validate_lifecycle_policy("test-bucket", DataTier.RAW_SECURITY_LOGS)
        
        assert result["compliant"] is False
        assert len(result["issues"]) > 0
        assert "Retention period" in result["issues"][0]
    
    @patch('detector.retention.boto3.Session')
    def test_validate_object_lock_compliant(self, mock_session):
        """Test validation of compliant Object Lock configuration."""
        mock_s3_client = Mock()
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_s3_client
        mock_session.return_value = mock_session_instance
        
        # Mock Object Lock configuration response
        mock_s3_client.get_object_lock_configuration.return_value = {
            'ObjectLockConfiguration': {
                'ObjectLockEnabled': 'Enabled',
                'Rule': {
                    'DefaultRetention': {
                        'Mode': 'GOVERNANCE',
                        'Years': 7
                    }
                }
            }
        }
        
        manager = RetentionPolicyManager(self.config)
        manager.s3_client = mock_s3_client
        
        result = manager._validate_object_lock("test-bucket", DataTier.RAW_SECURITY_LOGS)
        
        assert result["compliant"] is True
        assert len(result["issues"]) == 0
    
    @patch('detector.retention.boto3.Session')
    def test_validate_encryption_compliant(self, mock_session):
        """Test validation of compliant encryption configuration."""
        mock_s3_client = Mock()
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_s3_client
        mock_session.return_value = mock_session_instance
        
        # Mock encryption configuration response
        mock_s3_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
                        }
                    }
                ]
            }
        }
        
        manager = RetentionPolicyManager(self.config)
        manager.s3_client = mock_s3_client
        
        result = manager._validate_encryption("test-bucket")
        
        assert result["compliant"] is True
        assert len(result["issues"]) == 0
    
    @patch('detector.retention.boto3.Session')
    def test_collect_storage_metrics(self, mock_session):
        """Test collection of storage metrics."""
        mock_cloudwatch_client = Mock()
        mock_session_instance = Mock()
        mock_session_instance.client.return_value = mock_cloudwatch_client
        mock_session.return_value = mock_session_instance
        
        # Mock CloudWatch metrics responses
        mock_cloudwatch_client.get_metric_statistics.side_effect = [
            {  # Storage size response
                'Datapoints': [
                    {
                        'Timestamp': datetime.utcnow(),
                        'Average': 1073741824  # 1 GB in bytes
                    }
                ]
            },
            {  # Object count response
                'Datapoints': [
                    {
                        'Timestamp': datetime.utcnow(),
                        'Average': 1000
                    }
                ]
            }
        ]
        
        manager = RetentionPolicyManager(self.config)
        manager.cloudwatch_client = mock_cloudwatch_client
        
        metrics = manager._collect_storage_metrics("test-bucket")
        
        assert metrics["total_size_bytes"] == 1073741824
        assert metrics["total_objects"] == 1000
        assert metrics["cost_estimate_monthly"] > 0
    
    @patch('detector.retention.boto3.Session')
    def test_validate_retention_compliance_full(self, mock_session):
        """Test full retention compliance validation."""
        mock_s3_client = Mock()
        mock_cloudwatch_client = Mock()
        mock_session_instance = Mock()
        mock_session_instance.client.side_effect = [mock_s3_client, mock_cloudwatch_client]
        mock_session.return_value = mock_session_instance
        
        manager = RetentionPolicyManager(self.config)
        manager.s3_client = mock_s3_client
        manager.cloudwatch_client = mock_cloudwatch_client
        
        # Mock all validation methods to return compliant
        manager._validate_lifecycle_policy = Mock(return_value={"compliant": True, "issues": []})
        manager._validate_object_lock = Mock(return_value={"compliant": True, "issues": []})
        manager._validate_encryption = Mock(return_value={"compliant": True, "issues": []})
        manager._collect_storage_metrics = Mock(return_value={
            "total_objects": 1000,
            "total_size_bytes": 1073741824,
            "cost_estimate_monthly": 23.0
        })
        
        report = manager.validate_retention_compliance("test-bucket", DataTier.RAW_SECURITY_LOGS)
        
        assert report["compliant"] is True
        assert report["bucket_name"] == "test-bucket"
        assert report["data_tier"] == "raw_security_logs"
        assert len(report["issues"]) == 0
        assert "metrics" in report
    
    @patch('detector.retention.boto3.Session')
    def test_generate_compliance_report(self, mock_session):
        """Test generation of compliance report for multiple buckets."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        
        manager = RetentionPolicyManager(self.config)
        
        # Mock validate_retention_compliance
        manager.validate_retention_compliance = Mock(side_effect=[
            {
                "bucket_name": "bucket1",
                "compliant": True,
                "issues": [],
                "metrics": {"cost_estimate_monthly": 50.0, "total_size_bytes": 2**40}
            },
            {
                "bucket_name": "bucket2", 
                "compliant": False,
                "issues": ["Object Lock not enabled"],
                "metrics": {"cost_estimate_monthly": 30.0, "total_size_bytes": 2**39}
            }
        ])
        
        bucket_names = ["bucket1", "bucket2"]
        report = manager.generate_compliance_report(bucket_names)
        
        assert report["total_buckets"] == 2
        assert report["compliant_buckets"] == 1
        assert report["summary"]["compliance_rate"] == 0.5
        assert len(report["summary"]["critical_issues"]) > 0
        assert report["total_cost_monthly"] == 80.0


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    @patch('detector.retention.RetentionPolicyManager')
    def test_validate_bucket_compliance(self, mock_manager_class):
        """Test validate_bucket_compliance convenience function."""
        mock_manager = Mock()
        mock_manager.validate_retention_compliance.return_value = {"compliant": True}
        mock_manager_class.return_value = mock_manager
        
        config = {"data_retention": {}}
        result = validate_bucket_compliance("test-logs-bucket", config)
        
        assert result is True
        mock_manager.validate_retention_compliance.assert_called_once()
        call_args = mock_manager.validate_retention_compliance.call_args[0]
        assert call_args[0] == "test-logs-bucket"
        assert call_args[1] == DataTier.RAW_SECURITY_LOGS
    
    @patch('detector.retention.RetentionPolicyManager')
    def test_apply_retention_policies_to_bucket(self, mock_manager_class):
        """Test apply_retention_policies_to_bucket convenience function."""
        mock_manager = Mock()
        mock_manager.apply_retention_policies.return_value = True
        mock_manager_class.return_value = mock_manager
        
        config = {"data_retention": {}}
        result = apply_retention_policies_to_bucket(
            "test-bucket", 
            DataTier.COMPLIANCE_OUTPUTS, 
            config
        )
        
        assert result is True
        mock_manager.apply_retention_policies.assert_called_once_with(
            "test-bucket", 
            DataTier.COMPLIANCE_OUTPUTS
        )


class TestDataTierEnum:
    """Test DataTier enum values."""
    
    def test_data_tier_values(self):
        """Test DataTier enum contains expected values."""
        assert DataTier.RAW_SECURITY_LOGS == "raw_security_logs"
        assert DataTier.COMPLIANCE_OUTPUTS == "compliance_outputs"
        assert DataTier.MODEL_ARTIFACTS == "model_artifacts"
        assert DataTier.OPERATIONAL_LOGS == "operational_logs"


class TestStorageClassEnum:
    """Test StorageClass enum values."""
    
    def test_storage_class_values(self):
        """Test StorageClass enum contains expected values."""
        assert StorageClass.STANDARD == "STANDARD"
        assert StorageClass.STANDARD_IA == "STANDARD_IA"
        assert StorageClass.GLACIER == "GLACIER"
        assert StorageClass.DEEP_ARCHIVE == "DEEP_ARCHIVE"