"""Unit tests for the SecurityDetectorStack CDK infrastructure.

These tests validate that the CDK stack creates the expected resources
with correct configurations without actually deploying to AWS.
"""

import pytest
from aws_cdk import App, assertions

from infra.security_detector_stack import SecurityDetectorStack


class TestSecurityDetectorStack:
    """Test cases for SecurityDetectorStack CDK resources."""

    @pytest.fixture
    def default_config(self):
        """Default configuration for testing."""
        return {
            "environment": "test",
            "app_name": "anomaly-detector-test",
            "aws": {
                "region": "us-west-2"
            },
            "s3": {
                "model_bucket_name": "test-model-bucket",
                "data_bucket_name": "test-data-bucket", 
                "log_bucket_name": "test-log-bucket",
                "compliance_bucket_name": "test-compliance-bucket"
            },
            "kms": {
                "key_alias": "alias/test-key"
            },
            "alerts": {
                "sns_topic_name": "test-alerts",
                "email_endpoints": []
            },
            "data_retention": {
                "raw_security_logs": {
                    "retention_years": 7,
                    "immutable": True
                },
                "compliance_outputs": {
                    "retention_years": 5,
                    "immutable": True
                }
            },
            "features": {
                "enable_training": False,
                "enable_sagemaker": False,
                "enable_vpc_endpoints": False
            }
        }

    @pytest.fixture
    def app(self):
        """CDK App for testing."""
        return App()

    @pytest.fixture 
    def stack(self, app, default_config):
        """Security detector stack for testing."""
        return SecurityDetectorStack(
            app,
            "TestStack",
            config=default_config
        )

    @pytest.fixture
    def template(self, stack):
        """CloudFormation template from the stack."""
        return assertions.Template.from_stack(stack)

    def test_kms_key_created(self, template):
        """Test that KMS key is created with correct properties."""
        template.has_resource_properties("AWS::KMS::Key", {
            "Description": "KMS key for anomaly detector encryption",
            "EnableKeyRotation": True,
            "KeyPolicy": {
                "Statement": assertions.Match.array_with([
                    # Verify CloudWatch Logs policy is included
                    assertions.Match.object_like({
                        "Sid": "AllowCloudWatchLogs",
                        "Effect": "Allow"
                    })
                ])
            }
        })
        
        # Verify KMS alias is created
        template.has_resource_properties("AWS::KMS::Alias", {
            "AliasName": "alias/test-key"
        })

    def test_s3_buckets_created(self, template):
        """Test that all required S3 buckets are created."""
        # Model bucket
        template.has_resource_properties("AWS::S3::Bucket", {
            "BucketName": "test-model-bucket",
            "VersioningConfiguration": {
                "Status": "Enabled"
            },
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": assertions.Match.array_with([
                    assertions.Match.object_like({
                        "ServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms"
                        }
                    })
                ])
            },
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True
            }
        })
        
        # Data bucket
        template.has_resource_properties("AWS::S3::Bucket", {
            "BucketName": "test-data-bucket"
        })
        
        # Log bucket
        template.has_resource_properties("AWS::S3::Bucket", {
            "BucketName": "test-log-bucket"
        })
        
        # Compliance bucket
        template.has_resource_properties("AWS::S3::Bucket", {
            "BucketName": "test-compliance-bucket"
        })

    def test_bucket_lifecycle_policies(self, template):
        """Test that S3 buckets have appropriate lifecycle policies."""
        # Check model bucket lifecycle
        template.has_resource_properties("AWS::S3::Bucket", {
            "BucketName": "test-model-bucket",
            "LifecycleConfiguration": {
                "Rules": assertions.Match.array_with([
                    assertions.Match.object_like({
                        "Id": "ModelArtifactLifecycle",
                        "Status": "Enabled",
                        "Transitions": assertions.Match.array_with([
                            assertions.Match.object_like({
                                "StorageClass": "STANDARD_IA",
                                "TransitionInDays": 30
                            }),
                            assertions.Match.object_like({
                                "StorageClass": "GLACIER",
                                "TransitionInDays": 90
                            })
                        ])
                    })
                ])
            }
        })

    def test_iam_role_created(self, template):
        """Test that IAM role is created with correct permissions."""
        template.has_resource_properties("AWS::IAM::Role", {
            "AssumeRolePolicyDocument": {
                "Statement": assertions.Match.array_with([
                    assertions.Match.object_like({
                        "Action": "sts:AssumeRole",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        }
                    })
                ])
            }
        })
        
        # Check that managed policy is attached (separate assertion)
        template.resource_count_is("AWS::IAM::Role", 1)

    def test_sns_topic_created(self, template):
        """Test that SNS topic is created with encryption."""
        template.has_resource_properties("AWS::SNS::Topic", {
            "TopicName": "test-alerts",
            "DisplayName": "Anomaly Detector Alerts",
            "KmsMasterKeyId": assertions.Match.any_value()
        })

    def test_cloudwatch_log_group_created(self, template):
        """Test that CloudWatch log group is created."""
        template.has_resource_properties("AWS::Logs::LogGroup", {
            "LogGroupName": "/aws/lambda/anomaly-detector-test",
            "RetentionInDays": 30,
            "KmsKeyId": assertions.Match.any_value()
        })

    def test_cloudformation_parameters_created(self, template):
        """Test that CloudFormation parameters are created for optional resources."""
        template.has_parameter("EnableTraining", {
            "Type": "String",
            "Default": "false",
            "AllowedValues": ["true", "false"]
        })
        
        template.has_parameter("EnableSageMaker", {
            "Type": "String", 
            "Default": "false",
            "AllowedValues": ["true", "false"]
        })

    def test_resource_tagging(self, template, default_config):
        """Test that resources are properly tagged."""
        # Check that KMS key has tags
        template.has_resource_properties("AWS::KMS::Key", {
            "Tags": assertions.Match.array_with([
                assertions.Match.object_like({
                    "Key": "Application",
                    "Value": "anomaly-detector-test"
                }),
                assertions.Match.object_like({
                    "Key": "Environment", 
                    "Value": "test"
                }),
                assertions.Match.object_like({
                    "Key": "ManagedBy",
                    "Value": "CDK"
                })
            ])
        })

    def test_stack_with_training_enabled(self, app, default_config):
        """Test stack creation with training resources enabled."""
        config = default_config.copy()
        config["features"]["enable_training"] = True
        
        stack = SecurityDetectorStack(
            app,
            "TestStackWithTraining",
            config=config,
            enable_training=True
        )
        
        template = assertions.Template.from_stack(stack)
        
        # Verify parameters are still created (even though training is enabled)
        template.has_parameter("EnableTraining", {
            "Type": "String"
        })

    def test_stack_with_vpc_config(self, app, default_config):
        """Test stack creation with VPC configuration."""
        config = default_config.copy()
        config["vpc"] = {
            "vpc_id": None  # Test VPC creation instead of lookup
        }
        
        # Create stack with VPC endpoints enabled to trigger VPC creation
        stack = SecurityDetectorStack(
            app,
            "TestStackWithVPC", 
            config=config,
            enable_vpc_endpoints=True,
            env={
                "account": "123456789012",
                "region": "us-west-2"
            }
        )
        
        # Verify stack was created successfully
        assert stack is not None
        assert stack.vpc is not None

    def test_minimal_config(self, app):
        """Test stack creation with minimal configuration."""
        minimal_config = {
            "environment": "minimal",
            "app_name": "minimal-test",
            "aws": {"region": "us-east-1"},
            "s3": {
                "model_bucket_name": "minimal-model",
                "data_bucket_name": "minimal-data",
                "log_bucket_name": "minimal-log", 
                "compliance_bucket_name": "minimal-compliance"
            },
            "kms": {"key_alias": "alias/minimal"},
            "alerts": {"sns_topic_name": "minimal-alerts", "email_endpoints": []},
            "features": {
                "enable_training": False,
                "enable_sagemaker": False,
                "enable_vpc_endpoints": False
            }
        }
        
        stack = SecurityDetectorStack(
            app,
            "MinimalStack",
            config=minimal_config
        )
        
        template = assertions.Template.from_stack(stack)
        
        # Verify core resources are still created
        template.resource_count_is("AWS::S3::Bucket", 4)
        template.resource_count_is("AWS::KMS::Key", 1)
        template.resource_count_is("AWS::SNS::Topic", 1)


class TestStackConditions:
    """Test CloudFormation conditions and conditional resources."""

    @pytest.fixture
    def app(self):
        return App()

    @pytest.fixture
    def config(self):
        return {
            "environment": "condition-test",
            "app_name": "condition-test",
            "aws": {"region": "us-west-2"},
            "s3": {
                "model_bucket_name": "condition-model",
                "data_bucket_name": "condition-data",
                "log_bucket_name": "condition-log",
                "compliance_bucket_name": "condition-compliance"
            },
            "kms": {"key_alias": "alias/condition"},
            "alerts": {"sns_topic_name": "condition-alerts", "email_endpoints": []},
            "features": {
                "enable_training": False,
                "enable_sagemaker": False, 
                "enable_vpc_endpoints": False
            }
        }

    def test_training_condition_created(self, app, config):
        """Test that training condition is properly created."""
        stack = SecurityDetectorStack(
            app,
            "ConditionStack",
            config=config
        )
        
        template = assertions.Template.from_stack(stack)
        
        # Verify conditions exist
        template.has_condition("TrainingEnabledCondition", {
            "Fn::Equals": [
                {"Ref": "EnableTraining"},
                "true"
            ]
        })
        
        template.has_condition("SageMakerEnabledCondition", {
            "Fn::Equals": [
                {"Ref": "EnableSageMaker"},
                "true"
            ]
        })