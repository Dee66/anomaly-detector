"""Security Detector CDK Stack.

This stack creates the core infrastructure for the anomaly detector including:
- S3 buckets for data and model storage
- KMS keys for encryption
- IAM roles with least-privilege access
- VPC configuration for secure networking
- SNS topics for alerting
"""

from typing import Any, Dict

from aws_cdk import (
    CfnCondition,
    CfnParameter,
    Duration,
    Fn,
    RemovalPolicy,
    Stack,
    Tags,
)
from aws_cdk import (
    aws_ec2 as ec2,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_kms as kms,
)
from aws_cdk import (
    aws_logs as logs,
)
from aws_cdk import (
    aws_s3 as s3,
)
from aws_cdk import (
    aws_sns as sns,
)
from constructs import Construct


class SecurityDetectorStack(Stack):
    """CDK Stack for the security anomaly detector infrastructure."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        config: Dict[str, Any],
        enable_training: bool = False,
        enable_sagemaker: bool = False,
        enable_vpc_endpoints: bool = False,
        **kwargs
    ) -> None:
        """Initialize the Security Detector Stack.

        Args:
            scope: CDK scope
            construct_id: Stack identifier
            config: Configuration dictionary from config loader
            enable_training: Whether to enable training resources
            enable_sagemaker: Whether to enable SageMaker endpoints
            enable_vpc_endpoints: Whether to enable VPC endpoints
            **kwargs: Additional stack arguments
        """
        super().__init__(scope, construct_id, **kwargs)

        self.config = config

        # CloudFormation parameters for optional resources
        self._create_parameters()

        # Core encryption and security
        self.kms_key = self._create_kms_key()

        # Storage buckets
        self.model_bucket = self._create_model_bucket()
        self.data_bucket = self._create_data_bucket()
        self.log_bucket = self._create_log_bucket()
        self.compliance_bucket = self._create_compliance_bucket()

        # Networking (optional)
        if config.get("vpc", {}).get("vpc_id") or enable_vpc_endpoints:
            self.vpc = self._create_or_import_vpc()
            if enable_vpc_endpoints:
                self._create_vpc_endpoints()
        else:
            self.vpc = None

        # IAM roles
        self.detector_role = self._create_detector_role()

        # Alerting
        self.alerts_topic = self._create_alerts_topic()

        # CloudWatch log group
        self.log_group = self._create_log_group()

        # Optional training resources (gated by CloudFormation condition)
        if enable_training:
            self._create_training_resources()

        # Optional SageMaker resources (gated by CloudFormation condition)
        if enable_sagemaker:
            self._create_sagemaker_resources()

        # Apply consistent tagging
        self._apply_tags()

    def _create_parameters(self) -> None:
        """Create CloudFormation parameters for optional resources."""
        self.enable_training_param = CfnParameter(
            self, "EnableTraining",
            type="String",
            default="false",
            allowed_values=["true", "false"],
            description="Enable training infrastructure resources"
        )

        self.enable_sagemaker_param = CfnParameter(
            self, "EnableSageMaker",
            type="String",
            default="false",
            allowed_values=["true", "false"],
            description="Enable SageMaker inference endpoints"
        )

        # Create conditions
        self.training_enabled_condition = CfnCondition(
            self, "TrainingEnabledCondition",
            expression=Fn.condition_equals(self.enable_training_param.value_as_string, "true")
        )

        self.sagemaker_enabled_condition = CfnCondition(
            self, "SageMakerEnabledCondition",
            expression=Fn.condition_equals(self.enable_sagemaker_param.value_as_string, "true")
        )

    def _create_kms_key(self) -> kms.Key:
        """Create KMS key for encryption."""
        key = kms.Key(
            self, "DetectorKMSKey",
            alias=self.config["kms"]["key_alias"],
            description="KMS key for anomaly detector encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN
        )

        # Allow CloudWatch Logs to use the key
        key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogs",
                effect=iam.Effect.ALLOW,
                principals=[
                    iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")
                ],
                actions=[
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                resources=["*"]
            )
        )

        return key

    def _create_model_bucket(self) -> s3.Bucket:
        """Create S3 bucket for model artifacts."""
        bucket = s3.Bucket(
            self, "ModelBucket",
            bucket_name=self.config["s3"]["model_bucket_name"],
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ModelArtifactLifecycle",
                    enabled=True,
                    transitions=[
                        s3.Transition(
                            storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                            transition_after=Duration.days(30)
                        ),
                        s3.Transition(
                            storage_class=s3.StorageClass.GLACIER,
                            transition_after=Duration.days(90)
                        )
                    ]
                )
            ]
        )
        return bucket

    def _create_data_bucket(self) -> s3.Bucket:
        """Create S3 bucket for training/test data."""
        bucket = s3.Bucket(
            self, "DataBucket",
            bucket_name=self.config["s3"]["data_bucket_name"],
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN
        )
        return bucket

    def _create_log_bucket(self) -> s3.Bucket:
        """Create S3 bucket for security logs with comprehensive retention policy."""
        # Get retention configuration from config
        retention_config = self.config.get("data_retention", {}).get("raw_security_logs", {})
        retention_years = retention_config.get("retention_years", 7)
        enable_object_lock = retention_config.get("immutable", True)
        
        # Define lifecycle transitions based on policy
        lifecycle_transitions = []
        for transition in retention_config.get("lifecycle_transitions", []):
            storage_class_map = {
                "STANDARD_IA": s3.StorageClass.INFREQUENT_ACCESS,
                "GLACIER": s3.StorageClass.GLACIER,
                "DEEP_ARCHIVE": s3.StorageClass.DEEP_ARCHIVE
            }
            lifecycle_transitions.append(
                s3.Transition(
                    storage_class=storage_class_map[transition["storage_class"]],
                    transition_after=Duration.days(transition["days"])
                )
            )
        
        # Default transitions if not configured
        if not lifecycle_transitions:
            lifecycle_transitions = [
                s3.Transition(
                    storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                    transition_after=Duration.days(30)
                ),
                s3.Transition(
                    storage_class=s3.StorageClass.GLACIER,
                    transition_after=Duration.days(365)
                ),
                s3.Transition(
                    storage_class=s3.StorageClass.DEEP_ARCHIVE,
                    transition_after=Duration.days(1095)  # 3 years
                )
            ]

        bucket_props = {
            "bucket_name": self.config["s3"]["log_bucket_name"],
            "encryption": s3.BucketEncryption.KMS,
            "encryption_key": self.kms_key,
            "versioned": True,
            "block_public_access": s3.BlockPublicAccess.BLOCK_ALL,
            "removal_policy": RemovalPolicy.RETAIN,
            "lifecycle_rules": [
                s3.LifecycleRule(
                    id="SecurityLogRetentionPolicy",
                    enabled=True,
                    transitions=lifecycle_transitions,
                    expiration=Duration.days(retention_years * 365 + 30)  # Retention + grace period
                )
            ]
        }
        
        # Add Object Lock if enabled (for immutability)
        if enable_object_lock:
            bucket_props["object_lock_enabled"] = True
            bucket_props["object_lock_default_retention"] = s3.ObjectLockRetention(
                mode=s3.ObjectLockRetentionMode.GOVERNANCE,
                duration=Duration.days(retention_years * 365)
            )
        
        bucket = s3.Bucket(self, "SecurityLogBucket", **bucket_props)
        
        # Enable MFA Delete if configured
        if retention_config.get("mfa_delete", True):
            # Note: MFA Delete can only be enabled via AWS CLI after bucket creation
            # This is documented in the deployment guide
            pass
            
        return bucket

    def _create_compliance_bucket(self) -> s3.Bucket:
        """Create S3 bucket for processed compliance outputs."""
        # Get retention configuration from config
        retention_config = self.config.get("data_retention", {}).get("compliance_outputs", {})
        retention_years = retention_config.get("retention_years", 5)
        enable_object_lock = retention_config.get("immutable", True)
        
        # Define lifecycle transitions
        lifecycle_transitions = []
        for transition in retention_config.get("lifecycle_transitions", []):
            storage_class_map = {
                "STANDARD_IA": s3.StorageClass.INFREQUENT_ACCESS,
                "GLACIER": s3.StorageClass.GLACIER,
                "DEEP_ARCHIVE": s3.StorageClass.DEEP_ARCHIVE
            }
            lifecycle_transitions.append(
                s3.Transition(
                    storage_class=storage_class_map[transition["storage_class"]],
                    transition_after=Duration.days(transition["days"])
                )
            )
        
        # Default transitions if not configured
        if not lifecycle_transitions:
            lifecycle_transitions = [
                s3.Transition(
                    storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                    transition_after=Duration.days(90)
                ),
                s3.Transition(
                    storage_class=s3.StorageClass.GLACIER,
                    transition_after=Duration.days(730)  # 2 years
                )
            ]

        bucket_props = {
            "bucket_name": self.config["s3"]["compliance_bucket_name"],
            "encryption": s3.BucketEncryption.KMS,
            "encryption_key": self.kms_key,
            "versioned": True,
            "block_public_access": s3.BlockPublicAccess.BLOCK_ALL,
            "removal_policy": RemovalPolicy.RETAIN,
            "lifecycle_rules": [
                s3.LifecycleRule(
                    id="ComplianceOutputRetentionPolicy",
                    enabled=True,
                    transitions=lifecycle_transitions,
                    expiration=Duration.days(retention_years * 365)
                )
            ]
        }
        
        # Add Object Lock if enabled
        if enable_object_lock:
            bucket_props["object_lock_enabled"] = True
            bucket_props["object_lock_default_retention"] = s3.ObjectLockRetention(
                mode=s3.ObjectLockRetentionMode.GOVERNANCE,
                duration=Duration.days(retention_years * 365)
            )
        
        return s3.Bucket(self, "ComplianceBucket", **bucket_props)

    def _create_or_import_vpc(self) -> ec2.Vpc:
        """Create new VPC or import existing one."""
        vpc_id = self.config.get("vpc", {}).get("vpc_id")

        if vpc_id:
            # Import existing VPC
            return ec2.Vpc.from_lookup(
                self, "ImportedVPC",
                vpc_id=vpc_id
            )
        else:
            # Create new VPC
            return ec2.Vpc(
                self, "DetectorVPC",
                max_azs=2,
                cidr="10.0.0.0/16",
                subnet_configuration=[
                    ec2.SubnetConfiguration(
                        name="Private",
                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                        cidr_mask=24
                    ),
                    ec2.SubnetConfiguration(
                        name="Public",
                        subnet_type=ec2.SubnetType.PUBLIC,
                        cidr_mask=24
                    )
                ]
            )

    def _create_vpc_endpoints(self) -> None:
        """Create VPC endpoints for AWS services."""
        if not self.vpc:
            return

        # S3 Gateway Endpoint
        self.vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3
        )

        # Interface endpoints for other services
        endpoints = [
            ec2.InterfaceVpcEndpointAwsService.KMS,
            ec2.InterfaceVpcEndpointAwsService.SNS,
            ec2.InterfaceVpcEndpointAwsService.LOGS,
            ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER
        ]

        for service in endpoints:
            self.vpc.add_interface_endpoint(
                f"{service.name}Endpoint",
                service=service,
                private_dns_enabled=True
            )

    def _create_detector_role(self) -> iam.Role:
        """Create IAM role for the anomaly detector service."""
        role = iam.Role(
            self, "DetectorServiceRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaVPCAccessExecutionRole"
                )
            ]
        )

        # Add permissions for S3 buckets
        for bucket in [self.model_bucket, self.data_bucket, self.log_bucket, self.compliance_bucket]:
            bucket.grant_read_write(role)

        # Add KMS permissions
        self.kms_key.grant_encrypt_decrypt(role)

        # Add SNS permissions
        self.alerts_topic.grant_publish(role)

        return role

    def _create_alerts_topic(self) -> sns.Topic:
        """Create SNS topic for alerts."""
        topic = sns.Topic(
            self, "AlertsTopic",
            topic_name=self.config["alerts"]["sns_topic_name"],
            display_name="Anomaly Detector Alerts",
            kms_master_key=self.kms_key
        )

        # Add email subscriptions from config
        for email in self.config["alerts"].get("email_endpoints", []):
            topic.add_subscription(
                sns.EmailSubscription(email)
            )

        return topic

    def _create_log_group(self) -> logs.LogGroup:
        """Create CloudWatch log group."""
        return logs.LogGroup(
            self, "DetectorLogGroup",
            log_group_name=f"/aws/lambda/{self.config['app_name']}",
            encryption_key=self.kms_key,
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.RETAIN
        )

    def _create_training_resources(self) -> None:
        """Create training-specific resources (conditionally)."""
        # This would include SageMaker training jobs, data processing, etc.
        # For now, just a placeholder
        pass

    def _create_sagemaker_resources(self) -> None:
        """Create SageMaker inference resources (conditionally)."""
        # This would include SageMaker endpoints, models, etc.
        # For now, just a placeholder
        pass

    def _apply_tags(self) -> None:
        """Apply consistent tags to all resources."""
        tags = {
            "Application": self.config["app_name"],
            "Environment": self.config["environment"],
            "CostCenter": "SecurityAutomation",
            "ManagedBy": "CDK"
        }

        for key, value in tags.items():
            Tags.of(self).add(key, value)
