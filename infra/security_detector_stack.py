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
    aws_cloudwatch as cloudwatch,
)
from aws_cdk import (
    aws_cloudwatch_actions as cloudwatch_actions,
)
from aws_cdk import (
    aws_s3 as s3,
)
from aws_cdk import (
    aws_sns as sns,
)
from aws_cdk import (
    aws_sns_subscriptions as sns_subs,
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

        # Alerting (create before IAM roles)
        self.alerts_topic = self._create_alerts_topic()

        # IAM roles
        self.detector_role = self._create_detector_role()

        # CloudWatch log group
        self.log_group = self._create_log_group()

        # Create an error metric and alarm for the log group
        self._create_error_metric_and_alarm()

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
        
        # Define lifecycle transitions based on policy
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

        bucket = s3.Bucket(
            self, "SecurityLogBucket",
            bucket_name=self.config["s3"]["log_bucket_name"],
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="SecurityLogRetentionPolicy",
                    enabled=True,
                    transitions=lifecycle_transitions,
                    expiration=Duration.days(retention_years * 365 + 30)  # Retention + grace period
                )
            ]
        )
            
        return bucket

    def _create_compliance_bucket(self) -> s3.Bucket:
        """Create S3 bucket for processed compliance outputs."""
        # Get retention configuration from config
        retention_config = self.config.get("data_retention", {}).get("compliance_outputs", {})
        retention_years = retention_config.get("retention_years", 5)
        
        # Define lifecycle transitions
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

        return s3.Bucket(
            self, "ComplianceBucket",
            bucket_name=self.config["s3"]["compliance_bucket_name"],
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.RETAIN,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ComplianceOutputRetentionPolicy",
                    enabled=True,
                    transitions=lifecycle_transitions,
                    expiration=Duration.days(retention_years * 365)
                )
            ]
        )

    def _create_or_import_vpc(self) -> ec2.Vpc:
        """Create new VPC or import existing one."""
        vpc_id = self.config.get("vpc", {}).get("vpc_id")
        private_only = bool(self.config.get("vpc", {}).get("private_only", False))

        if vpc_id:
            # Import existing VPC
            return ec2.Vpc.from_lookup(
                self, "ImportedVPC",
                vpc_id=vpc_id
            )
        else:
            # Create new VPC
            subnet_configuration = []
            if private_only:
                subnet_configuration.append(
                    ec2.SubnetConfiguration(
                        name="Private",
                        # Use isolated private subnets when creating a private-only VPC so the
                        # construct does not require public subnets for NAT gateways during
                        # unit tests and for private-only deployments.
                        subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                        cidr_mask=24
                    )
                )
            else:
                subnet_configuration = [
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

            return ec2.Vpc(
                self, "DetectorVPC",
                max_azs=2,
                cidr="10.0.0.0/16",
                subnet_configuration=subnet_configuration
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
        # Create well-known interface endpoints. Use static construct ids to avoid
        # unresolved token values appearing in construct ids (which breaks assertions
        # during unit tests).
        mappings = [
            (ec2.InterfaceVpcEndpointAwsService.KMS, "KmsEndpoint"),
            (ec2.InterfaceVpcEndpointAwsService.SNS, "SnsEndpoint"),
            (ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS, "CloudWatchLogsEndpoint"),
            (ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER, "SecretsManagerEndpoint"),
        ]

        for service, construct_id in mappings:
            self.vpc.add_interface_endpoint(
                construct_id,
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
            master_key=self.kms_key
        )

        # Add email subscriptions from config
        for email in self.config["alerts"].get("email_endpoints", []):
            topic.add_subscription(
                sns_subs.EmailSubscription(email)
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

    def _create_error_metric_and_alarm(self) -> None:
        """Create a MetricFilter that counts ERROR occurrences and a CloudWatch Alarm."""
        if not self.log_group:
            return

        metric_namespace = f"{self.config.get('app_name', 'anomaly-detector')}/Logs"
        metric_name = "ErrorCount"

        # Create a Metric Filter to count lines containing the literal "ERROR"
        logs.MetricFilter(
            self, "ErrorMetricFilter",
            log_group=self.log_group,
            metric_namespace=metric_namespace,
            metric_name=metric_name,
            filter_pattern=logs.FilterPattern.literal("ERROR"),
            metric_value="1"
        )

        # Create a CloudWatch Alarm that fires when ErrorCount >= 1 in a single 1-minute period
        alarm_metric = cloudwatch.Metric(
            namespace=metric_namespace,
            metric_name=metric_name,
            period=Duration.minutes(1),
            statistic="Sum"
        )

        alarm = cloudwatch.Alarm(
            self, "ErrorAlarm",
            metric=alarm_metric,
            threshold=1,
            evaluation_periods=1,
            alarm_description="Alarm when logs contain ERROR entries",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )

        # If an alerts SNS topic exists in the stack config, publish alarm actions to it
        try:
            if getattr(self, "alerts_topic", None):
                alarm.add_alarm_action(cloudwatch_actions.SnsAction(self.alerts_topic))
        except Exception:
            # Don't fail synth if action wiring can't be applied in some contexts
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
