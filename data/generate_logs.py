"""Synthetic security log generator for development and testing.

This module generates realistic CloudTrail and VPC Flow Log data for:
- Development and testing of the anomaly detection pipeline
- Training data for NER models
- Benchmarking and performance testing
- Demonstration of security compliance features
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from detector.schemas import (
    CloudTrailUserIdentity,
    EventSource,
)


class SecurityLogGenerator:
    """Generate synthetic security logs for testing and development."""

    def __init__(self, seed: Optional[int] = None):
        """Initialize the generator with optional random seed for reproducibility."""
        self.random = random.Random(seed)

        # Realistic AWS account IDs
        self.account_ids = [
            "123456789012",
            "987654321098",
            "555666777888",
            "111222333444"
        ]

        # Common AWS regions
        self.regions = [
            "us-east-1", "us-west-2", "eu-west-1",
            "ap-southeast-1", "ca-central-1"
        ]

        # Realistic IAM entities
        self.iam_roles = [
            "DevOpsRole", "DataScientistRole", "ReadOnlyRole",
            "AdminRole", "LambdaExecutionRole", "EC2InstanceRole",
            "CrossAccountAccessRole", "ServiceRole", "PowerUserRole"
        ]

        self.iam_users = [
            "john.doe", "jane.smith", "admin", "service-user",
            "backup-user", "monitoring-user", "deploy-user"
        ]

        # VPC and networking components
        self.vpc_ids = [f"vpc-{self._generate_id()}" for _ in range(5)]
        self.subnet_ids = [f"subnet-{self._generate_id()}" for _ in range(10)]
        self.security_group_ids = [f"sg-{self._generate_id()}" for _ in range(8)]

        # S3 buckets
        self.s3_buckets = [
            "company-data-prod", "company-logs-archive", "company-backups",
            "ml-training-data", "application-assets", "compliance-reports"
        ]

        # KMS keys
        self.kms_keys = [str(uuid.uuid4()) for _ in range(3)]

        # EC2 instances
        self.ec2_instances = [f"i-{self._generate_id()}" for _ in range(8)]

        # IP address ranges (using private ranges for safety)
        self.internal_ips = [
            "10.0.{}.{}".format(self.random.randint(0, 255), self.random.randint(1, 254))
            for _ in range(20)
        ]
        self.external_ips = [
            "203.0.{}.{}".format(self.random.randint(1, 254), self.random.randint(1, 254))
            for _ in range(10)
        ]

    def _generate_id(self, length: int = 8) -> str:
        """Generate a random hexadecimal ID."""
        return ''.join(self.random.choices('0123456789abcdef', k=length))

    def _generate_timestamp(self, days_back: int = 7) -> datetime:
        """Generate a random timestamp within the last N days."""
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(days=days_back)
        random_seconds = self.random.randint(0, int((now - start_time).total_seconds()))
        return start_time + timedelta(seconds=random_seconds)

    def generate_cloudtrail_event(self,
                                 event_name: Optional[str] = None,
                                 make_suspicious: bool = False) -> Dict[str, Any]:
        """Generate a CloudTrail event record."""

        # Common CloudTrail events
        common_events = [
            "ConsoleLogin", "AssumeRole", "CreateUser", "DeleteUser",
            "PutBucketPolicy", "GetObject", "CreateRole", "AttachRolePolicy",
            "RunInstances", "TerminateInstances", "CreateKey", "DescribeInstances"
        ]

        # Suspicious events that might indicate security issues
        suspicious_events = [
            "CreateAccessKey", "DeleteRole", "PutBucketAcl", "CreateUser",
            "AttachUserPolicy", "DetachRolePolicy", "ModifyDBInstance"
        ]

        if make_suspicious:
            event_name = event_name or self.random.choice(suspicious_events)
        else:
            event_name = event_name or self.random.choice(common_events)

        account_id = self.random.choice(self.account_ids)
        region = self.random.choice(self.regions)

        # Generate user identity
        user_type = self.random.choice(["IAMUser", "AssumedRole", "Root"])
        if user_type == "IAMUser":
            user_identity = CloudTrailUserIdentity(
                type=user_type,
                principalId=f"AIDA{self._generate_id().upper()}",
                arn=f"arn:aws:iam::{account_id}:user/{self.random.choice(self.iam_users)}",
                accountId=account_id,
                userName=self.random.choice(self.iam_users)
            )
        elif user_type == "AssumedRole":
            role = self.random.choice(self.iam_roles)
            session_id = self.random.randint(1000, 9999)
            user_identity = CloudTrailUserIdentity(
                type=user_type,
                principalId=f"AROA{self._generate_id().upper()}:session-{session_id}",
                arn=f"arn:aws:sts::{account_id}:assumed-role/{role}/session-{session_id}",
                accountId=account_id
            )
        else:  # Root
            user_identity = CloudTrailUserIdentity(
                type=user_type,
                principalId=account_id,
                arn=f"arn:aws:iam::{account_id}:root",
                accountId=account_id
            )

        # Generate source IP (suspicious events more likely from external IPs)
        if make_suspicious and self.random.random() < 0.7:
            source_ip = self.random.choice(self.external_ips)
        else:
            source_ip = self.random.choice(self.internal_ips + self.external_ips)

        # Event-specific request parameters
        request_params = {}
        if "S3" in event_name or "Bucket" in event_name:
            request_params["bucketName"] = self.random.choice(self.s3_buckets)
        elif "EC2" in event_name or "Instance" in event_name:
            request_params["instanceId"] = self.random.choice(self.ec2_instances)
        elif "Role" in event_name:
            request_params["roleName"] = self.random.choice(self.iam_roles)
        elif "User" in event_name:
            request_params["userName"] = self.random.choice(self.iam_users)
        elif "Key" in event_name:
            request_params["keyId"] = self.random.choice(self.kms_keys)

        event = {
            "eventVersion": "1.08",
            "userIdentity": user_identity.model_dump(),
            "eventTime": self._generate_timestamp().isoformat().replace('+00:00', 'Z'),
            "eventSource": f"{event_name.lower()}.amazonaws.com",
            "eventName": event_name,
            "awsRegion": region,
            "sourceIPAddress": source_ip,
            "userAgent": self.random.choice([
                "aws-cli/2.0.55", "console.aws.amazon.com", "Boto3/1.17.49",
                "terraform-provider-aws/3.74.0", "aws-sdk-go/1.38.68"
            ]),
            "requestParameters": request_params,
            "responseElements": None,
            "requestID": self._generate_id(32),
            "eventID": self._generate_id(32),
            "eventType": "AwsApiCall",
            "recipientAccountId": account_id
        }

        return event

    def generate_vpc_flow_log(self, make_suspicious: bool = False) -> Dict[str, Any]:
        """Generate a VPC Flow Log record."""

        src_ip = self.random.choice(self.internal_ips)

        # Suspicious traffic patterns
        if make_suspicious:
            dst_ip = self.random.choice(self.external_ips)  # Outbound to external
            dst_port = self.random.choice([22, 3389, 443, 80, 21, 23])  # Common attack ports
            protocol = 6  # TCP
            action = "ACCEPT" if self.random.random() < 0.8 else "REJECT"
            packets = self.random.randint(100, 10000)  # High packet count
            bytes_transferred = packets * self.random.randint(64, 1500)
        else:
            dst_ip = self.random.choice(self.internal_ips + self.external_ips)
            dst_port = self.random.choice([80, 443, 22, 3306, 5432, 6379, 8080])
            protocol = self.random.choice([6, 17])  # TCP or UDP
            action = self.random.choice(["ACCEPT"] * 8 + ["REJECT"] * 2)  # Mostly accept
            packets = self.random.randint(1, 100)
            bytes_transferred = packets * self.random.randint(64, 1500)

        start_time = self._generate_timestamp()
        end_time = start_time + timedelta(seconds=self.random.randint(1, 300))

        flow_log = {
            "version": 2,
            "account_id": self.random.choice(self.account_ids),
            "interface_id": f"eni-{self._generate_id()}",
            "srcaddr": src_ip,
            "dstaddr": dst_ip,
            "srcport": self.random.randint(1024, 65535),
            "dstport": dst_port,
            "protocol": protocol,
            "packets": packets,
            "bytes": bytes_transferred,
            "windowstart": int(start_time.timestamp()),
            "windowend": int(end_time.timestamp()),
            "action": action,
            "flowlogstatus": "OK"
        }

        return flow_log

    def generate_log_batch(self,
                          event_type: EventSource,
                          count: int = 100,
                          suspicious_rate: float = 0.1) -> List[Dict[str, Any]]:
        """Generate a batch of log entries."""
        logs = []
        suspicious_count = int(count * suspicious_rate)
        normal_count = count - suspicious_count

        for _ in range(normal_count):
            if event_type == EventSource.CLOUDTRAIL:
                logs.append(self.generate_cloudtrail_event(make_suspicious=False))
            elif event_type == EventSource.VPC_FLOW:
                logs.append(self.generate_vpc_flow_log(make_suspicious=False))

        for _ in range(suspicious_count):
            if event_type == EventSource.CLOUDTRAIL:
                logs.append(self.generate_cloudtrail_event(make_suspicious=True))
            elif event_type == EventSource.VPC_FLOW:
                logs.append(self.generate_vpc_flow_log(make_suspicious=True))

        # Shuffle to mix suspicious and normal events
        self.random.shuffle(logs)
        return logs

    def save_logs_to_file(self,
                         logs: List[Dict[str, Any]],
                         filepath: Path,
                         format: str = "jsonl") -> None:
        """Save logs to file in specified format."""
        filepath.parent.mkdir(parents=True, exist_ok=True)

        if format == "jsonl":
            with open(filepath, 'w') as f:
                for log in logs:
                    f.write(json.dumps(log) + "\n")
        elif format == "json":
            with open(filepath, 'w') as f:
                json.dump(logs, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

        print(f"✅ Saved {len(logs)} log entries to {filepath}")


def main():
    """Command-line interface for the log generator."""
    parser = argparse.ArgumentParser(description="Generate synthetic security logs")
    parser.add_argument("--type", choices=["cloudtrail", "vpc"], required=True,
                       help="Type of logs to generate")
    parser.add_argument("--count", type=int, default=100,
                       help="Number of log entries to generate")
    parser.add_argument("--suspicious-rate", type=float, default=0.1,
                       help="Fraction of logs that should be suspicious (0.0-1.0)")
    parser.add_argument("--output", type=Path, default="data/synthetic_logs.jsonl",
                       help="Output file path")
    parser.add_argument("--format", choices=["json", "jsonl"], default="jsonl",
                       help="Output format")
    parser.add_argument("--seed", type=int, help="Random seed for reproducibility")

    args = parser.parse_args()

    # Validate suspicious rate
    if not 0.0 <= args.suspicious_rate <= 1.0:
        print("❌ Error: suspicious-rate must be between 0.0 and 1.0")
        return 1

    print(f"🎯 Generating {args.count} {args.type} logs...")
    print(f"📊 Suspicious rate: {args.suspicious_rate:.1%}")

    generator = SecurityLogGenerator(seed=args.seed)

    if args.type == "cloudtrail":
        event_type = EventSource.CLOUDTRAIL
    else:
        event_type = EventSource.VPC_FLOW

    # Generate logs
    logs = generator.generate_log_batch(
        event_type=event_type,
        count=args.count,
        suspicious_rate=args.suspicious_rate
    )

    # Save to file
    generator.save_logs_to_file(logs, args.output, args.format)

    print("✅ Log generation complete!")
    print(f"📁 Output: {args.output}")

    return 0


if __name__ == "__main__":
    exit(main())
