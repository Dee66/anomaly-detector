"""Tests for the synthetic log generator."""

import json

# Add paths for imports
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "data"))

from detector.schemas import CloudTrailEvent, EventSource, VPCFlowLogRecord
from generate_logs import SecurityLogGenerator


class TestSecurityLogGenerator:
    """Test the synthetic security log generator."""

    def setup_method(self):
        """Set up test fixtures."""
        self.generator = SecurityLogGenerator(seed=42)  # Fixed seed for reproducibility

    def test_generator_initialization(self):
        """Test that generator initializes with proper data."""
        assert len(self.generator.account_ids) > 0
        assert len(self.generator.regions) > 0
        assert len(self.generator.iam_roles) > 0
        assert len(self.generator.iam_users) > 0
        assert len(self.generator.vpc_ids) > 0

    def test_generate_cloudtrail_event(self):
        """Test CloudTrail event generation."""
        event_data = self.generator.generate_cloudtrail_event()

        # Validate structure
        assert "eventVersion" in event_data
        assert "userIdentity" in event_data
        assert "eventTime" in event_data
        assert "eventName" in event_data
        assert "awsRegion" in event_data
        assert "requestID" in event_data
        assert "eventID" in event_data

        # Validate content
        assert event_data["eventVersion"] == "1.08"
        assert event_data["awsRegion"] in self.generator.regions
        assert event_data["recipientAccountId"] in self.generator.account_ids

        # Validate user identity structure
        user_identity = event_data["userIdentity"]
        assert "type" in user_identity
        assert "accountId" in user_identity
        assert user_identity["type"] in ["IAMUser", "AssumedRole", "Root"]

    def test_generate_cloudtrail_event_suspicious(self):
        """Test generating suspicious CloudTrail events."""
        normal_event = self.generator.generate_cloudtrail_event(make_suspicious=False)
        suspicious_event = self.generator.generate_cloudtrail_event(make_suspicious=True)

        # Both should be valid CloudTrail events
        assert "eventName" in normal_event
        assert "eventName" in suspicious_event

        # Suspicious events more likely to have external IPs
        # (This is probabilistic, so we'll just check structure)
        assert "sourceIPAddress" in suspicious_event

    def test_generate_cloudtrail_event_specific_name(self):
        """Test generating CloudTrail event with specific event name."""
        event_data = self.generator.generate_cloudtrail_event(event_name="CreateUser")
        assert event_data["eventName"] == "CreateUser"

    def test_generate_vpc_flow_log(self):
        """Test VPC Flow Log generation."""
        flow_data = self.generator.generate_vpc_flow_log()

        # Validate structure
        required_fields = [
            "version", "account_id", "interface_id", "srcaddr", "dstaddr",
            "srcport", "dstport", "protocol", "packets", "bytes",
            "windowstart", "windowend", "action", "flowlogstatus"
        ]

        for field in required_fields:
            assert field in flow_data, f"Missing field: {field}"

        # Validate content
        assert flow_data["version"] == 2
        assert flow_data["account_id"] in self.generator.account_ids
        assert flow_data["action"] in ["ACCEPT", "REJECT"]
        assert flow_data["flowlogstatus"] == "OK"
        assert isinstance(flow_data["srcport"], int)
        assert isinstance(flow_data["dstport"], int)
        assert 0 <= flow_data["srcport"] <= 65535
        assert 0 <= flow_data["dstport"] <= 65535

    def test_generate_vpc_flow_log_suspicious(self):
        """Test generating suspicious VPC Flow Logs."""
        normal_flow = self.generator.generate_vpc_flow_log(make_suspicious=False)
        suspicious_flow = self.generator.generate_vpc_flow_log(make_suspicious=True)

        # Both should be valid flow logs
        assert "srcaddr" in normal_flow
        assert "srcaddr" in suspicious_flow
        assert "dstaddr" in normal_flow
        assert "dstaddr" in suspicious_flow

        # Suspicious flows often have higher packet counts
        # (This is probabilistic, but we can check structure)
        assert isinstance(suspicious_flow["packets"], int)
        assert suspicious_flow["packets"] > 0

    def test_generate_log_batch_cloudtrail(self):
        """Test generating a batch of CloudTrail logs."""
        logs = self.generator.generate_log_batch(
            event_type=EventSource.CLOUDTRAIL,
            count=50,
            suspicious_rate=0.2
        )

        assert len(logs) == 50

        # Validate all logs are CloudTrail events
        for log in logs:
            assert "eventName" in log
            assert "userIdentity" in log
            assert "eventTime" in log

        # Check that we can parse them with our schema
        parsed_count = 0
        for log in logs[:5]:  # Test first 5 for performance
            try:
                CloudTrailEvent(**log)
                parsed_count += 1
            except Exception as e:
                pytest.fail(f"Failed to parse CloudTrail event: {e}")

        assert parsed_count == 5

    def test_generate_log_batch_vpc(self):
        """Test generating a batch of VPC Flow Logs."""
        logs = self.generator.generate_log_batch(
            event_type=EventSource.VPC_FLOW,
            count=30,
            suspicious_rate=0.1
        )

        assert len(logs) == 30

        # Validate all logs are VPC flow logs
        for log in logs:
            assert "srcaddr" in log
            assert "dstaddr" in log
            assert "action" in log

        # Check that we can parse them with our schema
        parsed_count = 0
        for log in logs[:5]:  # Test first 5 for performance
            try:
                VPCFlowLogRecord(**log)
                parsed_count += 1
            except Exception as e:
                pytest.fail(f"Failed to parse VPC Flow Log: {e}")

        assert parsed_count == 5

    def test_generate_log_batch_suspicious_rate(self):
        """Test that suspicious rate is approximately correct."""
        logs = self.generator.generate_log_batch(
            event_type=EventSource.CLOUDTRAIL,
            count=100,
            suspicious_rate=0.3
        )

        assert len(logs) == 100
        # We can't easily test the exact suspicious rate without
        # more sophisticated detection, but we can verify structure

    def test_save_logs_to_file_jsonl(self):
        """Test saving logs to JSONL format."""
        logs = self.generator.generate_log_batch(
            event_type=EventSource.CLOUDTRAIL,
            count=10,
            suspicious_rate=0.1
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            filepath = Path(temp_dir) / "test_logs.jsonl"
            self.generator.save_logs_to_file(logs, filepath, format="jsonl")

            # Verify file was created
            assert filepath.exists()

            # Verify content
            with open(filepath, 'r') as f:
                lines = f.readlines()

            assert len(lines) == 10

            # Verify each line is valid JSON
            for line in lines:
                parsed = json.loads(line.strip())
                assert "eventName" in parsed

    def test_save_logs_to_file_json(self):
        """Test saving logs to JSON format."""
        logs = self.generator.generate_log_batch(
            event_type=EventSource.VPC_FLOW,
            count=5,
            suspicious_rate=0.0
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            filepath = Path(temp_dir) / "test_logs.json"
            self.generator.save_logs_to_file(logs, filepath, format="json")

            # Verify file was created
            assert filepath.exists()

            # Verify content
            with open(filepath, 'r') as f:
                parsed_logs = json.load(f)

            assert len(parsed_logs) == 5
            assert isinstance(parsed_logs, list)

            # Verify structure
            for log in parsed_logs:
                assert "srcaddr" in log
                assert "dstaddr" in log

    def test_save_logs_invalid_format(self):
        """Test error handling for invalid format."""
        logs = [{"test": "data"}]

        with tempfile.TemporaryDirectory() as temp_dir:
            filepath = Path(temp_dir) / "test.txt"

            with pytest.raises(ValueError, match="Unsupported format"):
                self.generator.save_logs_to_file(logs, filepath, format="xml")

    def test_reproducibility_with_seed(self):
        """Test that the same seed produces the same output."""
        gen1 = SecurityLogGenerator(seed=123)
        gen2 = SecurityLogGenerator(seed=123)

        event1 = gen1.generate_cloudtrail_event()
        event2 = gen2.generate_cloudtrail_event()

        # Should be identical
        assert event1["eventID"] == event2["eventID"]
        assert event1["requestID"] == event2["requestID"]
        assert event1["eventName"] == event2["eventName"]

    def test_different_seeds_different_output(self):
        """Test that different seeds produce different output."""
        gen1 = SecurityLogGenerator(seed=123)
        gen2 = SecurityLogGenerator(seed=456)

        event1 = gen1.generate_cloudtrail_event()
        event2 = gen2.generate_cloudtrail_event()

        # Should be different
        assert event1["eventID"] != event2["eventID"]
