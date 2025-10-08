"""Tests for S3 log ingestion functionality."""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

import pytest

# Add paths for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from detector.ingestion import S3LogIngester, LocalLogIngester
from detector.schemas import EventSource, SecurityLogBatch


class TestS3LogIngester:
    """Test S3 log ingestion functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        with patch('detector.ingestion.boto3'):
            self.ingester = S3LogIngester()
    
    def test_initialization_without_boto3(self):
        """Test that proper error is raised without boto3."""
        with patch('detector.ingestion.HAS_BOTO3', False):
            with pytest.raises(ImportError, match="boto3 is required"):
                S3LogIngester()
    
    def test_detect_log_format_cloudtrail_by_path(self):
        """Test log format detection using file path hints."""
        content = '{"Records": []}'
        
        # CloudTrail path hints
        assert self.ingester.detect_log_format(content, "logs/cloudtrail/2024/file.json") == EventSource.CLOUDTRAIL
        assert self.ingester.detect_log_format(content, "aws-cloudtrail-logs/file.gz") == EventSource.CLOUDTRAIL
    
    def test_detect_log_format_vpc_by_path(self):
        """Test VPC Flow Log format detection using file path hints."""
        content = "2 123456789012 eni-1235 10.0.0.1 10.0.0.2 443 80 6 20 1500 1234567890 1234567891 ACCEPT OK"
        
        # VPC Flow Log path hints
        assert self.ingester.detect_log_format(content, "vpc-flow-logs/file.txt") == EventSource.VPC_FLOW
        assert self.ingester.detect_log_format(content, "logs/vpc/flow/file.gz") == EventSource.VPC_FLOW
        assert self.ingester.detect_log_format(content, "flow-logs/file.txt") == EventSource.VPC_FLOW
    
    def test_detect_log_format_by_content(self):
        """Test log format detection using content analysis."""
        # JSON content (CloudTrail)
        cloudtrail_content = '{"Records": [{"eventVersion": "1.08"}]}'
        assert self.ingester.detect_log_format(cloudtrail_content, "unknown.txt") == EventSource.CLOUDTRAIL
        
        # Space-separated content (VPC Flow Log)
        vpc_content = "2 123456789012 eni-1235 10.0.0.1 10.0.0.2 443 80 6 20 1500 1234567890 1234567891 ACCEPT OK"
        assert self.ingester.detect_log_format(vpc_content, "unknown.txt") == EventSource.VPC_FLOW
    
    def test_parse_cloudtrail_logs_records_array(self):
        """Test parsing CloudTrail logs with Records array."""
        log_content = json.dumps({
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                        "arn": "arn:aws:iam::123456789012:user/test-user",
                        "accountId": "123456789012",
                        "userName": "test-user"
                    },
                    "eventTime": "2024-01-01T12:00:00Z",
                    "eventSource": "s3.amazonaws.com",
                    "eventName": "GetObject",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": "203.0.113.12",
                    "userAgent": "aws-cli/2.0.55",
                    "requestParameters": {},
                    "responseElements": None,
                    "requestID": "87654321",
                    "eventID": "12345678",
                    "eventType": "AwsApiCall",
                    "recipientAccountId": "123456789012"
                }
            ]
        })
        
        events = self.ingester.parse_cloudtrail_logs(log_content)
        assert len(events) == 1
        assert events[0].eventName == "GetObject"
        assert events[0].userIdentity.userName == "test-user"
    
    def test_parse_cloudtrail_logs_single_record(self):
        """Test parsing CloudTrail logs with single record (no Records array)."""
        log_content = json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "Root",
                "principalId": "123456789012",
                "arn": "arn:aws:iam::123456789012:root",
                "accountId": "123456789012"
            },
            "eventTime": "2024-01-01T12:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.168.1.1",
            "userAgent": "console.aws.amazon.com",
            "requestParameters": {},
            "responseElements": None,
            "requestID": "87654321",
            "eventID": "12345678",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012"
        })
        
        events = self.ingester.parse_cloudtrail_logs(log_content)
        assert len(events) == 1
        assert events[0].eventName == "CreateUser"
    
    def test_parse_cloudtrail_logs_invalid_json(self):
        """Test parsing CloudTrail logs with invalid JSON."""
        invalid_content = "{ invalid json content"
        
        events = self.ingester.parse_cloudtrail_logs(invalid_content)
        assert len(events) == 0
    
    def test_parse_vpc_flow_logs_valid(self):
        """Test parsing valid VPC Flow Logs."""
        log_content = """version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action flowlogstatus
2 123456789012 eni-1235b8ca 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK
2 123456789012 eni-1235b8ca 172.31.9.69 172.31.9.12 49761 3389 6 20 4249 1418530010 1418530070 REJECT OK"""
        
        records = self.ingester.parse_vpc_flow_logs(log_content)
        assert len(records) == 2
        
        # Check first record
        assert records[0].version == 2
        assert records[0].account_id == "123456789012"
        assert records[0].srcaddr == "172.31.16.139"
        assert records[0].dstaddr == "172.31.16.21"
        assert records[0].srcport == 20641
        assert records[0].dstport == 22
        assert records[0].action == "ACCEPT"
        
        # Check second record
        assert records[1].action == "REJECT"
        assert records[1].dstport == 3389
    
    def test_parse_vpc_flow_logs_insufficient_fields(self):
        """Test parsing VPC Flow Logs with insufficient fields."""
        log_content = "2 123456789012 eni-1235 10.0.0.1"  # Only 4 fields
        
        records = self.ingester.parse_vpc_flow_logs(log_content)
        assert len(records) == 0
    
    def test_parse_vpc_flow_logs_invalid_data(self):
        """Test parsing VPC Flow Logs with invalid data types."""
        log_content = "invalid 123456789012 eni-1235 10.0.0.1 10.0.0.2 abc 80 6 20 1500 1234567890 1234567891 ACCEPT OK"
        
        records = self.ingester.parse_vpc_flow_logs(log_content)
        assert len(records) == 0
    
    @patch('detector.ingestion.boto3')
    def test_list_log_files_success(self, mock_boto3):
        """Test successful S3 file listing."""
        mock_s3_client = Mock()
        mock_boto3.Session.return_value.client.return_value = mock_s3_client
        
        # Mock paginator response
        mock_paginator = Mock()
        mock_s3_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Contents': [
                    {
                        'Key': 'logs/2024/01/01/cloudtrail.json',
                        'Size': 1024,
                        'LastModified': datetime(2024, 1, 1, 12, 0, 0),
                        'ETag': '"abc123"'
                    },
                    {
                        'Key': 'logs/2024/01/01/vpc-flow.txt',
                        'Size': 2048,
                        'LastModified': datetime(2024, 1, 1, 13, 0, 0),
                        'ETag': '"def456"'
                    }
                ]
            }
        ]
        
        ingester = S3LogIngester()
        files = ingester.list_log_files('test-bucket', 'logs/')
        
        assert len(files) == 2
        assert files[0]['bucket'] == 'test-bucket'
        assert files[0]['key'] == 'logs/2024/01/01/cloudtrail.json'
        assert files[0]['size'] == 1024
        assert files[1]['key'] == 'logs/2024/01/01/vpc-flow.txt'
    
    @patch('detector.ingestion.boto3')
    def test_read_log_file_success(self, mock_boto3):
        """Test successful S3 file reading."""
        mock_s3_client = Mock()
        mock_boto3.Session.return_value.client.return_value = mock_s3_client
        
        test_content = "test log content"
        mock_response = {
            'Body': Mock()
        }
        mock_response['Body'].read.return_value = test_content.encode('utf-8')
        mock_s3_client.get_object.return_value = mock_response
        
        ingester = S3LogIngester()
        content = ingester.read_log_file('test-bucket', 'test-key.txt')
        
        assert content == test_content
        mock_s3_client.get_object.assert_called_once_with(Bucket='test-bucket', Key='test-key.txt')
    
    @patch('detector.ingestion.boto3')
    def test_read_log_file_gzipped(self, mock_boto3):
        """Test reading gzipped S3 file."""
        import gzip
        
        mock_s3_client = Mock()
        mock_boto3.Session.return_value.client.return_value = mock_s3_client
        
        test_content = "test log content"
        compressed_content = gzip.compress(test_content.encode('utf-8'))
        
        mock_response = {
            'Body': Mock()
        }
        mock_response['Body'].read.return_value = compressed_content
        mock_s3_client.get_object.return_value = mock_response
        
        ingester = S3LogIngester()
        content = ingester.read_log_file('test-bucket', 'test-key.gz')
        
        assert content == test_content


class TestLocalLogIngester:
    """Test local file ingestion functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.ingester = LocalLogIngester()
    
    def test_read_log_file_text(self):
        """Test reading plain text log file."""
        test_content = "test log content"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(test_content)
            temp_path = f.name
        
        try:
            content = self.ingester.read_log_file(temp_path)
            assert content == test_content
        finally:
            Path(temp_path).unlink()
    
    def test_read_log_file_gzipped(self):
        """Test reading gzipped log file."""
        import gzip
        
        test_content = "test log content"
        
        with tempfile.NamedTemporaryFile(suffix='.gz', delete=False) as f:
            temp_path = f.name
        
        try:
            with gzip.open(temp_path, 'wt', encoding='utf-8') as f:
                f.write(test_content)
            
            content = self.ingester.read_log_file(temp_path)
            assert content == test_content
        finally:
            Path(temp_path).unlink()
    
    def test_read_log_file_not_found(self):
        """Test error handling for missing file."""
        with pytest.raises(FileNotFoundError):
            self.ingester.read_log_file("/nonexistent/file.txt")
    
    def test_ingest_file_cloudtrail(self):
        """Test ingesting a CloudTrail log file."""
        cloudtrail_content = json.dumps({
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "Root",
                        "principalId": "123456789012",
                        "arn": "arn:aws:iam::123456789012:root",
                        "accountId": "123456789012"
                    },
                    "eventTime": "2024-01-01T12:00:00Z",
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "CreateUser",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": "192.168.1.1",
                    "userAgent": "console.aws.amazon.com",
                    "requestParameters": {},
                    "responseElements": None,
                    "requestID": "87654321",
                    "eventID": "12345678",
                    "eventType": "AwsApiCall",
                    "recipientAccountId": "123456789012"
                }
            ]
        })
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(cloudtrail_content)
            temp_path = f.name
        
        try:
            batch = self.ingester.ingest_file(temp_path, EventSource.CLOUDTRAIL)
            assert batch.event_source == EventSource.CLOUDTRAIL
            assert batch.log_count == 1
            assert batch.source_bucket == "local"
            assert batch.source_key == temp_path
        finally:
            Path(temp_path).unlink()
    
    def test_ingest_file_vpc_flow(self):
        """Test ingesting a VPC Flow Log file."""
        vpc_content = """version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action flowlogstatus
2 123456789012 eni-1235b8ca 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(vpc_content)
            temp_path = f.name
        
        try:
            batch = self.ingester.ingest_file(temp_path, EventSource.VPC_FLOW)
            assert batch.event_source == EventSource.VPC_FLOW
            assert batch.log_count == 1
            assert batch.source_bucket == "local"
        finally:
            Path(temp_path).unlink()