"""S3 log ingestion pipeline for security logs.

This module handles reading security logs from S3, parsing them according to 
their format (CloudTrail, VPC Flow Logs), and preparing them for entity extraction
and anomaly detection.
"""

import json
import gzip
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterator, Union
from datetime import datetime
import logging

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from .schemas import (
    CloudTrailEvent,
    VPCFlowLogRecord,
    EventSource,
    SecurityLogBatch,
    ProcessingResult
)

logger = logging.getLogger(__name__)


class S3LogIngester:
    """Handles ingestion of security logs from S3 buckets."""
    
    def __init__(self, aws_region: str = "us-east-1", profile_name: Optional[str] = None):
        """Initialize the S3 log ingester.
        
        Args:
            aws_region: AWS region for S3 client
            profile_name: AWS profile name (optional)
        """
        if not HAS_BOTO3:
            raise ImportError("boto3 is required for S3 operations. Install with: poetry add boto3")
        
        self.aws_region = aws_region
        self.profile_name = profile_name
        
        # Initialize S3 client
        session = boto3.Session(profile_name=profile_name)
        self.s3_client = session.client('s3', region_name=aws_region)
        
        logger.info(f"Initialized S3LogIngester for region {aws_region}")
    
    def list_log_files(self, 
                       bucket_name: str, 
                       prefix: str = "",
                       start_date: Optional[datetime] = None,
                       end_date: Optional[datetime] = None,
                       max_files: Optional[int] = None) -> List[Dict[str, Any]]:
        """List log files in S3 bucket within date range.
        
        Args:
            bucket_name: S3 bucket name
            prefix: S3 key prefix to filter files
            start_date: Filter files modified after this date
            end_date: Filter files modified before this date
            max_files: Maximum number of files to return
            
        Returns:
            List of S3 object metadata dicts
        """
        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=bucket_name, Prefix=prefix)
            
            files = []
            for page in page_iterator:
                if 'Contents' not in page:
                    continue
                    
                for obj in page['Contents']:
                    # Apply date filtering
                    if start_date and obj['LastModified'] < start_date:
                        continue
                    if end_date and obj['LastModified'] > end_date:
                        continue
                    
                    # Skip directories
                    if obj['Key'].endswith('/'):
                        continue
                    
                    files.append({
                        'bucket': bucket_name,
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'],
                        'etag': obj['ETag']
                    })
                    
                    # Apply max files limit
                    if max_files and len(files) >= max_files:
                        break
                
                if max_files and len(files) >= max_files:
                    break
            
            logger.info(f"Found {len(files)} log files in s3://{bucket_name}/{prefix}")
            return files
            
        except ClientError as e:
            logger.error(f"Error listing S3 objects: {e}")
            raise
        except NoCredentialsError:
            logger.error("AWS credentials not found")
            raise
    
    def read_log_file(self, bucket_name: str, key: str) -> str:
        """Read a single log file from S3.
        
        Args:
            bucket_name: S3 bucket name
            key: S3 object key
            
        Returns:
            Raw log file content as string
        """
        try:
            response = self.s3_client.get_object(Bucket=bucket_name, Key=key)
            content = response['Body'].read()
            
            # Handle gzipped files
            if key.endswith('.gz'):
                content = gzip.decompress(content)
            
            return content.decode('utf-8')
            
        except ClientError as e:
            logger.error(f"Error reading S3 object s3://{bucket_name}/{key}: {e}")
            raise
    
    def parse_cloudtrail_logs(self, raw_content: str) -> List[CloudTrailEvent]:
        """Parse CloudTrail log content into structured events.
        
        CloudTrail logs are typically JSON with a 'Records' array.
        
        Args:
            raw_content: Raw log file content
            
        Returns:
            List of parsed CloudTrail events
        """
        events = []
        errors = []
        
        try:
            # CloudTrail logs are JSON with Records array
            log_data = json.loads(raw_content)
            
            if 'Records' in log_data:
                records = log_data['Records']
            elif isinstance(log_data, list):
                # Some CloudTrail exports are just arrays
                records = log_data
            else:
                # Single record
                records = [log_data]
            
            for record in records:
                try:
                    event = CloudTrailEvent(**record)
                    events.append(event)
                except Exception as e:
                    errors.append(f"Failed to parse CloudTrail record: {e}")
                    logger.warning(f"Failed to parse CloudTrail record: {e}")
        
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in CloudTrail log: {e}")
            logger.error(f"Invalid JSON in CloudTrail log: {e}")
        
        logger.info(f"Parsed {len(events)} CloudTrail events with {len(errors)} errors")
        return events
    
    def parse_vpc_flow_logs(self, raw_content: str) -> List[VPCFlowLogRecord]:
        """Parse VPC Flow Log content into structured records.
        
        VPC Flow Logs can be space-separated or custom format.
        This assumes the default format.
        
        Args:
            raw_content: Raw log file content
            
        Returns:
            List of parsed VPC Flow Log records
        """
        records = []
        errors = []
        
        lines = raw_content.strip().split('\n')
        
        # Skip header line if present
        if lines and lines[0].startswith('version'):
            lines = lines[1:]
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            try:
                # Parse space-separated values (default VPC Flow Log format)
                fields = line.strip().split()
                
                if len(fields) >= 14:  # Minimum required fields
                    record_data = {
                        'version': int(fields[0]),
                        'account_id': fields[1],
                        'interface_id': fields[2],
                        'srcaddr': fields[3],
                        'dstaddr': fields[4],
                        'srcport': int(fields[5]),
                        'dstport': int(fields[6]),
                        'protocol': int(fields[7]),
                        'packets': int(fields[8]),
                        'bytes': int(fields[9]),
                        'windowstart': int(fields[10]),
                        'windowend': int(fields[11]),
                        'action': fields[12],
                        'flowlogstatus': fields[13]
                    }
                    
                    record = VPCFlowLogRecord(**record_data)
                    records.append(record)
                else:
                    errors.append(f"Line {line_num}: Insufficient fields ({len(fields)} < 14)")
                    
            except (ValueError, IndexError) as e:
                errors.append(f"Line {line_num}: Parse error - {e}")
                logger.warning(f"Failed to parse VPC Flow Log line {line_num}: {e}")
        
        logger.info(f"Parsed {len(records)} VPC Flow Log records with {len(errors)} errors")
        return records
    
    def detect_log_format(self, raw_content: str, file_key: str) -> EventSource:
        """Detect the format of a log file.
        
        Args:
            raw_content: Raw log file content
            file_key: S3 key of the file (for hints)
            
        Returns:
            Detected log format
        """
        # Use file path hints first
        if 'cloudtrail' in file_key.lower():
            return EventSource.CLOUDTRAIL
        elif 'vpc' in file_key.lower() or 'flow' in file_key.lower():
            return EventSource.VPC_FLOW
        
        # Try to detect from content
        content_sample = raw_content[:1000].strip()
        
        # Check for JSON (CloudTrail)
        if content_sample.startswith('{') or content_sample.startswith('['):
            try:
                json.loads(content_sample)
                return EventSource.CLOUDTRAIL
            except json.JSONDecodeError:
                pass
        
        # Check for VPC Flow Log format (space-separated values)
        lines = content_sample.split('\n')[:5]  # Check first few lines
        for line in lines:
            fields = line.strip().split()
            if len(fields) >= 14 and fields[0].isdigit():  # Version field
                return EventSource.VPC_FLOW
        
        # Default to CloudTrail
        logger.warning(f"Could not detect format for {file_key}, defaulting to CloudTrail")
        return EventSource.CLOUDTRAIL
    
    def ingest_file(self, 
                    bucket_name: str, 
                    key: str,
                    event_source: Optional[EventSource] = None) -> SecurityLogBatch:
        """Ingest a single log file and return parsed events.
        
        Args:
            bucket_name: S3 bucket name
            key: S3 object key
            event_source: Override auto-detection of log format
            
        Returns:
            SecurityLogBatch with parsed events
        """
        logger.info(f"Ingesting log file s3://{bucket_name}/{key}")
        
        # Read raw content
        raw_content = self.read_log_file(bucket_name, key)
        
        # Detect format if not specified
        if event_source is None:
            event_source = self.detect_log_format(raw_content, key)
        
        # Parse based on format
        parsed_events = []
        if event_source == EventSource.CLOUDTRAIL:
            cloudtrail_events = self.parse_cloudtrail_logs(raw_content)
            parsed_events = [event.model_dump() for event in cloudtrail_events]
        elif event_source == EventSource.VPC_FLOW:
            vpc_events = self.parse_vpc_flow_logs(raw_content)
            parsed_events = [event.model_dump() for event in vpc_events]
        
        # Create batch metadata
        batch = SecurityLogBatch(
            batch_id=f"s3-{bucket_name}-{key.replace('/', '-')}",
            source_bucket=bucket_name,
            source_key=key,
            event_source=event_source,
            log_count=len(parsed_events),
            size_bytes=len(raw_content.encode('utf-8'))
        )
        
        logger.info(f"Successfully ingested {len(parsed_events)} events from {key}")
        return batch
    
    def ingest_batch(self, 
                     bucket_name: str, 
                     file_keys: List[str],
                     event_source: Optional[EventSource] = None,
                     max_files: Optional[int] = None) -> ProcessingResult:
        """Ingest multiple log files as a batch.
        
        Args:
            bucket_name: S3 bucket name
            file_keys: List of S3 object keys to process
            event_source: Override auto-detection of log format
            max_files: Maximum number of files to process
            
        Returns:
            ProcessingResult with batch metadata and any errors
        """
        start_time = datetime.utcnow()
        processed_files = 0
        total_events = 0
        errors = []
        warnings = []
        batches = []
        
        # Limit files if specified
        if max_files:
            file_keys = file_keys[:max_files]
        
        batch_id = f"batch-{int(start_time.timestamp())}"
        logger.info(f"Starting batch ingestion {batch_id} for {len(file_keys)} files")
        
        for key in file_keys:
            try:
                batch = self.ingest_file(bucket_name, key, event_source)
                batches.append(batch)
                processed_files += 1
                total_events += batch.log_count
                
            except Exception as e:
                error_msg = f"Failed to process {key}: {e}"
                errors.append(error_msg)
                logger.error(error_msg)
        
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()
        
        result = ProcessingResult(
            batch_id=batch_id,
            total_events=total_events,
            entities_extracted=0,  # Will be filled by entity extraction pipeline
            anomalies_detected=0,  # Will be filled by scoring pipeline
            high_risk_events=0,  # Will be filled by scoring pipeline
            processing_time_seconds=processing_time,
            errors=errors,
            warnings=warnings
        )
        
        logger.info(f"Batch ingestion complete: {processed_files} files, "
                   f"{total_events} events, {len(errors)} errors")
        
        return result


class LocalLogIngester:
    """Handles ingestion of security logs from local files (for testing/dev)."""
    
    def read_log_file(self, file_path: Union[str, Path]) -> str:
        """Read a log file from local filesystem.
        
        Args:
            file_path: Path to log file
            
        Returns:
            Raw log file content as string
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        if file_path.suffix == '.gz':
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                return f.read()
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
    
    def ingest_file(self, 
                    file_path: Union[str, Path],
                    event_source: Optional[EventSource] = None) -> SecurityLogBatch:
        """Ingest a single log file from local filesystem.
        
        Args:
            file_path: Path to log file
            event_source: Override auto-detection of log format
            
        Returns:
            SecurityLogBatch with parsed events
        """
        file_path = Path(file_path)
        logger.info(f"Ingesting local log file {file_path}")
        
        # Use S3 ingester logic for parsing
        s3_ingester = S3LogIngester()
        raw_content = self.read_log_file(file_path)
        
        # Detect format if not specified
        if event_source is None:
            event_source = s3_ingester.detect_log_format(raw_content, str(file_path))
        
        # Parse based on format
        parsed_events = []
        if event_source == EventSource.CLOUDTRAIL:
            cloudtrail_events = s3_ingester.parse_cloudtrail_logs(raw_content)
            parsed_events = [event.model_dump() for event in cloudtrail_events]
        elif event_source == EventSource.VPC_FLOW:
            vpc_events = s3_ingester.parse_vpc_flow_logs(raw_content)
            parsed_events = [event.model_dump() for event in vpc_events]
        
        # Create batch metadata
        batch = SecurityLogBatch(
            batch_id=f"local-{file_path.stem}",
            source_bucket="local",
            source_key=str(file_path),
            event_source=event_source,
            log_count=len(parsed_events),
            size_bytes=file_path.stat().st_size
        )
        
        logger.info(f"Successfully ingested {len(parsed_events)} events from {file_path}")
        return batch