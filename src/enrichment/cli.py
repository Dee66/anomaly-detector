#!/usr/bin/env python3
"""CLI interface for the real-time enrichment handler.

This script provides command-line access to the enrichment functionality
for testing, debugging, and manual processing of security logs.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from detector.schemas import CloudTrailEvent
from enrichment.handler import EnrichmentHandler


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Real-time security log enrichment handler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a single CloudTrail event from JSON file
  python -m enrichment.cli --input event.json --type cloudtrail
  
  # Process with custom configuration
  python -m enrichment.cli --input events.json --config config.json --output results.json
  
  # Test with synthetic data
  python -m enrichment.cli --test --output test_results.json
        """
    )
    
    parser.add_argument(
        "--input", "-i",
        type=Path,
        help="Input JSON file containing security log events"
    )
    
    parser.add_argument(
        "--output", "-o", 
        type=Path,
        help="Output JSON file for compliance results (default: stdout)"
    )
    
    parser.add_argument(
        "--type", "-t",
        choices=["cloudtrail", "vpc_flow"],
        default="cloudtrail",
        help="Type of log events to process (default: cloudtrail)"
    )
    
    parser.add_argument(
        "--config", "-c",
        type=Path,
        help="Configuration file for enrichment handler"
    )
    
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run with synthetic test data"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and args.config.exists():
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Initialize handler
    handler = EnrichmentHandler(config)
    
    if args.test:
        # Generate synthetic test data
        events = _generate_test_events()
    elif args.input and args.input.exists():
        # Load events from file
        with open(args.input, 'r') as f:
            data = json.load(f)
            events = data if isinstance(data, list) else [data]
    else:
        print("Error: Must provide --input file or use --test mode", file=sys.stderr)
        return 1
    
    # Process events
    results = []
    for event_data in events:
        try:
            if args.type == "cloudtrail":
                event = CloudTrailEvent(**event_data)
                result = handler.process_cloudtrail_event(event)
                results.append(result.dict())
            else:
                print(f"Error: Log type '{args.type}' not yet implemented", file=sys.stderr)
                return 1
                
        except Exception as e:
            error_result = {
                "error": str(e),
                "event_id": event_data.get("eventID", "unknown"),
                "processed_at": datetime.utcnow().isoformat()
            }
            results.append(error_result)
            if args.verbose:
                print(f"Error processing event {event_data.get('eventID', 'unknown')}: {e}", file=sys.stderr)
    
    # Output results
    output_data = {
        "processed_at": datetime.utcnow().isoformat(),
        "total_events": len(events),
        "successful_results": len([r for r in results if "error" not in r]),
        "errors": len([r for r in results if "error" in r]),
        "results": results
    }
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"Results written to {args.output}")
    else:
        print(json.dumps(output_data, indent=2, default=str))
    
    return 0


def _generate_test_events() -> list[Dict[str, Any]]:
    """Generate synthetic test events for testing."""
    return [
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
            "requestParameters": {
                "bucketName": "test-bucket",
                "key": "sensitive-data.csv"
            },
            "responseElements": None,
            "requestID": "87654321",
            "eventID": "12345678-1234-1234-1234-123456789012",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012"
        },
        {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": "AROACKCEVSQ6C2EXAMPLE:test-session",
                "arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/test-session",
                "accountId": "123456789012"
            },
            "eventTime": "2024-01-01T12:05:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateRole",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "192.168.1.100",
            "userAgent": "aws-cli/2.0.55",
            "requestParameters": {
                "roleName": "SuspiciousRole",
                "assumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%7D"
            },
            "responseElements": {
                "role": {
                    "arn": "arn:aws:iam::123456789012:role/SuspiciousRole"
                }
            },
            "requestID": "87654322",
            "eventID": "12345679-1234-1234-1234-123456789012",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012"
        }
    ]


if __name__ == "__main__":
    sys.exit(main())