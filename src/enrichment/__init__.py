"""Real-time enrichment handler for security log processing.

This module provides real-time log enrichment capabilities including:
- Log parsing and normalization
- NER-based entity tagging
- Anomaly scoring and risk assessment
- Audit trail generation
- Secure output to compliance systems

The enrichment handler is designed for deployment in AWS Lambda/Fargate
with full VPC isolation and KMS encryption.
"""

__version__ = "0.1.0"