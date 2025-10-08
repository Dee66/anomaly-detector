"""NER Model Training and Development Module.

This module provides comprehensive training capabilities for Named Entity Recognition (NER)
models specialized for security log analysis. It includes fine-tuning pipelines,
data preparation utilities, and evaluation metrics tracking.

Key Features:
- Fine-tuning of transformer models (DistilBERT, RoBERTa) for security entity extraction
- Custom tokenization and sequence labeling for AWS resource identifiers
- Advanced training strategies with learning rate scheduling and early stopping
- Comprehensive evaluation with F1-score, precision, recall tracking
- Integration with MLflow for experiment tracking and model versioning
- CloudWatch metrics export for production monitoring
"""

__version__ = "0.1.0"