#!/usr/bin/env python3
"""Training script for Security Event Anomaly Detection Models.

This script orchestrates the training of both NER models for entity extraction
and anomaly detection models for security event analysis. It supports distributed
training, hyperparameter tuning, and comprehensive metrics collection.

Usage:
    python train.py --config config/train_config.yaml
    python train.py --config config/train_config.yaml --hyperparams config/hyperparams.json
    python train.py --model-type ner --epochs 10 --batch-size 32
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

import yaml
import torch
import numpy as np
from transformers import (
    AutoTokenizer, AutoModelForTokenClassification,
    TrainingArguments, Trainer, EarlyStoppingCallback
)
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
import boto3
import wandb

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.train.ner_train import SecurityLogDataset, NERTrainer
from src.detector.scoring import AnomalyScoringEngine
from src.detector.core import EnrichmentEngine
from config import SecurityDetectorConfig

logger = logging.getLogger(__name__)


class TrainingConfig:
    """Training configuration management."""
    
    def __init__(self, config_path: Optional[str] = None, hyperparams_path: Optional[str] = None):
        """Initialize training configuration.
        
        Args:
            config_path: Path to main training configuration file
            hyperparams_path: Path to hyperparameters configuration file
        """
        self.config = self._load_config(config_path)
        self.hyperparams = self._load_hyperparams(hyperparams_path)
        self._merge_configs()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load main training configuration."""
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
        
        # Default configuration
        return {
            "model": {
                "type": "ner",  # "ner" or "anomaly" or "both"
                "base_model": "distilbert-base-uncased",
                "num_labels": 9,  # B-USER, I-USER, B-ROLE, I-ROLE, B-RESOURCE, I-RESOURCE, B-IP, I-IP, O
                "max_length": 512
            },
            "training": {
                "epochs": 10,
                "batch_size": 16,
                "learning_rate": 2e-5,
                "weight_decay": 0.01,
                "warmup_steps": 500,
                "gradient_accumulation_steps": 1,
                "early_stopping_patience": 3,
                "save_steps": 500,
                "eval_steps": 500,
                "logging_steps": 100
            },
            "data": {
                "train_split": 0.8,
                "val_split": 0.1,
                "test_split": 0.1,
                "max_samples": None,
                "augmentation": {
                    "enabled": False,
                    "techniques": ["synonym_replacement", "random_insertion"]
                }
            },
            "optimization": {
                "mixed_precision": True,
                "gradient_checkpointing": False,
                "dataloader_num_workers": 4,
                "pin_memory": True
            },
            "monitoring": {
                "wandb_enabled": False,
                "wandb_project": "security-anomaly-detection",
                "cloudwatch_enabled": True,
                "metrics_namespace": "SecurityDetector/Training"
            },
            "output": {
                "model_dir": "models",
                "metrics_dir": "metrics",
                "logs_dir": "logs"
            }
        }
    
    def _load_hyperparams(self, hyperparams_path: Optional[str]) -> Dict[str, Any]:
        """Load hyperparameters configuration."""
        if hyperparams_path and Path(hyperparams_path).exists():
            with open(hyperparams_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _merge_configs(self):
        """Merge hyperparameters into main config."""
        for key, value in self.hyperparams.items():
            if key in self.config:
                if isinstance(self.config[key], dict) and isinstance(value, dict):
                    self.config[key].update(value)
                else:
                    self.config[key] = value
            else:
                self.config[key] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to configuration value
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value


class MetricsCollector:
    """Collect and export training metrics."""
    
    def __init__(self, config: TrainingConfig):
        """Initialize metrics collector.
        
        Args:
            config: Training configuration
        """
        self.config = config
        self.metrics_history = []
        
        # Initialize CloudWatch client if enabled
        self.cloudwatch = None
        if config.get("monitoring.cloudwatch_enabled", False):
            try:
                self.cloudwatch = boto3.client('cloudwatch')
            except Exception as e:
                logger.warning(f"Failed to initialize CloudWatch client: {e}")
        
        # Initialize Weights & Biases if enabled
        if config.get("monitoring.wandb_enabled", False):
            try:
                wandb.init(
                    project=config.get("monitoring.wandb_project", "security-anomaly-detection"),
                    config=config.config
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Weights & Biases: {e}")
    
    def log_metrics(self, metrics: Dict[str, float], step: int, prefix: str = ""):
        """Log metrics to all configured backends.
        
        Args:
            metrics: Dictionary of metric name -> value
            step: Training step
            prefix: Prefix for metric names
        """
        # Add timestamp and step
        metric_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "step": step,
            "metrics": {f"{prefix}{k}" if prefix else k: v for k, v in metrics.items()}
        }
        self.metrics_history.append(metric_entry)
        
        # Log to Weights & Biases
        if wandb.run:
            wandb.log({f"{prefix}{k}" if prefix else k: v for k, v in metrics.items()}, step=step)
        
        # Log to CloudWatch
        if self.cloudwatch:
            self._log_to_cloudwatch(metrics, prefix)
        
        # Log to console
        metrics_str = ", ".join([f"{k}: {v:.4f}" for k, v in metrics.items()])
        logger.info(f"Step {step} - {prefix}{metrics_str}")
    
    def _log_to_cloudwatch(self, metrics: Dict[str, float], prefix: str):
        """Log metrics to CloudWatch."""
        try:
            namespace = self.config.get("monitoring.metrics_namespace", "SecurityDetector/Training")
            
            metric_data = []
            for name, value in metrics.items():
                metric_data.append({
                    'MetricName': f"{prefix}{name}" if prefix else name,
                    'Value': value,
                    'Unit': 'None',
                    'Timestamp': datetime.utcnow()
                })
            
            # CloudWatch has a limit of 20 metrics per put_metric_data call
            for i in range(0, len(metric_data), 20):
                batch = metric_data[i:i+20]
                self.cloudwatch.put_metric_data(
                    Namespace=namespace,
                    MetricData=batch
                )
        except Exception as e:
            logger.warning(f"Failed to log metrics to CloudWatch: {e}")
    
    def save_metrics(self, output_dir: str):
        """Save metrics history to file.
        
        Args:
            output_dir: Directory to save metrics
        """
        output_path = Path(output_dir) / "metrics_history.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.metrics_history, f, indent=2)
        
        logger.info(f"Metrics saved to {output_path}")


class SecurityDetectorTrainer:
    """Main trainer for security detector models."""
    
    def __init__(self, config: TrainingConfig):
        """Initialize the trainer.
        
        Args:
            config: Training configuration
        """
        self.config = config
        self.metrics_collector = MetricsCollector(config)
        
        # Set up device
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"Using device: {self.device}")
        
        # Initialize models based on configuration
        self.ner_trainer = None
        self.anomaly_engine = None
        
        if config.get("model.type") in ["ner", "both"]:
            self.ner_trainer = self._initialize_ner_trainer()
        
        if config.get("model.type") in ["anomaly", "both"]:
            self.anomaly_engine = self._initialize_anomaly_engine()
    
    def _initialize_ner_trainer(self) -> NERTrainer:
        """Initialize NER trainer."""
        return NERTrainer(
            model_name=self.config.get("model.base_model", "distilbert-base-uncased"),
            num_labels=self.config.get("model.num_labels", 9),
            device=self.device
        )
    
    def _initialize_anomaly_engine(self) -> AnomalyScoringEngine:
        """Initialize anomaly scoring engine."""
        anomaly_config = {
            "anomaly_threshold": self.config.get("training.anomaly_threshold", 5.0),
            "statistical_threshold": self.config.get("training.statistical_threshold", 2.5)
        }
        return AnomalyScoringEngine(anomaly_config)
    
    def train(self, train_data_path: str, output_dir: str) -> Dict[str, Any]:
        """Train the models.
        
        Args:
            train_data_path: Path to training data
            output_dir: Directory to save outputs
            
        Returns:
            Training results dictionary
        """
        logger.info("Starting training...")
        start_time = time.time()
        
        # Create output directories
        model_dir = Path(output_dir) / self.config.get("output.model_dir", "models")
        metrics_dir = Path(output_dir) / self.config.get("output.metrics_dir", "metrics")
        logs_dir = Path(output_dir) / self.config.get("output.logs_dir", "logs")
        
        for dir_path in [model_dir, metrics_dir, logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        # Train NER model if configured
        if self.ner_trainer:
            logger.info("Training NER model...")
            ner_results = self._train_ner_model(train_data_path, model_dir)
            results["ner"] = ner_results
        
        # Train anomaly detection if configured
        if self.anomaly_engine:
            logger.info("Training anomaly detection...")
            anomaly_results = self._train_anomaly_model(train_data_path, model_dir)
            results["anomaly"] = anomaly_results
        
        # Save metrics
        self.metrics_collector.save_metrics(metrics_dir)
        
        # Calculate total training time
        total_time = time.time() - start_time
        results["total_training_time"] = total_time
        
        logger.info(f"Training completed in {total_time:.2f} seconds")
        return results
    
    def _train_ner_model(self, train_data_path: str, model_dir: Path) -> Dict[str, Any]:
        """Train NER model.
        
        Args:
            train_data_path: Path to training data
            model_dir: Directory to save model
            
        Returns:
            NER training results
        """
        # Load and prepare data
        logger.info("Loading NER training data...")
        
        # For now, create synthetic data for demonstration
        # In practice, this would load real labeled data
        synthetic_data = self._create_synthetic_ner_data()
        
        # Split data
        train_data, val_data, test_data = self._split_data(synthetic_data)
        
        # Create datasets
        tokenizer = self.ner_trainer.tokenizer
        max_length = self.config.get("model.max_length", 512)
        
        train_dataset = SecurityLogDataset(
            train_data, tokenizer, max_length, self.ner_trainer.label_map
        )
        val_dataset = SecurityLogDataset(
            val_data, tokenizer, max_length, self.ner_trainer.label_map
        )
        
        # Set up training arguments
        training_args = TrainingArguments(
            output_dir=str(model_dir / "ner"),
            num_train_epochs=self.config.get("training.epochs", 10),
            per_device_train_batch_size=self.config.get("training.batch_size", 16),
            per_device_eval_batch_size=self.config.get("training.batch_size", 16),
            learning_rate=self.config.get("training.learning_rate", 2e-5),
            weight_decay=self.config.get("training.weight_decay", 0.01),
            warmup_steps=self.config.get("training.warmup_steps", 500),
            gradient_accumulation_steps=self.config.get("training.gradient_accumulation_steps", 1),
            save_steps=self.config.get("training.save_steps", 500),
            eval_steps=self.config.get("training.eval_steps", 500),
            logging_steps=self.config.get("training.logging_steps", 100),
            evaluation_strategy="steps",
            save_strategy="steps",
            load_best_model_at_end=True,
            metric_for_best_model="eval_f1",
            greater_is_better=True,
            fp16=self.config.get("optimization.mixed_precision", True),
            gradient_checkpointing=self.config.get("optimization.gradient_checkpointing", False),
            dataloader_num_workers=self.config.get("optimization.dataloader_num_workers", 4),
            dataloader_pin_memory=self.config.get("optimization.pin_memory", True),
            report_to=["wandb"] if wandb.run else None
        )
        
        # Create trainer
        trainer = Trainer(
            model=self.ner_trainer.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=self._compute_ner_metrics,
            callbacks=[EarlyStoppingCallback(
                early_stopping_patience=self.config.get("training.early_stopping_patience", 3)
            )]
        )
        
        # Train model
        logger.info("Starting NER model training...")
        train_result = trainer.train()
        
        # Evaluate on test set
        test_dataset = SecurityLogDataset(
            test_data, tokenizer, max_length, self.ner_trainer.label_map
        )
        test_results = trainer.evaluate(test_dataset)
        
        # Save model
        trainer.save_model()
        tokenizer.save_pretrained(str(model_dir / "ner"))
        
        return {
            "train_loss": train_result.training_loss,
            "train_steps": train_result.global_step,
            "test_results": test_results
        }
    
    def _train_anomaly_model(self, train_data_path: str, model_dir: Path) -> Dict[str, Any]:
        """Train anomaly detection model.
        
        Args:
            train_data_path: Path to training data
            model_dir: Directory to save model
            
        Returns:
            Anomaly training results
        """
        # For anomaly detection, we primarily need to build baselines
        # This would involve processing historical events to establish normal patterns
        
        logger.info("Building anomaly detection baselines...")
        
        # Create synthetic events for demonstration
        synthetic_events = self._create_synthetic_events()
        
        # Process events to build behavioral baselines
        total_events = len(synthetic_events)
        anomaly_count = 0
        
        for i, (event, entities) in enumerate(synthetic_events):
            # Update behavioral profiles and detect anomalies
            anomaly_scores = self.anomaly_engine.score_event(event, entities)
            
            # Count anomalies
            if any(score.is_anomaly for score in anomaly_scores):
                anomaly_count += 1
            
            # Log metrics every 100 events
            if (i + 1) % 100 == 0:
                metrics = {
                    "processed_events": i + 1,
                    "anomaly_rate": anomaly_count / (i + 1),
                    "total_profiles": len(self.anomaly_engine.behavioral_detector.entity_profiles)
                }
                self.metrics_collector.log_metrics(metrics, i + 1, "anomaly_training/")
        
        # Save anomaly engine state
        engine_state = {
            "entity_profiles": len(self.anomaly_engine.behavioral_detector.entity_profiles),
            "combination_counts": len(self.anomaly_engine.rare_combo_detector.combination_counts),
            "total_combinations": self.anomaly_engine.rare_combo_detector.total_combinations,
            "detector_weights": self.anomaly_engine.detector_weights
        }
        
        with open(model_dir / "anomaly_engine_state.json", 'w') as f:
            json.dump(engine_state, f, indent=2)
        
        return {
            "total_events_processed": total_events,
            "anomaly_rate": anomaly_count / total_events,
            "final_profiles": len(self.anomaly_engine.behavioral_detector.entity_profiles)
        }
    
    def _compute_ner_metrics(self, eval_pred):
        """Compute NER metrics for evaluation."""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=2)
        
        # Remove padding and special tokens
        true_predictions = []
        true_labels = []
        
        for prediction, label in zip(predictions, labels):
            for pred_id, label_id in zip(prediction, label):
                if label_id != -100:  # -100 is the ignore index
                    true_predictions.append(pred_id)
                    true_labels.append(label_id)
        
        # Calculate metrics
        f1 = f1_score(true_labels, true_predictions, average='weighted')
        
        return {
            "f1": f1,
            "accuracy": (np.array(true_predictions) == np.array(true_labels)).mean()
        }
    
    def _create_synthetic_ner_data(self) -> List[Tuple[str, List[Tuple[str, str]]]]:
        """Create synthetic NER training data."""
        # This would be replaced with real data loading in production
        synthetic_data = [
            (
                "User john.doe@company.com assumed role arn:aws:iam::123456789012:role/S3ReadOnlyRole from IP 192.168.1.100",
                [
                    ("User", "O"),
                    ("john.doe@company.com", "B-USER"),
                    ("assumed", "O"),
                    ("role", "O"),
                    ("arn:aws:iam::123456789012:role/S3ReadOnlyRole", "B-ROLE"),
                    ("from", "O"),
                    ("IP", "O"),
                    ("192.168.1.100", "B-IP")
                ]
            ),
            (
                "Admin alice.smith created IAM user bob.jones with PowerUserAccess policy",
                [
                    ("Admin", "O"),
                    ("alice.smith", "B-USER"),
                    ("created", "O"),
                    ("IAM", "O"),
                    ("user", "O"),
                    ("bob.jones", "B-USER"),
                    ("with", "O"),
                    ("PowerUserAccess", "B-ROLE"),
                    ("policy", "O")
                ]
            )
        ] * 1000  # Repeat for training data
        
        return synthetic_data
    
    def _create_synthetic_events(self) -> List[Tuple[Any, List[Any]]]:
        """Create synthetic CloudTrail events for anomaly training."""
        # This would be replaced with real event loading in production
        from datetime import datetime, timedelta
        from src.detector.schemas import CloudTrailEvent, UserIdentity, ExtractedEntity
        
        synthetic_events = []
        base_time = datetime.utcnow()
        
        users = ["john.doe", "alice.smith", "bob.jones", "carol.white"]
        actions = ["AssumeRole", "CreateUser", "AttachUserPolicy", "ListUsers", "DescribeInstances"]
        ips = ["192.168.1.100", "10.0.1.50", "172.16.0.25"]
        
        for i in range(1000):
            event_time = base_time - timedelta(hours=i // 10)
            
            event = CloudTrailEvent(
                eventTime=event_time,
                eventName=np.random.choice(actions),
                userIdentity=UserIdentity(
                    type="IAMUser",
                    principalId="AIDACKCEVSQ6C2EXAMPLE",
                    arn=f"arn:aws:iam::123456789012:user/{np.random.choice(users)}",
                    accountId="123456789012",
                    userName=np.random.choice(users)
                ),
                awsRegion="us-east-1",
                sourceIPAddress=np.random.choice(ips),
                userAgent="aws-cli/2.0.0",
                requestParameters={},
                responseElements={}
            )
            
            # Create corresponding entities
            entities = [
                ExtractedEntity(
                    entity_id=event.userIdentity.userName,
                    entity_type="USER",
                    context={"source": "userIdentity"},
                    confidence=0.9
                ),
                ExtractedEntity(
                    entity_id=event.sourceIPAddress,
                    entity_type="IP",
                    context={"source": "sourceIPAddress"},
                    confidence=0.95
                )
            ]
            
            synthetic_events.append((event, entities))
        
        return synthetic_events
    
    def _split_data(self, data: List[Any]) -> Tuple[List[Any], List[Any], List[Any]]:
        """Split data into train/val/test sets."""
        train_split = self.config.get("data.train_split", 0.8)
        val_split = self.config.get("data.val_split", 0.1)
        
        # First split into train and temp
        train_data, temp_data = train_test_split(
            data, train_size=train_split, random_state=42
        )
        
        # Split temp into val and test
        val_size = val_split / (val_split + self.config.get("data.test_split", 0.1))
        val_data, test_data = train_test_split(
            temp_data, train_size=val_size, random_state=42
        )
        
        return train_data, val_data, test_data


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Train Security Event Anomaly Detection Models")
    
    parser.add_argument(
        "--config",
        type=str,
        help="Path to training configuration file"
    )
    parser.add_argument(
        "--hyperparams",
        type=str,
        help="Path to hyperparameters file"
    )
    parser.add_argument(
        "--train-data",
        type=str,
        default="data/train",
        help="Path to training data directory"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="output",
        help="Output directory for models and metrics"
    )
    parser.add_argument(
        "--model-type",
        type=str,
        choices=["ner", "anomaly", "both"],
        help="Type of model to train"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        help="Number of training epochs"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        help="Training batch size"
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        help="Learning rate"
    )
    parser.add_argument(
        "--device",
        type=str,
        choices=["auto", "cpu", "cuda"],
        default="auto",
        help="Device to use for training"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without actual training"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    return parser.parse_args()


def setup_logging(verbose: bool = False):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('training.log')
        ]
    )


def main():
    """Main training function."""
    args = parse_args()
    setup_logging(args.verbose)
    
    logger.info("Starting Security Detector training...")
    logger.info(f"Arguments: {vars(args)}")
    
    try:
        # Load configuration
        config = TrainingConfig(args.config, args.hyperparams)
        
        # Override config with command line arguments
        if args.model_type:
            config.config["model"]["type"] = args.model_type
        if args.epochs:
            config.config["training"]["epochs"] = args.epochs
        if args.batch_size:
            config.config["training"]["batch_size"] = args.batch_size
        if args.learning_rate:
            config.config["training"]["learning_rate"] = args.learning_rate
        
        # Set device if specified
        if args.device != "auto":
            if args.device == "cuda" and not torch.cuda.is_available():
                logger.warning("CUDA not available, falling back to CPU")
                args.device = "cpu"
        
        if args.dry_run:
            logger.info("Dry run mode - configuration loaded successfully")
            logger.info(f"Final configuration: {json.dumps(config.config, indent=2)}")
            return
        
        # Initialize trainer
        trainer = SecurityDetectorTrainer(config)
        
        # Run training
        results = trainer.train(args.train_data, args.output_dir)
        
        # Save final results
        results_path = Path(args.output_dir) / "training_results.json"
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info("Training completed successfully!")
        logger.info(f"Results: {json.dumps(results, indent=2, default=str)}")
        
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()