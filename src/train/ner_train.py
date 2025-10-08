"""NER Model Training Pipeline for Security Entity Extraction.

This module implements a comprehensive training pipeline for fine-tuning transformer
models to extract security-relevant entities from AWS CloudTrail and VPC Flow Logs.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
import warnings

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForTokenClassification,
    TrainingArguments,
    Trainer,
    DataCollatorForTokenClassification,
    EarlyStoppingCallback
)
from sklearn.metrics import classification_report, f1_score, precision_recall_fscore_support
import boto3
from botocore.exceptions import ClientError

from detector.schemas import EntityType, ExtractedEntity
from detector.config import load_config

logger = logging.getLogger(__name__)

# Suppress transformers warnings for cleaner output
warnings.filterwarnings("ignore", category=UserWarning, module="transformers")


class SecurityLogDataset(Dataset):
    """PyTorch Dataset for security log NER training."""
    
    def __init__(
        self,
        texts: List[str],
        labels: List[List[str]],
        tokenizer,
        max_length: int = 512,
        label_to_id: Optional[Dict[str, int]] = None
    ):
        """Initialize the dataset.
        
        Args:
            texts: List of input texts (log entries)
            labels: List of label sequences (BIO format)
            tokenizer: HuggingFace tokenizer
            max_length: Maximum sequence length
            label_to_id: Mapping from label names to IDs
        """
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length
        
        # Create label mapping if not provided
        if label_to_id is None:
            unique_labels = set()
            for label_seq in labels:
                unique_labels.update(label_seq)
            self.label_to_id = {label: idx for idx, label in enumerate(sorted(unique_labels))}
        else:
            self.label_to_id = label_to_id
        
        self.id_to_label = {idx: label for label, idx in self.label_to_id.items()}
    
    def __len__(self):
        return len(self.texts)
    
    def __getitem__(self, idx):
        text = self.texts[idx]
        labels = self.labels[idx]
        
        # Tokenize input
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )
        
        # Align labels with tokenized input
        aligned_labels = self._align_labels_with_tokens(text, labels, encoding)
        
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(aligned_labels, dtype=torch.long)
        }
    
    def _align_labels_with_tokens(
        self, 
        text: str, 
        labels: List[str], 
        encoding
    ) -> List[int]:
        """Align BIO labels with tokenized input."""
        # Simple word-level alignment (could be enhanced with spaCy)
        words = text.split()
        
        if len(words) != len(labels):
            logger.warning(f"Mismatch between words ({len(words)}) and labels ({len(labels)})")
            # Pad or truncate labels to match
            if len(labels) < len(words):
                labels.extend(['O'] * (len(words) - len(labels)))
            else:
                labels = labels[:len(words)]
        
        # Map to token-level labels
        token_labels = []
        word_idx = 0
        
        for i, token_id in enumerate(encoding['input_ids'][0]):
            if i == 0:  # [CLS] token
                token_labels.append(self.label_to_id.get('O', 0))
            elif i == len(encoding['input_ids'][0]) - 1:  # [SEP] token
                token_labels.append(self.label_to_id.get('O', 0))
            elif word_idx < len(labels):
                token_labels.append(self.label_to_id.get(labels[word_idx], 0))
                word_idx += 1
            else:
                token_labels.append(self.label_to_id.get('O', 0))
        
        # Pad to max_length
        while len(token_labels) < self.max_length:
            token_labels.append(self.label_to_id.get('O', 0))
        
        return token_labels[:self.max_length]


class NERTrainer:
    """Trainer class for NER model fine-tuning."""
    
    def __init__(
        self,
        config: Dict[str, Any],
        model_name: str = "distilbert-base-uncased",
        output_dir: str = "./models"
    ):
        """Initialize the NER trainer.
        
        Args:
            config: Configuration dictionary
            model_name: HuggingFace model name
            output_dir: Directory to save trained models
        """
        self.config = config
        self.model_name = model_name
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize tokenizer and model
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        # Add special tokens for security entities
        special_tokens = ["[ARN]", "[IP]", "[VPC]", "[KEY]", "[BUCKET]"]
        self.tokenizer.add_tokens(special_tokens)
        
        # Label configuration for BIO tagging
        self.entity_types = [
            "IAM_ROLE_ARN", "IAM_USER_ARN", "IP_ADDRESS", 
            "VPC_ID", "SUBNET_ID", "KMS_KEY_ID", 
            "S3_BUCKET", "EC2_INSTANCE_ID", "SECURITY_GROUP_ID"
        ]
        
        # Create BIO labels
        self.labels = ["O"]  # Outside
        for entity_type in self.entity_types:
            self.labels.extend([f"B-{entity_type}", f"I-{entity_type}"])
        
        self.label_to_id = {label: idx for idx, label in enumerate(self.labels)}
        self.id_to_label = {idx: label for label, idx in self.label_to_id.items()}
        
        # Initialize model
        self.model = AutoModelForTokenClassification.from_pretrained(
            model_name,
            num_labels=len(self.labels),
            id2label=self.id_to_label,
            label2id=self.label_to_id
        )
        
        # Resize token embeddings to include new tokens
        self.model.resize_token_embeddings(len(self.tokenizer))
        
        # Training metrics storage
        self.training_metrics = []
        
        # CloudWatch client for metrics
        self.cloudwatch_client = None
        if config.get("aws", {}).get("profile"):
            session = boto3.Session(profile_name=config["aws"]["profile"])
            self.cloudwatch_client = session.client('cloudwatch')
    
    def prepare_training_data(
        self, 
        synthetic_data_path: Optional[str] = None,
        real_data_path: Optional[str] = None
    ) -> Tuple[SecurityLogDataset, SecurityLogDataset]:
        """Prepare training and validation datasets.
        
        Args:
            synthetic_data_path: Path to synthetic training data
            real_data_path: Path to real log data (if available)
            
        Returns:
            Tuple of (train_dataset, val_dataset)
        """
        # Load synthetic data
        if synthetic_data_path and Path(synthetic_data_path).exists():
            with open(synthetic_data_path, 'r') as f:
                synthetic_data = json.load(f)
        else:
            # Generate synthetic data if not provided
            synthetic_data = self._generate_synthetic_training_data()
        
        # Prepare texts and labels
        texts, labels = self._convert_to_bio_format(synthetic_data)
        
        # Split into train/validation (80/20)
        split_idx = int(0.8 * len(texts))
        
        train_texts = texts[:split_idx]
        train_labels = labels[:split_idx]
        val_texts = texts[split_idx:]
        val_labels = labels[split_idx:]
        
        # Create datasets
        train_dataset = SecurityLogDataset(
            train_texts, train_labels, self.tokenizer, 
            label_to_id=self.label_to_id
        )
        
        val_dataset = SecurityLogDataset(
            val_texts, val_labels, self.tokenizer,
            label_to_id=self.label_to_id
        )
        
        logger.info(f"Prepared training data: {len(train_dataset)} train, {len(val_dataset)} val samples")
        return train_dataset, val_dataset
    
    def _generate_synthetic_training_data(self) -> List[Dict[str, Any]]:
        """Generate synthetic training data for NER."""
        from data.generate_logs import SecurityLogGenerator
        
        generator = SecurityLogGenerator()
        synthetic_data = []
        
        # Generate CloudTrail events
        for _ in range(1000):
            event = generator.generate_cloudtrail_event()
            synthetic_data.append({
                "text": json.dumps(event.dict()),
                "entities": self._extract_entities_from_event(event)
            })
        
        # Generate VPC Flow Logs
        for _ in range(500):
            log = generator.generate_vpc_flow_log()
            synthetic_data.append({
                "text": f"{log.srcaddr} {log.dstaddr} {log.action}",
                "entities": [
                    {"start": 0, "end": len(log.srcaddr), "label": "IP_ADDRESS"},
                    {"start": len(log.srcaddr) + 1, "end": len(log.srcaddr) + 1 + len(log.dstaddr), "label": "IP_ADDRESS"}
                ]
            })
        
        return synthetic_data
    
    def _extract_entities_from_event(self, event) -> List[Dict[str, Any]]:
        """Extract entity annotations from CloudTrail event."""
        entities = []
        text = json.dumps(event.dict())
        
        # Extract ARNs
        if hasattr(event, 'userIdentity') and event.userIdentity.arn:
            arn = event.userIdentity.arn
            start = text.find(arn)
            if start != -1:
                entity_type = "IAM_ROLE_ARN" if "role" in arn else "IAM_USER_ARN"
                entities.append({
                    "start": start,
                    "end": start + len(arn),
                    "label": entity_type
                })
        
        # Extract IP addresses
        if hasattr(event, 'sourceIPAddress') and event.sourceIPAddress:
            ip = event.sourceIPAddress
            start = text.find(ip)
            if start != -1:
                entities.append({
                    "start": start,
                    "end": start + len(ip),
                    "label": "IP_ADDRESS"
                })
        
        return entities
    
    def _convert_to_bio_format(
        self, 
        data: List[Dict[str, Any]]
    ) -> Tuple[List[str], List[List[str]]]:
        """Convert entity annotations to BIO format."""
        texts = []
        labels = []
        
        for item in data:
            text = item["text"]
            entities = item.get("entities", [])
            
            # Simple word-level tokenization
            words = text.split()
            word_labels = ["O"] * len(words)
            
            # Map entity spans to word-level labels
            for entity in entities:
                start_char = entity["start"]
                end_char = entity["end"]
                label = entity["label"]
                
                # Find words that overlap with entity span
                char_pos = 0
                for i, word in enumerate(words):
                    word_start = char_pos
                    word_end = char_pos + len(word)
                    
                    if word_start >= start_char and word_end <= end_char:
                        if word_labels[i] == "O":  # Only label if not already labeled
                            if word_start == start_char:
                                word_labels[i] = f"B-{label}"
                            else:
                                word_labels[i] = f"I-{label}"
                    
                    char_pos = word_end + 1  # +1 for space
            
            texts.append(text)
            labels.append(word_labels)
        
        return texts, labels
    
    def train(
        self,
        train_dataset: SecurityLogDataset,
        val_dataset: SecurityLogDataset,
        num_epochs: int = 3,
        learning_rate: float = 2e-5,
        batch_size: int = 16,
        warmup_steps: int = 500,
        weight_decay: float = 0.01
    ) -> Dict[str, Any]:
        """Train the NER model.
        
        Args:
            train_dataset: Training dataset
            val_dataset: Validation dataset
            num_epochs: Number of training epochs
            learning_rate: Learning rate
            batch_size: Training batch size
            warmup_steps: Number of warmup steps
            weight_decay: Weight decay for regularization
            
        Returns:
            Training metrics and model paths
        """
        # Training arguments
        training_args = TrainingArguments(
            output_dir=str(self.output_dir / "checkpoints"),
            num_train_epochs=num_epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            warmup_steps=warmup_steps,
            weight_decay=weight_decay,
            learning_rate=learning_rate,
            logging_dir=str(self.output_dir / "logs"),
            logging_steps=50,
            evaluation_strategy="steps",
            eval_steps=200,
            save_strategy="steps",
            save_steps=200,
            load_best_model_at_end=True,
            metric_for_best_model="eval_f1",
            greater_is_better=True,
            remove_unused_columns=False,
            push_to_hub=False,
            report_to=None  # Disable wandb/tensorboard
        )
        
        # Data collator
        data_collator = DataCollatorForTokenClassification(
            tokenizer=self.tokenizer,
            padding=True
        )
        
        # Initialize trainer
        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            tokenizer=self.tokenizer,
            data_collator=data_collator,
            compute_metrics=self._compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
        )
        
        # Train the model
        logger.info("Starting NER model training...")
        train_result = trainer.train()
        
        # Save the final model
        model_save_path = self.output_dir / f"ner_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        trainer.save_model(str(model_save_path))
        self.tokenizer.save_pretrained(str(model_save_path))
        
        # Final evaluation
        eval_result = trainer.evaluate()
        
        # Compile training metrics
        final_metrics = {
            "model_name": self.model_name,
            "model_save_path": str(model_save_path),
            "training_time": train_result.metrics.get("train_runtime", 0),
            "train_loss": train_result.metrics.get("train_loss", 0),
            "eval_metrics": eval_result,
            "num_parameters": self.model.num_parameters(),
            "num_train_samples": len(train_dataset),
            "num_val_samples": len(val_dataset),
            "training_config": {
                "num_epochs": num_epochs,
                "learning_rate": learning_rate,
                "batch_size": batch_size,
                "warmup_steps": warmup_steps,
                "weight_decay": weight_decay
            },
            "label_distribution": self._analyze_label_distribution(train_dataset),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Save metrics
        metrics_file = self.output_dir / f"training_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(metrics_file, 'w') as f:
            json.dump(final_metrics, f, indent=2)
        
        # Send metrics to CloudWatch
        if self.cloudwatch_client:
            self._send_metrics_to_cloudwatch(final_metrics)
        
        logger.info(f"Training completed. Model saved to: {model_save_path}")
        logger.info(f"Final F1 Score: {eval_result.get('eval_f1', 'N/A')}")
        
        return final_metrics
    
    def _compute_metrics(self, eval_pred):
        """Compute evaluation metrics."""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=2)
        
        # Remove ignored index (padding tokens)
        true_predictions = [
            [self.id_to_label[p] for p, l in zip(prediction, label) if l != -100]
            for prediction, label in zip(predictions, labels)
        ]
        true_labels = [
            [self.id_to_label[l] for p, l in zip(prediction, label) if l != -100]
            for prediction, label in zip(predictions, labels)
        ]
        
        # Flatten for sklearn metrics
        flat_true_labels = [label for sublist in true_labels for label in sublist]
        flat_predictions = [pred for sublist in true_predictions for pred in sublist]
        
        # Calculate metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            flat_true_labels, flat_predictions, average='weighted', zero_division=0
        )
        
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1
        }
    
    def _analyze_label_distribution(self, dataset: SecurityLogDataset) -> Dict[str, int]:
        """Analyze label distribution in the dataset."""
        label_counts = {}
        
        for i in range(len(dataset)):
            item = dataset[i]
            labels = item['labels']
            
            for label_id in labels:
                label_name = self.id_to_label.get(label_id.item(), 'UNKNOWN')
                label_counts[label_name] = label_counts.get(label_name, 0) + 1
        
        return label_counts
    
    def _send_metrics_to_cloudwatch(self, metrics: Dict[str, Any]) -> None:
        """Send training metrics to CloudWatch."""
        try:
            namespace = f"AnomalyDetector/{self.config.get('environment', 'dev')}"
            
            # Send key metrics
            metric_data = [
                {
                    'MetricName': 'NER_F1_Score',
                    'Value': metrics["eval_metrics"].get("eval_f1", 0),
                    'Unit': 'None',
                    'Dimensions': [
                        {'Name': 'ModelName', 'Value': self.model_name},
                        {'Name': 'Environment', 'Value': self.config.get('environment', 'dev')}
                    ]
                },
                {
                    'MetricName': 'NER_Precision',
                    'Value': metrics["eval_metrics"].get("eval_precision", 0),
                    'Unit': 'None',
                    'Dimensions': [
                        {'Name': 'ModelName', 'Value': self.model_name},
                        {'Name': 'Environment', 'Value': self.config.get('environment', 'dev')}
                    ]
                },
                {
                    'MetricName': 'NER_Recall',
                    'Value': metrics["eval_metrics"].get("eval_recall", 0),
                    'Unit': 'None',
                    'Dimensions': [
                        {'Name': 'ModelName', 'Value': self.model_name},
                        {'Name': 'Environment', 'Value': self.config.get('environment', 'dev')}
                    ]
                },
                {
                    'MetricName': 'Training_Time_Seconds',
                    'Value': metrics.get("training_time", 0),
                    'Unit': 'Seconds',
                    'Dimensions': [
                        {'Name': 'ModelName', 'Value': self.model_name},
                        {'Name': 'Environment', 'Value': self.config.get('environment', 'dev')}
                    ]
                }
            ]
            
            self.cloudwatch_client.put_metric_data(
                Namespace=namespace,
                MetricData=metric_data
            )
            
            logger.info("Training metrics sent to CloudWatch")
            
        except Exception as e:
            logger.warning(f"Failed to send metrics to CloudWatch: {str(e)}")


def train_ner_model(
    config_env: str = "dev",
    model_name: str = "distilbert-base-uncased",
    epochs: int = 3,
    learning_rate: float = 2e-5,
    batch_size: int = 16
) -> Dict[str, Any]:
    """Convenience function to train NER model.
    
    Args:
        config_env: Configuration environment (dev/prod)
        model_name: HuggingFace model name
        epochs: Number of training epochs
        learning_rate: Learning rate
        batch_size: Training batch size
        
    Returns:
        Training metrics and results
    """
    # Load configuration
    config = load_config(config_env)
    
    # Initialize trainer
    trainer = NERTrainer(
        config=config,
        model_name=model_name,
        output_dir=f"./models/{config_env}"
    )
    
    # Prepare data
    train_dataset, val_dataset = trainer.prepare_training_data()
    
    # Train model
    metrics = trainer.train(
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        num_epochs=epochs,
        learning_rate=learning_rate,
        batch_size=batch_size
    )
    
    return metrics


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Train NER model for security entity extraction")
    parser.add_argument("--config", default="dev", help="Configuration environment")
    parser.add_argument("--model", default="distilbert-base-uncased", help="Model name")
    parser.add_argument("--epochs", type=int, default=3, help="Number of epochs")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
    parser.add_argument("--batch-size", type=int, default=16, help="Batch size")
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Train model
    metrics = train_ner_model(
        config_env=args.config,
        model_name=args.model,
        epochs=args.epochs,
        learning_rate=args.lr,
        batch_size=args.batch_size
    )
    
    print(f"Training completed successfully!")
    print(f"F1 Score: {metrics['eval_metrics'].get('eval_f1', 'N/A')}")
    print(f"Model saved to: {metrics['model_save_path']}")