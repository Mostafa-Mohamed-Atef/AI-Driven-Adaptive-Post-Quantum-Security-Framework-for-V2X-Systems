"""
Model Trainer — End-to-end training pipeline for CNN and LSTM models.

Generates synthetic BSM data with labeled attacks, trains both models,
evaluates performance, and persists the trained weights.
"""

import os
import time
import logging
import numpy as np

from ids.config import (
    TRAINING_EPOCHS,
    TRAINING_BATCH_SIZE,
    BSM_FEATURE_DIM,
    LSTM_WINDOW_SIZE,
    MODEL_SAVE_DIR,
)
from ids.models.cnn_model import CNNModel
from ids.models.lstm_model import LSTMModel
from ids.data.generate_training_data import TrainingDataGenerator
from ids.metrics.evaluator import IDSEvaluator

logger = logging.getLogger(__name__)


class ModelTrainer:
    """
    Orchestrates synthetic data generation, model training, evaluation,
    and persistence for both CNN and LSTM models.
    """

    def __init__(self):
        self.cnn_model = CNNModel(input_dim=BSM_FEATURE_DIM)
        self.lstm_model = LSTMModel(
            window_size=LSTM_WINDOW_SIZE,
            feature_dim=BSM_FEATURE_DIM,
        )
        self.data_generator = TrainingDataGenerator()
        self.evaluator = IDSEvaluator()
        self.training_results = {}

    def train_all(self, n_normal: int = 5000, n_attack: int = 1000) -> dict:
        """
        Full training pipeline:
          1. Generate synthetic data
          2. Train CNN on individual BSMs
          3. Train LSTM on BSM sequences
          4. Evaluate both models
          5. Save models

        Returns dict with training and evaluation metrics.
        """
        logger.info("=" * 60)
        logger.info("STARTING MODEL TRAINING PIPELINE")
        logger.info("=" * 60)
        start = time.time()

        results = {}

        # ── 1. Generate training data ────────────────────────────────────
        logger.info("Generating synthetic training data...")
        cnn_data = self.data_generator.generate_cnn_dataset(
            n_normal=n_normal, n_attack=n_attack
        )
        lstm_data = self.data_generator.generate_lstm_dataset(
            n_normal=n_normal // 5, n_attack=n_attack // 5,
            window_size=LSTM_WINDOW_SIZE,
        )

        logger.info(
            "CNN data: X=%s, y=%s (%.1f%% attack)",
            cnn_data["X_train"].shape,
            cnn_data["y_train"].shape,
            100 * cnn_data["y_train"].mean(),
        )
        logger.info(
            "LSTM data: X=%s, y=%s (%.1f%% attack)",
            lstm_data["X_train"].shape,
            lstm_data["y_train"].shape,
            100 * lstm_data["y_train"].mean(),
        )

        # ── 2. Train CNN ─────────────────────────────────────────────────
        logger.info("Training CNN model...")
        cnn_history = self.cnn_model.train(
            cnn_data["X_train"], cnn_data["y_train"],
            epochs=TRAINING_EPOCHS,
            batch_size=TRAINING_BATCH_SIZE,
        )
        results["cnn_training"] = cnn_history
        logger.info("CNN training complete: %s", cnn_history)

        # ── 3. Train LSTM ────────────────────────────────────────────────
        logger.info("Training LSTM model...")
        lstm_history = self.lstm_model.train(
            lstm_data["X_train"], lstm_data["y_train"],
            epochs=TRAINING_EPOCHS,
            batch_size=TRAINING_BATCH_SIZE,
        )
        results["lstm_training"] = lstm_history
        logger.info("LSTM training complete: %s", lstm_history)

        # ── 4. Evaluate ──────────────────────────────────────────────────
        logger.info("Evaluating models...")

        # CNN evaluation
        cnn_preds = []
        for i in range(len(cnn_data["X_test"])):
            sample = cnn_data["X_test"][i:i+1]
            score = self.cnn_model.predict_anomaly_score(sample)
            cnn_preds.append(score)
        cnn_preds = np.array(cnn_preds)

        cnn_eval = self.evaluator.evaluate(
            cnn_data["y_test"], cnn_preds,
            model_name="CNN"
        )
        results["cnn_evaluation"] = cnn_eval

        # LSTM evaluation
        lstm_preds = []
        for i in range(len(lstm_data["X_test"])):
            sample = lstm_data["X_test"][i:i+1]
            score = self.lstm_model.predict_anomaly_score(sample)
            lstm_preds.append(score)
        lstm_preds = np.array(lstm_preds)

        lstm_eval = self.evaluator.evaluate(
            lstm_data["y_test"], lstm_preds,
            model_name="LSTM"
        )
        results["lstm_evaluation"] = lstm_eval

        # ── 5. Save models ───────────────────────────────────────────────
        os.makedirs(MODEL_SAVE_DIR, exist_ok=True)
        cnn_path = os.path.join(MODEL_SAVE_DIR, "cnn_model")
        lstm_path = os.path.join(MODEL_SAVE_DIR, "lstm_model")

        self.cnn_model.save(cnn_path)
        self.lstm_model.save(lstm_path)

        elapsed = time.time() - start
        results["total_time_seconds"] = round(elapsed, 2)
        self.training_results = results

        logger.info("=" * 60)
        logger.info("TRAINING PIPELINE COMPLETE (%.1fs)", elapsed)
        logger.info("CNN — Accuracy: %.3f, F1: %.3f",
                     cnn_eval.get("accuracy", 0), cnn_eval.get("f1_score", 0))
        logger.info("LSTM — Accuracy: %.3f, F1: %.3f",
                     lstm_eval.get("accuracy", 0), lstm_eval.get("f1_score", 0))
        logger.info("=" * 60)

        return results

    def load_pretrained(self) -> bool:
        """
        Attempt to load pre-trained models from disk.
        Returns True if at least one model was loaded.
        """
        loaded = False
        cnn_path = os.path.join(MODEL_SAVE_DIR, "cnn_model")
        lstm_path = os.path.join(MODEL_SAVE_DIR, "lstm_model")

        if os.path.exists(cnn_path) or os.path.exists(cnn_path + ".pkl"):
            self.cnn_model.load(cnn_path)
            loaded = True

        if os.path.exists(lstm_path) or os.path.exists(lstm_path + ".pkl"):
            self.lstm_model.load(lstm_path)
            loaded = True

        return loaded
