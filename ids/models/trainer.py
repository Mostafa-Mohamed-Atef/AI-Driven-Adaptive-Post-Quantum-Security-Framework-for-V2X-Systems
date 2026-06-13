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
        self.scaler = None

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
        self.scaler = cnn_data.get("scaler")
        lstm_data = self.data_generator.generate_lstm_dataset(
            n_normal=n_normal // 5, n_attack=n_attack // 5,
            window_size=LSTM_WINDOW_SIZE,
            scaler=self.scaler,
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

        if self.scaler is not None:
            import joblib
            joblib.dump(self.scaler, os.path.join(MODEL_SAVE_DIR, "feature_scaler.pkl"))
            logger.info("Feature scaler saved to %s", MODEL_SAVE_DIR)

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

    def fine_tune(self, features: np.ndarray, label: int) -> dict:
        """
        Incrementally update both models on a single confirmed sample.

        Called by the /api/ids/adapt endpoint when the Misbehavior Authority
        confirms (label=1) or rejects (label=0) an IDS alert.  Uses a very
        small learning rate so the models improve without catastrophic forgetting.
        """
        results = {}
        FINE_TUNE_LR = 1e-5

        try:
            import tensorflow as tf
            from tensorflow import keras

            X_cnn = features.reshape(1, -1, 1).astype(np.float32)
            y     = np.array([label], dtype=np.float32)

            # CNN fine-tune
            if self.cnn_model._trained and self.cnn_model._use_tf:
                self.cnn_model.model.optimizer.learning_rate = FINE_TUNE_LR
                loss = self.cnn_model.model.train_on_batch(X_cnn, y)
                results["cnn_loss"] = float(loss[0]) if isinstance(loss, (list, tuple)) else float(loss)

            # LSTM fine-tune: build a single-step sequence by repeating the feature vector
            if self.lstm_model._trained and self.lstm_model._use_tf:
                from ids.config import LSTM_WINDOW_SIZE
                X_seq = np.tile(features, (LSTM_WINDOW_SIZE, 1))[np.newaxis].astype(np.float32)
                self.lstm_model.model.optimizer.learning_rate = FINE_TUNE_LR
                loss = self.lstm_model.model.train_on_batch(X_seq, y)
                results["lstm_loss"] = float(loss[0]) if isinstance(loss, (list, tuple)) else float(loss)

            results["label"]  = label
            results["status"] = "fine-tuned"
            logger.info("Fine-tuned on confirmed label=%d — CNN loss=%s LSTM loss=%s",
                        label,
                        results.get("cnn_loss", "n/a"),
                        results.get("lstm_loss", "n/a"))
        except Exception as exc:
            logger.warning("Fine-tune failed: %s", exc)
            results["status"] = "failed"
            results["error"]  = str(exc)

        return results

    def load_pretrained(self) -> bool:
        """
        Attempt to load pre-trained models from disk.
        Returns True if at least one model was loaded.
        """
        loaded = False
        cnn_path = os.path.join(MODEL_SAVE_DIR, "cnn_model")
        lstm_path = os.path.join(MODEL_SAVE_DIR, "lstm_model")

        if (os.path.exists(cnn_path + ".keras") or os.path.exists(cnn_path + ".pkl")):
            self.cnn_model.load(cnn_path)
            loaded = True

        if (os.path.exists(lstm_path + ".keras") or os.path.exists(lstm_path + ".pkl")):
            self.lstm_model.load(lstm_path)
            loaded = True

        scaler_path = os.path.join(MODEL_SAVE_DIR, "feature_scaler.pkl")
        if os.path.exists(scaler_path):
            import joblib
            self.scaler = joblib.load(scaler_path)
            logger.info("Feature scaler loaded from %s", scaler_path)

        return loaded
