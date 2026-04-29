#!/usr/bin/env python3
"""
Train IDS models on real-world datasets.

Usage:
    # Train on VeReMi dataset
    python train_on_dataset.py --dataset veremi --path ./datasets/veremi.csv

    # Train on CICIoV2024
    python train_on_dataset.py --dataset ciciv --path ./datasets/ciciv2024.csv

    # Train on any CSV (specify label column)
    python train_on_dataset.py --dataset csv --path ./datasets/mydata.csv --label-col label

    # Train on built-in synthetic data (no download needed)
    python train_on_dataset.py --dataset synthetic

    # Show evaluation metrics after training
    python train_on_dataset.py --dataset synthetic --evaluate
"""

import os
import sys
import json
import argparse
import logging
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ids.config import (
    TRAINING_EPOCHS, TRAINING_BATCH_SIZE,
    BSM_FEATURE_DIM, LSTM_WINDOW_SIZE, MODEL_SAVE_DIR,
)
from ids.models.cnn_model import CNNModel
from ids.models.lstm_model import LSTMModel
from ids.metrics.evaluator import IDSEvaluator
from ids.data.dataset_loader import DatasetLoader
from ids.data.generate_training_data import TrainingDataGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="Train IDS models on real or synthetic datasets"
    )
    parser.add_argument(
        "--dataset", required=True,
        choices=["veremi", "ciciv", "csv", "synthetic"],
        help="Dataset type to load",
    )
    parser.add_argument("--path", help="Path to dataset CSV file")
    parser.add_argument("--label-col", default="label",
                        help="Label column name (for csv mode)")
    parser.add_argument("--epochs", type=int, default=TRAINING_EPOCHS)
    parser.add_argument("--batch-size", type=int, default=TRAINING_BATCH_SIZE)
    parser.add_argument("--output-dir", default=MODEL_SAVE_DIR)
    parser.add_argument("--evaluate", action="store_true",
                        help="Show detailed evaluation after training")
    args = parser.parse_args()

    # ── Load Data ────────────────────────────────────────────────────────
    loader = DatasetLoader()

    if args.dataset == "synthetic":
        logger.info("Using built-in synthetic data generator")
        gen = TrainingDataGenerator()
        cnn_data = gen.generate_cnn_dataset(n_normal=5000, n_attack=1000)
        lstm_data = gen.generate_lstm_dataset(n_normal=1000, n_attack=200)
    else:
        if not args.path or not os.path.exists(args.path):
            logger.error("Dataset file not found: %s", args.path)
            print("\n  ERROR: Please provide a valid --path to your CSV file.")
            print("  See the walkthrough for download links.\n")
            sys.exit(1)

        if args.dataset == "veremi":
            data = loader.load_veremi(args.path)
        elif args.dataset == "ciciv":
            data = loader.load_ciciv(args.path)
        else:
            data = loader.load_csv(args.path, label_column=args.label_col)

        cnn_data = data

        # Build LSTM sequences from the same data
        X_all = np.vstack([data["X_train"], data["X_test"]])
        y_all = np.concatenate([data["y_train"], data["y_test"]])
        X_seq, y_seq = loader.build_lstm_sequences(X_all, y_all, LSTM_WINDOW_SIZE)

        if len(X_seq) > 0:
            split = int(len(X_seq) * 0.8)
            lstm_data = {
                "X_train": X_seq[:split], "y_train": y_seq[:split],
                "X_test": X_seq[split:], "y_test": y_seq[split:],
            }
        else:
            logger.warning("Not enough data for LSTM sequences, using synthetic")
            gen = TrainingDataGenerator()
            lstm_data = gen.generate_lstm_dataset(n_normal=500, n_attack=100)

    # ── Train CNN ────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("TRAINING CNN MODEL")
    logger.info("Data shape: X=%s, y=%s", cnn_data["X_train"].shape,
                cnn_data["y_train"].shape)
    logger.info("=" * 60)

    cnn = CNNModel(input_dim=BSM_FEATURE_DIM)
    cnn_result = cnn.train(
        cnn_data["X_train"], cnn_data["y_train"],
        epochs=args.epochs, batch_size=args.batch_size,
    )
    logger.info("CNN training result: %s", cnn_result)

    # ── Train LSTM ───────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("TRAINING LSTM MODEL")
    logger.info("Data shape: X=%s, y=%s", lstm_data["X_train"].shape,
                lstm_data["y_train"].shape)
    logger.info("=" * 60)

    lstm = LSTMModel(window_size=LSTM_WINDOW_SIZE, feature_dim=BSM_FEATURE_DIM)
    lstm_result = lstm.train(
        lstm_data["X_train"], lstm_data["y_train"],
        epochs=args.epochs, batch_size=args.batch_size,
    )
    logger.info("LSTM training result: %s", lstm_result)

    # ── Save Models ──────────────────────────────────────────────────────
    os.makedirs(args.output_dir, exist_ok=True)
    cnn.save(os.path.join(args.output_dir, "cnn_model"))
    lstm.save(os.path.join(args.output_dir, "lstm_model"))
    logger.info("Models saved to %s", args.output_dir)

    # ── Evaluate ─────────────────────────────────────────────────────────
    if args.evaluate:
        evaluator = IDSEvaluator()

        logger.info("=" * 60)
        logger.info("EVALUATION RESULTS")
        logger.info("=" * 60)

        # CNN evaluation
        cnn_preds = np.array([
            cnn.predict_anomaly_score(cnn_data["X_test"][i:i+1])
            for i in range(len(cnn_data["X_test"]))
        ])
        cnn_eval = evaluator.evaluate(cnn_data["y_test"], cnn_preds, model_name="CNN")

        # LSTM evaluation
        lstm_preds = np.array([
            lstm.predict_anomaly_score(lstm_data["X_test"][i:i+1])
            for i in range(len(lstm_data["X_test"]))
        ])
        lstm_eval = evaluator.evaluate(lstm_data["y_test"], lstm_preds, model_name="LSTM")

        # Print summary
        print("\n" + "=" * 60)
        print("  MODEL EVALUATION SUMMARY")
        print("=" * 60)
        for name, result in [("CNN", cnn_eval), ("LSTM", lstm_eval)]:
            print(f"\n  {name} Model:")
            print(f"    Accuracy:  {result['accuracy']:.4f}")
            print(f"    Precision: {result['precision']:.4f}")
            print(f"    Recall:    {result['recall']:.4f}")
            print(f"    F1 Score:  {result['f1_score']:.4f}")
            print(f"    ROC-AUC:   {result['roc_auc']:.4f}")

            benchmarks = evaluator.meets_benchmarks(result)
            print(f"    Meets F1≥95.1%:     {'✓' if benchmarks['f1_target_95.1'] else '✗'}")
            print(f"    Meets AUC≥0.96:     {'✓' if benchmarks['auc_target_0.96'] else '✗'}")
            print(f"    Meets Recall≥96.8%: {'✓' if benchmarks['recall_target_96.8'] else '✗'}")

        # Save results
        results_path = os.path.join(args.output_dir, "evaluation_results.json")
        with open(results_path, "w") as f:
            json.dump({"cnn": cnn_eval, "lstm": lstm_eval}, f, indent=2)
        print(f"\n  Results saved to: {results_path}")

    print("\n✓ Training complete!\n")


if __name__ == "__main__":
    main()
