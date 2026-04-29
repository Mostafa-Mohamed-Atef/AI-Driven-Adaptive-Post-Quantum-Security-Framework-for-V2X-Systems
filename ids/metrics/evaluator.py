"""
IDS Evaluator — Precision, Recall, F1, ROC-AUC metrics.

Provides comprehensive evaluation of detection model performance
with targets from the reference paper:
  - Sybil F1 >= 95.1%
  - FDI detection rate >= 96.8%
  - ROC-AUC >= 0.96
"""

import logging
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report,
)

logger = logging.getLogger(__name__)


class IDSEvaluator:
    """Evaluate IDS detection models with advanced metrics."""

    def __init__(self):
        self.results_history = []

    def evaluate(self, y_true: np.ndarray, y_scores: np.ndarray,
                 threshold: float = 0.5, model_name: str = "Model") -> dict:
        """
        Compute all evaluation metrics.

        Parameters
        ----------
        y_true : array of {0, 1}
        y_scores : array of floats in [0, 1] (anomaly scores)
        threshold : decision boundary
        model_name : label for logging
        """
        y_pred = (y_scores >= threshold).astype(int)

        try:
            acc = accuracy_score(y_true, y_pred)
            prec = precision_score(y_true, y_pred, zero_division=0)
            rec = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)
        except Exception:
            acc = prec = rec = f1 = 0.0

        try:
            auc = roc_auc_score(y_true, y_scores)
        except Exception:
            auc = 0.0

        try:
            cm = confusion_matrix(y_true, y_pred).tolist()
        except Exception:
            cm = [[0, 0], [0, 0]]

        result = {
            "model": model_name,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "confusion_matrix": cm,
            "threshold": threshold,
            "total_samples": len(y_true),
            "positive_samples": int(y_true.sum()),
            "negative_samples": int(len(y_true) - y_true.sum()),
        }

        self.results_history.append(result)

        logger.info(
            "%s evaluation — Acc: %.3f | P: %.3f | R: %.3f | "
            "F1: %.3f | AUC: %.3f",
            model_name, acc, prec, rec, f1, auc,
        )

        return result

    def get_latest_results(self) -> list[dict]:
        return self.results_history[-5:]

    def meets_benchmarks(self, result: dict) -> dict:
        """Check if results meet the paper's benchmarks."""
        return {
            "f1_target_95.1": result["f1_score"] >= 0.951,
            "auc_target_0.96": result["roc_auc"] >= 0.96,
            "recall_target_96.8": result["recall"] >= 0.968,
        }
