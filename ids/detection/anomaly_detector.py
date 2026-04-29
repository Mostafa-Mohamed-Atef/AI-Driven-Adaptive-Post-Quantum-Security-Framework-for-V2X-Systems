"""
Hybrid Anomaly Detector — Orchestrates CNN (spatial) and LSTM (temporal)
deep-learning models for AI-based anomaly detection.

This is the second layer of the detection pipeline, processing messages
that passed the signature-based checks.  It combines the outputs of
both models via a weighted ensemble to produce a single anomaly score.
"""

import time
import logging
import numpy as np

from ids.config import ANOMALY_THRESHOLD, LSTM_WINDOW_SIZE

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Ensemble anomaly detector combining CNN and LSTM predictions.

    The CNN analyses individual BSM feature vectors for spatial anomalies,
    while the LSTM analyses sequences for temporal anomalies.
    """

    def __init__(self, cnn_model=None, lstm_model=None):
        self._cnn_model = cnn_model
        self._lstm_model = lstm_model

        # Ensemble weights (tunable)
        self._cnn_weight = 0.4
        self._lstm_weight = 0.6

        # Track recent scores for trend analysis
        self._recent_scores: dict[str, list[float]] = {}
        self._max_scores = 50

    # ── Public API ───────────────────────────────────────────────────────────

    def detect(self, processed_msg: dict,
               vehicle_sequence: np.ndarray = None) -> list[dict]:
        """
        Run the hybrid CNN + LSTM anomaly detection.

        Parameters
        ----------
        processed_msg : dict
            Output from BSMPreprocessor.preprocess().
        vehicle_sequence : np.ndarray, optional
            Shape (window_size, features) from preprocessor.get_vehicle_sequence().
            Required for LSTM component.

        Returns
        -------
        list[dict]  — alerts (may be empty)
        """
        alerts = []
        vid = processed_msg["vehicle_id"]
        features = processed_msg["features"]

        cnn_score = 0.0
        lstm_score = 0.0

        # CNN prediction (single BSM)
        if self._cnn_model is not None:
            try:
                cnn_score = self._cnn_predict(features)
            except Exception as exc:
                logger.debug("CNN prediction failed: %s", exc)

        # LSTM prediction (BSM sequence)
        if self._lstm_model is not None and vehicle_sequence is not None:
            try:
                lstm_score = self._lstm_predict(vehicle_sequence)
            except Exception as exc:
                logger.debug("LSTM prediction failed: %s", exc)

        # Weighted ensemble
        if self._cnn_model and self._lstm_model and vehicle_sequence is not None:
            combined_score = (
                self._cnn_weight * cnn_score +
                self._lstm_weight * lstm_score
            )
        elif self._cnn_model:
            combined_score = cnn_score
        elif self._lstm_model and vehicle_sequence is not None:
            combined_score = lstm_score
        else:
            # No models loaded — skip AI detection
            return alerts

        # Track score
        if vid not in self._recent_scores:
            self._recent_scores[vid] = []
        self._recent_scores[vid].append(combined_score)
        if len(self._recent_scores[vid]) > self._max_scores:
            self._recent_scores[vid].pop(0)

        # Alert if above threshold
        if combined_score > ANOMALY_THRESHOLD:
            # Check if this is a sustained anomaly or a spike
            recent = self._recent_scores[vid][-10:]
            sustained = sum(1 for s in recent if s > ANOMALY_THRESHOLD) > 3

            severity = "critical" if sustained else "high"
            if combined_score < 0.5:
                severity = "medium"

            alert = {
                "detector": "anomaly_ai",
                "attack_type": "anomaly",
                "severity": severity,
                "vehicle_id": vid,
                "description": (
                    f"AI anomaly detected: ensemble_score={combined_score:.3f} "
                    f"(CNN={cnn_score:.3f}, LSTM={lstm_score:.3f}, "
                    f"threshold={ANOMALY_THRESHOLD})"
                ),
                "confidence": round(combined_score, 3),
                "cnn_score": round(cnn_score, 3),
                "lstm_score": round(lstm_score, 3),
                "sustained": sustained,
                "timestamp": time.time(),
            }
            alerts.append(alert)

        return alerts

    def set_models(self, cnn_model=None, lstm_model=None):
        """Inject trained models at runtime."""
        if cnn_model:
            self._cnn_model = cnn_model
            logger.info("Anomaly detector CNN model updated")
        if lstm_model:
            self._lstm_model = lstm_model
            logger.info("Anomaly detector LSTM model updated")

    def get_score_history(self, vehicle_id: str) -> list[float]:
        """Return recent anomaly scores for a vehicle."""
        return self._recent_scores.get(vehicle_id, [])

    # ── Model Interfaces ─────────────────────────────────────────────────────

    def _cnn_predict(self, features: np.ndarray) -> float:
        """Get anomaly score from CNN model."""
        # Reshape: (features,) → (1, features, 1) for Conv1D
        X = features.reshape(1, -1, 1)
        score = self._cnn_model.predict_anomaly_score(X)
        return float(np.clip(score, 0.0, 1.0))

    def _lstm_predict(self, sequence: np.ndarray) -> float:
        """Get anomaly score from LSTM model."""
        # Reshape: (window, features) → (1, window, features)
        X = sequence.reshape(1, sequence.shape[0], sequence.shape[1])
        score = self._lstm_model.predict_anomaly_score(X)
        return float(np.clip(score, 0.0, 1.0))
