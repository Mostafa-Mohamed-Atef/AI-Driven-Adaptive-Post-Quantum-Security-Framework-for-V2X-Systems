"""
Hybrid Anomaly Detector — Orchestrates CNN (spatial) and LSTM (temporal)
deep-learning models for AI-based anomaly detection.

Adaptive behaviour:
  1. Threshold drift   — the detection threshold self-adjusts based on the
                         observed alert rate over a sliding window of 100
                         messages, keeping false-positive rate near 5 %.
  2. MA fine-tuning    — when the Misbehavior Authority confirms or rejects an
                         alert, the feature vector is stored here and the
                         trainer fine-tunes the model on that confirmed label.
"""

import time
import logging
import numpy as np

from ids.config import ANOMALY_THRESHOLD, LSTM_WINDOW_SIZE

logger = logging.getLogger(__name__)

# Adaptive threshold bounds — never drift outside these limits
_THRESH_MIN = 0.20
_THRESH_MAX = 0.85
_TARGET_ALERT_RATE   = 0.05   # aim for ~5 % of messages to trigger an alert
_THRESH_STEP         = 0.002  # how much to nudge the threshold each adjustment
_ADAPT_WINDOW        = 100    # number of recent decisions used to estimate rate
_ADAPT_MIN_SAMPLES   = 20     # don't adjust until we have this many samples


class AnomalyDetector:
    """
    Ensemble anomaly detector combining CNN and LSTM predictions.

    The CNN analyses individual BSM feature vectors for spatial anomalies.
    The LSTM analyses sequences for temporal anomalies.
    The ensemble combines both scores with configurable weights.

    The detection threshold adapts automatically to operating conditions
    and can be nudged via MA feedback (fine-tuning loop).
    """

    def __init__(self, cnn_model=None, lstm_model=None):
        self._cnn_model  = cnn_model
        self._lstm_model = lstm_model

        # Ensemble weights
        self._cnn_weight  = 0.4
        self._lstm_weight = 0.6

        # Per-vehicle score history for trend analysis
        self._recent_scores: dict[str, list[float]] = {}
        self._max_scores = 50

        # ── Adaptive threshold ────────────────────────────────────────────
        self._adaptive_threshold = float(ANOMALY_THRESHOLD)
        self._alert_window: list[int] = []   # 1=alerted, 0=not alerted
        self._threshold_history: list[tuple[float, float]] = []  # (ts, thresh)

        # ── Feature cache for MA feedback ─────────────────────────────────
        # Stores the most recent feature vector per vehicle so the fine-tune
        # endpoint can retrieve it after the MA confirms/rejects an alert.
        self._last_features: dict[str, np.ndarray] = {}

    # ── Public API ───────────────────────────────────────────────────────────

    def detect(self, processed_msg: dict,
               vehicle_sequence: np.ndarray = None) -> list[dict]:
        alerts = []
        vid      = processed_msg["vehicle_id"]
        features = processed_msg["features"]

        self._last_features[vid] = features

        cnn_score  = 0.0
        lstm_score = 0.0

        if self._cnn_model is not None:
            try:
                cnn_score = self._cnn_predict(features)
            except Exception as exc:
                logger.debug("CNN prediction failed: %s", exc)

        if self._lstm_model is not None and vehicle_sequence is not None:
            try:
                lstm_score = self._lstm_predict(vehicle_sequence)
            except Exception as exc:
                logger.debug("LSTM prediction failed: %s", exc)

        if self._cnn_model and self._lstm_model and vehicle_sequence is not None:
            combined = self._cnn_weight * cnn_score + self._lstm_weight * lstm_score
        elif self._cnn_model:
            combined = cnn_score
        elif self._lstm_model and vehicle_sequence is not None:
            combined = lstm_score
        else:
            return alerts

        # Track per-vehicle scores
        if vid not in self._recent_scores:
            self._recent_scores[vid] = []
        self._recent_scores[vid].append(combined)
        if len(self._recent_scores[vid]) > self._max_scores:
            self._recent_scores[vid].pop(0)

        threshold = self._adaptive_threshold
        alerted   = combined > threshold
        self._update_adaptive_threshold(alerted)

        if alerted:
            recent    = self._recent_scores[vid][-10:]
            sustained = sum(1 for s in recent if s > threshold) > 3
            severity  = "critical" if sustained else ("high" if combined >= 0.7 else "medium")

            alerts.append({
                "detector":   "anomaly_ai",
                "attack_type": "anomaly",
                "severity":   severity,
                "vehicle_id": vid,
                "description": (
                    f"AI anomaly: ensemble={combined:.3f} "
                    f"(CNN={cnn_score:.3f}, LSTM={lstm_score:.3f}, "
                    f"adaptive_threshold={threshold:.3f})"
                ),
                "confidence":          round(combined, 3),
                "cnn_score":           round(cnn_score, 3),
                "lstm_score":          round(lstm_score, 3),
                "sustained":           sustained,
                "adaptive_threshold":  round(threshold, 4),
                "timestamp":           time.time(),
            })

        return alerts

    def set_models(self, cnn_model=None, lstm_model=None):
        if cnn_model:
            self._cnn_model = cnn_model
            logger.info("Anomaly detector CNN model updated")
        if lstm_model:
            self._lstm_model = lstm_model
            logger.info("Anomaly detector LSTM model updated")

    def get_score_history(self, vehicle_id: str) -> list[float]:
        return self._recent_scores.get(vehicle_id, [])

    def get_last_features(self, vehicle_id: str) -> np.ndarray | None:
        return self._last_features.get(vehicle_id)

    def get_adaptive_status(self) -> dict:
        rate = (sum(self._alert_window) / len(self._alert_window)
                if self._alert_window else 0.0)
        return {
            "adaptive_threshold":  round(self._adaptive_threshold, 4),
            "base_threshold":      ANOMALY_THRESHOLD,
            "current_alert_rate":  round(rate, 4),
            "target_alert_rate":   _TARGET_ALERT_RATE,
            "window_size":         len(self._alert_window),
        }

    # ── Adaptive threshold ────────────────────────────────────────────────────

    def _update_adaptive_threshold(self, alerted: bool) -> None:
        self._alert_window.append(1 if alerted else 0)
        if len(self._alert_window) > _ADAPT_WINDOW:
            self._alert_window.pop(0)

        if len(self._alert_window) < _ADAPT_MIN_SAMPLES:
            return

        rate = sum(self._alert_window) / len(self._alert_window)

        if rate > _TARGET_ALERT_RATE * 2:
            # Too many alerts → raise threshold (reduce false positives)
            self._adaptive_threshold = min(
                _THRESH_MAX,
                self._adaptive_threshold + _THRESH_STEP,
            )
        elif rate < _TARGET_ALERT_RATE * 0.5:
            # Too few alerts → lower threshold (increase sensitivity)
            self._adaptive_threshold = max(
                _THRESH_MIN,
                self._adaptive_threshold - _THRESH_STEP,
            )

        self._threshold_history.append((time.time(), self._adaptive_threshold))
        if len(self._threshold_history) > 500:
            self._threshold_history.pop(0)

    # ── Model interfaces ──────────────────────────────────────────────────────

    def _cnn_predict(self, features: np.ndarray) -> float:
        X     = features.reshape(1, -1, 1)
        score = self._cnn_model.predict_anomaly_score(X)
        return float(np.clip(score, 0.0, 1.0))

    def _lstm_predict(self, sequence: np.ndarray) -> float:
        X     = sequence.reshape(1, sequence.shape[0], sequence.shape[1])
        score = self._lstm_model.predict_anomaly_score(X)
        return float(np.clip(score, 0.0, 1.0))
