"""
False Data Injection (FDI) Detector — LSTM-based trajectory analysis.

Detects FDI attacks where a vehicle with valid credentials sends
manipulated data (position, speed, heading).  The LSTM learns normal
vehicle movement patterns and flags deviations beyond the configured
threshold.

Target metric: Detection rate ≥ 96.8 % (per reference paper).
"""

import time
import math
import logging
import numpy as np
from collections import defaultdict

from ids.config import (
    FDI_POSITION_ERROR_THRESHOLD,
    FDI_SPEED_ERROR_THRESHOLD,
    LSTM_WINDOW_SIZE,
)

logger = logging.getLogger(__name__)


class FDIDetector:
    """
    False Data Injection detector using physics-based trajectory
    prediction combined with (optional) LSTM-learned patterns.

    The detector maintains per-vehicle trajectory state and flags
    messages whose reported kinematics are physically implausible.
    When a trained LSTM model is available, it augments the
    physics-based checks with learned predictions.
    """

    def __init__(self, lstm_model=None):
        """
        Parameters
        ----------
        lstm_model : object, optional
            A trained LSTMModel instance.  If None, only physics-based
            detection is used.
        """
        self._lstm_model = lstm_model

        # Per-vehicle state for physics-based prediction
        self._trajectories: dict[str, list[dict]] = defaultdict(list)
        self._max_trajectory = 50

        # Track FDI scores over time for each vehicle
        self._fdi_scores: dict[str, list[float]] = defaultdict(list)

    # ── Public API ───────────────────────────────────────────────────────────

    def detect(self, processed_msg: dict) -> list[dict]:
        """
        Analyse a preprocessed BSM for false data injection.

        Returns a list of alert dicts (may be empty).
        """
        alerts = []
        vid = processed_msg["vehicle_id"]
        raw = processed_msg["raw_data"]

        # Update trajectory history
        state = {
            "lat": raw.get("latitude", 0.0),
            "lon": raw.get("longitude", 0.0),
            "speed": raw.get("speed", 0.0),
            "heading": raw.get("heading", 0.0),
            "acceleration": raw.get("acceleration", 0.0),
            "timestamp": processed_msg["timestamp"],
        }
        self._trajectories[vid].append(state)
        if len(self._trajectories[vid]) > self._max_trajectory:
            self._trajectories[vid].pop(0)

        # Need at least 2 points for prediction
        trajectory = self._trajectories[vid]
        if len(trajectory) < 2:
            return alerts

        # 1. Physics-based prediction check
        physics_alert = self._physics_check(vid, trajectory)
        if physics_alert:
            alerts.append(physics_alert)

        # 2. LSTM-based prediction (if model available)
        if self._lstm_model is not None:
            lstm_alert = self._lstm_check(vid, processed_msg)
            if lstm_alert:
                alerts.append(lstm_alert)

        return alerts

    def set_lstm_model(self, model):
        """Inject a trained LSTM model at runtime."""
        self._lstm_model = model
        logger.info("FDI detector LSTM model updated")

    def get_trajectory_summary(self, vehicle_id: str) -> dict:
        """Return trajectory state for dashboard visualization."""
        traj = self._trajectories.get(vehicle_id, [])
        return {
            "vehicle_id": vehicle_id,
            "points": len(traj),
            "fdi_scores": self._fdi_scores.get(vehicle_id, [])[-20:],
        }

    # ── Physics-based Detection ──────────────────────────────────────────────

    def _physics_check(self, vid: str, trajectory: list[dict]) -> dict | None:
        """
        Predict the next position based on the previous state and
        compare against the reported position.
        """
        prev = trajectory[-2]
        curr = trajectory[-1]
        dt = max(curr["timestamp"] - prev["timestamp"], 0.001)

        # Predicted position from prev velocity and heading
        speed_ms = prev["speed"] / 3.6  # km/h → m/s
        heading_rad = math.radians(prev["heading"])
        dx = speed_ms * dt * math.sin(heading_rad)
        dy = speed_ms * dt * math.cos(heading_rad)

        pred_lat = prev["lat"] + (dy / 111_320.0)
        pred_lon = prev["lon"] + (dx / (111_320.0 * math.cos(math.radians(prev["lat"]))))

        # Actual vs predicted distance
        pos_error = self._haversine(pred_lat, pred_lon, curr["lat"], curr["lon"])

        # Speed consistency check
        actual_dist = self._haversine(prev["lat"], prev["lon"], curr["lat"], curr["lon"])
        inferred_speed = (actual_dist / dt) * 3.6
        speed_error = abs(curr["speed"] - inferred_speed)

        # Track scores
        fdi_score = min(1.0, (pos_error / FDI_POSITION_ERROR_THRESHOLD +
                              speed_error / FDI_SPEED_ERROR_THRESHOLD) / 2.0)
        self._fdi_scores[vid].append(fdi_score)
        if len(self._fdi_scores[vid]) > 100:
            self._fdi_scores[vid].pop(0)

        # Alert if both position and speed are suspicious
        if (pos_error > FDI_POSITION_ERROR_THRESHOLD or
                speed_error > FDI_SPEED_ERROR_THRESHOLD):

            severity = "critical" if fdi_score > 0.8 else "high"
            return {
                "detector": "fdi",
                "attack_type": "false_data_injection",
                "severity": severity,
                "vehicle_id": vid,
                "description": (
                    f"FDI detected: position error={pos_error:.1f}m "
                    f"(threshold={FDI_POSITION_ERROR_THRESHOLD}m), "
                    f"speed error={speed_error:.1f}km/h "
                    f"(threshold={FDI_SPEED_ERROR_THRESHOLD}km/h)"
                ),
                "confidence": round(fdi_score, 3),
                "position_error_m": round(pos_error, 2),
                "speed_error_kmh": round(speed_error, 2),
                "timestamp": time.time(),
            }

        return None

    # ── LSTM-based Detection ─────────────────────────────────────────────────

    def _lstm_check(self, vid: str, processed_msg: dict) -> dict | None:
        """Use the trained LSTM to predict next state and flag deviations."""
        try:
            trajectory = self._trajectories[vid]
            if len(trajectory) < LSTM_WINDOW_SIZE:
                return None

            # Build input sequence from trajectory
            recent = trajectory[-LSTM_WINDOW_SIZE:]
            sequence = np.array([
                [s["lat"], s["lon"], s["speed"], s["heading"], s["acceleration"]]
                for s in recent
            ], dtype=np.float32)

            # Reshape for LSTM: (1, window_size, features)
            X = sequence.reshape(1, LSTM_WINDOW_SIZE, 5)

            # Predict anomaly score
            score = self._lstm_model.predict_anomaly_score(X)

            if score > 0.65:
                return {
                    "detector": "fdi_lstm",
                    "attack_type": "false_data_injection",
                    "severity": "high" if score > 0.8 else "medium",
                    "vehicle_id": vid,
                    "description": (
                        f"LSTM-based FDI detection: anomaly score={score:.3f} "
                        f"exceeds threshold (0.65)"
                    ),
                    "confidence": round(score, 3),
                    "timestamp": time.time(),
                }
        except Exception as exc:
            logger.debug("LSTM FDI check failed for %s: %s", vid, exc)

        return None

    @staticmethod
    def _haversine(lat1, lon1, lat2, lon2):
        R = 6_371_000
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = (math.sin(dphi / 2) ** 2 +
             math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2)
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
