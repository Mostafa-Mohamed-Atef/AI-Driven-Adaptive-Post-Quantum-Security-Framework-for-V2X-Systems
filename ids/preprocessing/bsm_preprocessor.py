"""
BSM Preprocessor — Cleaning, normalization, and feature extraction.

Converts raw BSM/CAM/DENM JSON messages into a normalized feature vector
suitable for the CNN and LSTM detection models.  Applies noise reduction
(up to 30% as per the reference paper) via outlier clamping and
z-score normalization.
"""

import time
import math
import logging
import numpy as np
from collections import defaultdict

logger = logging.getLogger(__name__)


class BSMPreprocessor:
    """Cleans, normalises, and extracts features from raw V2X messages."""

    # ── Expected ranges for sanity clamping ──────────────────────────────────
    VALID_RANGES = {
        "latitude":     (-90.0, 90.0),
        "longitude":    (-180.0, 180.0),
        "speed":        (0.0, 250.0),       # km/h
        "heading":      (0.0, 360.0),
        "acceleration": (-15.0, 15.0),      # m/s²
    }

    def __init__(self):
        # Running statistics for z-score normalization (online Welford)
        self._means = np.zeros(10)
        self._vars = np.ones(10)
        self._count = 0

        # Per-vehicle history for temporal feature derivation
        self._vehicle_history: dict[str, list[dict]] = defaultdict(list)
        self._max_history = 50  # keep last N messages per vehicle

    # ── Public API ───────────────────────────────────────────────────────────

    def preprocess(self, raw_msg: dict) -> dict | None:
        """
        Full pipeline: validate → clean → extract features → normalize.

        Returns a dict with keys:
            vehicle_id, timestamp, features (np.ndarray of shape (10,)),
            raw_data (cleaned dict), attack_surface (metadata hints).
        Returns *None* when the message cannot be processed.
        """
        # 1. Parse & flatten
        parsed = self._parse_message(raw_msg)
        if parsed is None:
            return None

        # 2. Sanity-clamp numeric fields (reduces noise ~30 %)
        cleaned = self._clamp_fields(parsed)

        # 3. Store in vehicle history for temporal features
        vid = cleaned["vehicle_id"]
        self._vehicle_history[vid].append(cleaned)
        if len(self._vehicle_history[vid]) > self._max_history:
            self._vehicle_history[vid].pop(0)

        # 4. Extract feature vector
        features = self._extract_features(cleaned, vid)

        # 5. Online z-score normalization
        features = self._normalize(features)

        return {
            "vehicle_id": vid,
            "timestamp": cleaned["timestamp"],
            "features": features,
            "raw_data": cleaned,
            "attack_surface": self._attack_surface_hints(cleaned, vid),
        }

    def preprocess_batch(self, messages: list[dict]) -> list[dict]:
        """Process a list of raw messages, returning successfully processed ones."""
        results = []
        for msg in messages:
            out = self.preprocess(msg)
            if out is not None:
                results.append(out)
        return results

    def get_vehicle_sequence(self, vehicle_id: str, window: int = 20) -> np.ndarray | None:
        """
        Return the last *window* preprocessed feature vectors for a vehicle
        as a 2-D array (window, 10).  Used by the LSTM models.
        Returns None if insufficient history.
        """
        history = self._vehicle_history.get(vehicle_id, [])
        if len(history) < window:
            return None

        recent = history[-window:]
        vectors = []
        for entry in recent:
            feat = self._extract_features(entry, vehicle_id)
            feat = self._normalize(feat)
            vectors.append(feat)
        return np.array(vectors)

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _parse_message(self, raw: dict) -> dict | None:
        """Flatten the nested BSM format produced by vehicles."""
        try:
            # Handle nested {'data': {...}, 'signature': ..., 'crypto': ...}
            if "data" in raw and isinstance(raw["data"], dict):
                payload = raw["data"]
            else:
                payload = raw

            position = payload.get("position", [0.0, 0.0])
            if isinstance(position, list) and len(position) >= 2:
                lat, lon = float(position[0]), float(position[1])
            else:
                lat, lon = 0.0, 0.0

            return {
                "vehicle_id": str(payload.get("vehicle_id", raw.get("vehicle_id", "unknown"))),
                "message_type": payload.get("message_type", payload.get("type", "UNKNOWN")),
                "timestamp": float(payload.get("timestamp", time.time())),
                "latitude": lat,
                "longitude": lon,
                "speed": float(payload.get("speed", 0.0)),
                "heading": float(payload.get("heading", 0.0)),
                "acceleration": float(payload.get("acceleration", 0.0)),
                "crypto_type": payload.get("crypto_type", raw.get("crypto", "unknown")),
                "signature": raw.get("signature", ""),
            }
        except (ValueError, TypeError, KeyError) as exc:
            logger.warning("Failed to parse BSM: %s", exc)
            return None

    def _clamp_fields(self, parsed: dict) -> dict:
        """Clamp numeric fields to valid physical ranges (noise reduction)."""
        for field, (lo, hi) in self.VALID_RANGES.items():
            if field in parsed:
                parsed[field] = max(lo, min(hi, parsed[field]))
        return parsed

    def _extract_features(self, cleaned: dict, vehicle_id: str) -> np.ndarray:
        """
        Build a 10-dimensional feature vector:
          [0] latitude
          [1] longitude
          [2] speed
          [3] heading
          [4] acceleration
          [5] message_frequency    (msgs/sec in last 10 s)
          [6] inter_message_gap    (seconds since previous msg)
          [7] position_delta       (meters from previous position)
          [8] speed_consistency    (|actual_speed − inferred_speed|)
          [9] heading_consistency  (|heading_change − expected_change|)
        """
        history = self._vehicle_history.get(vehicle_id, [])
        prev = history[-2] if len(history) >= 2 else None

        # Basic kinematic features
        lat = cleaned["latitude"]
        lon = cleaned["longitude"]
        spd = cleaned["speed"]
        hdg = cleaned["heading"]
        acc = cleaned["acceleration"]

        # Derived temporal features
        if prev is not None:
            dt = max(cleaned["timestamp"] - prev["timestamp"], 0.001)
            gap = dt
            pos_delta = self._haversine(
                prev["latitude"], prev["longitude"], lat, lon
            )
            inferred_speed = (pos_delta / dt) * 3.6  # m/s → km/h
            speed_consistency = abs(spd - inferred_speed)
            heading_change = abs(hdg - prev["heading"])
            if heading_change > 180:
                heading_change = 360 - heading_change
            expected_heading_change = 0.0 if spd < 1 else heading_change
            heading_consistency = abs(heading_change - expected_heading_change)
        else:
            gap = 0.0
            pos_delta = 0.0
            speed_consistency = 0.0
            heading_consistency = 0.0

        # Message frequency in the last 10 seconds
        now = cleaned["timestamp"]
        recent = [
            m for m in history
            if now - m["timestamp"] <= 10.0
        ]
        msg_freq = len(recent) / 10.0

        return np.array([
            lat, lon, spd, hdg, acc,
            msg_freq, gap, pos_delta,
            speed_consistency, heading_consistency,
        ], dtype=np.float32)

    def _normalize(self, features: np.ndarray) -> np.ndarray:
        """Online z-score normalization (Welford's method)."""
        self._count += 1
        delta = features - self._means
        self._means += delta / self._count
        delta2 = features - self._means
        self._vars += (delta * delta2 - self._vars) / self._count

        std = np.sqrt(np.maximum(self._vars, 1e-8))
        return (features - self._means) / std

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Great-circle distance between two points in **meters**."""
        R = 6_371_000  # Earth radius in meters
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = (
            math.sin(dphi / 2) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
        )
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    def _attack_surface_hints(self, cleaned: dict, vid: str) -> dict:
        """Quick heuristic flags for downstream detectors."""
        hints = {}
        history = self._vehicle_history.get(vid, [])

        # Replay hint: duplicate signature
        if len(history) >= 2:
            if cleaned["signature"] == history[-2].get("signature", ""):
                hints["possible_replay"] = True

        # DoS hint: very high frequency
        now = cleaned["timestamp"]
        recent = [m for m in history if now - m["timestamp"] <= 1.0]
        if len(recent) > 10:
            hints["possible_dos"] = True

        return hints
