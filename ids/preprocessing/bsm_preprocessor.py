"""
BSM Preprocessor — Cleaning, normalization, and 15-feature extraction.

Extracts the same 15 features used during Colab training so the loaded
Keras models receive correctly-shaped, correctly-scaled input:

  [0]  pos_x              longitude (degrees)
  [1]  pos_y              latitude  (degrees)
  [2]  spd                reported speed (m/s)
  [3]  hed                reported heading (radians)
  [4]  acl                reported acceleration (m/s²)
  [5]  inter_msg_gap      seconds since previous message from this vehicle
  [6]  pos_noise_mag      kinematic position error magnitude (m)  ← best proxy
  [7]  spd_noise          |position-implied speed − reported speed| (m/s)
  [8]  hed_noise          angular error between movement direction and heading (rad)
  [9]  acl_noise          |speed-delta acceleration − reported acl| (m/s²)
  [10] kinematic_error    same as pos_noise_mag (duplicate for model compatibility)
  [11] speed_consistency  same as spd_noise
  [12] heading_consistency same as hed_noise
  [13] accel_consistency  same as acl_noise
  [14] spatial_density    distinct vehicles per 100 m grid cell per 1-s bin
"""

import time
import math
import logging
import numpy as np
from collections import defaultdict

logger = logging.getLogger(__name__)

_TWO_PI = 2.0 * math.pi
_DEG_PER_METER_LAT = 1.0 / 111_320.0   # degrees latitude per metre
_GRID_SIZE_M = 100.0                     # spatial density grid resolution
_DENSITY_BIN_S = 1.0                     # time bin size (seconds)


class BSMPreprocessor:
    """Cleans, normalises, and extracts 15 features from raw V2X messages."""

    VALID_RANGES = {
        "speed":        (0.0, 80.0),        # m/s  (~288 km/h max)
        "heading":      (-math.pi, math.pi), # radians
        "acceleration": (-15.0, 15.0),       # m/s²
    }

    def __init__(self):
        self._scaler = None

        # Welford online stats — fallback when scaler not loaded yet
        self._means = np.zeros(15, dtype=np.float32)
        self._vars  = np.ones(15,  dtype=np.float32)
        self._count = 0

        # Per-vehicle message history (for temporal features)
        self._vehicle_history: dict[str, list[dict]] = defaultdict(list)
        self._max_history = 50

        # Global position registry for spatial density:
        # {(time_bin, grid_x, grid_y): set of sender_ids}
        self._spatial_registry: dict[tuple, set] = defaultdict(set)
        self._registry_bins: list[int] = []   # sorted list of active bins
        self._max_registry_bins = 30          # keep last 30 seconds of bins

    # ── Public API ───────────────────────────────────────────────────────────

    def preprocess(self, raw_msg: dict) -> dict | None:
        parsed = self._parse_message(raw_msg)
        if parsed is None:
            return None

        cleaned = self._clamp_fields(parsed)
        vid = cleaned["vehicle_id"]

        self._vehicle_history[vid].append(cleaned)
        if len(self._vehicle_history[vid]) > self._max_history:
            self._vehicle_history[vid].pop(0)

        self._register_position(vid, cleaned)

        features = self._extract_features(cleaned, vid)
        features = self._normalize(features)
        self._vehicle_history[vid][-1]["_normalized_features"] = features

        return {
            "vehicle_id":   vid,
            "timestamp":    cleaned["timestamp"],
            "features":     features,
            "raw_data":     cleaned,
            "attack_surface": self._attack_surface_hints(cleaned, vid),
        }

    def set_scaler(self, scaler) -> None:
        self._scaler = scaler

    def preprocess_batch(self, messages: list[dict]) -> list[dict]:
        return [r for m in messages for r in [self.preprocess(m)] if r is not None]

    def get_vehicle_sequence(self, vehicle_id: str, window: int = 20) -> np.ndarray | None:
        history = self._vehicle_history.get(vehicle_id, [])
        if len(history) < window:
            return None
        vectors = [
            e["_normalized_features"]
            for e in history[-window:]
            if "_normalized_features" in e
        ]
        if len(vectors) < window:
            return None
        return np.array(vectors, dtype=np.float32)  # (window, 15)

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _parse_message(self, raw: dict) -> dict | None:
        try:
            payload = raw["data"] if ("data" in raw and isinstance(raw["data"], dict)) else raw

            position = payload.get("position", [0.0, 0.0])
            if isinstance(position, list) and len(position) >= 2:
                lat, lon = float(position[0]), float(position[1])
            else:
                lat, lon = 0.0, 0.0

            # Accept speed in m/s; if clearly in km/h (>80) convert down
            spd_raw = float(payload.get("speed", 0.0))
            if spd_raw > 80.0:
                spd_raw = spd_raw / 3.6

            # Heading: accept degrees or radians.
            # Values > 2π suggest degrees → convert.
            hed_raw = float(payload.get("heading", 0.0))
            if abs(hed_raw) > _TWO_PI:
                hed_raw = math.radians(hed_raw)

            return {
                "vehicle_id":   str(payload.get("vehicle_id", raw.get("vehicle_id", "unknown"))),
                "message_type": payload.get("message_type", "UNKNOWN"),
                "timestamp":    float(payload.get("timestamp", time.time())),
                "latitude":     lat,
                "longitude":    lon,
                "speed":        spd_raw,
                "heading":      hed_raw,
                "acceleration": float(payload.get("acceleration", 0.0)),
                "signature":    raw.get("signature", ""),
            }
        except (ValueError, TypeError, KeyError) as exc:
            logger.warning("Failed to parse BSM: %s", exc)
            return None

    def _clamp_fields(self, parsed: dict) -> dict:
        for field, (lo, hi) in self.VALID_RANGES.items():
            if field in parsed:
                parsed[field] = max(lo, min(hi, parsed[field]))
        return parsed

    def _extract_features(self, cleaned: dict, vehicle_id: str) -> np.ndarray:
        """
        Build a 15-dimensional feature vector matching the Colab training order.
        Features 6-9 (noise proxies) and 10-13 (kinematic consistency) are
        computed from trajectory physics — the best available approximation of
        the VeReMi ground-truth noise labels.
        """
        history = self._vehicle_history.get(vehicle_id, [])
        prev    = history[-2] if len(history) >= 2 else None

        lon = cleaned["longitude"]
        lat = cleaned["latitude"]
        spd = cleaned["speed"]        # m/s
        hed = cleaned["heading"]      # radians
        acl = cleaned["acceleration"] # m/s²

        if prev is not None:
            dt = max(cleaned["timestamp"] - prev["timestamp"], 0.05)

            # Displacement in metres (flat-earth approximation)
            cos_lat = math.cos(math.radians((lat + prev["latitude"]) / 2.0))
            dx_m = (lon - prev["longitude"]) * 111_320.0 * cos_lat
            dy_m = (lat - prev["latitude"])  * 111_320.0
            dist_m = math.sqrt(dx_m * dx_m + dy_m * dy_m)

            # Kinematic prediction from previous state
            prev_spd = prev["speed"]
            prev_hed = prev["heading"]
            exp_dx = prev_spd * math.cos(prev_hed) * dt
            exp_dy = prev_spd * math.sin(prev_hed) * dt
            kinematic_err = math.sqrt((dx_m - exp_dx) ** 2 + (dy_m - exp_dy) ** 2)

            # Speed implied by position change vs reported speed
            pos_spd = dist_m / dt
            spd_err = abs(pos_spd - spd)

            # Heading implied by movement vs reported heading
            if dist_m > 0.1:
                move_hed  = math.atan2(dy_m, dx_m)
                raw_diff  = abs(move_hed - hed) % _TWO_PI
                hed_err   = min(raw_diff, _TWO_PI - raw_diff)
            else:
                hed_err = 0.0

            # Acceleration from speed change vs reported acl
            acl_err = abs((spd - prev_spd) / dt - acl)

            inter_msg_gap = dt

        else:
            kinematic_err  = 0.0
            spd_err        = 0.0
            hed_err        = 0.0
            acl_err        = 0.0
            inter_msg_gap  = 0.0

        spatial_density = self._spatial_density(lat, lon, cleaned["timestamp"])

        return np.array([
            # ── Original 10 BSM fields (notebook columns 0-9) ──────────────
            lon,            # pos_x
            lat,            # pos_y
            spd,            # spd
            hed,            # hed
            acl,            # acl
            inter_msg_gap,  # inter_msg_gap
            kinematic_err,  # pos_noise_mag  (ground-truth proxy)
            spd_err,        # spd_noise      (ground-truth proxy)
            hed_err,        # hed_noise      (ground-truth proxy)
            acl_err,        # acl_noise      (ground-truth proxy)
            # ── 5 engineered kinematic/spatial features (columns 10-14) ────
            kinematic_err,  # kinematic_error
            spd_err,        # speed_consistency
            hed_err,        # heading_consistency
            acl_err,        # accel_consistency
            spatial_density,# spatial_density
        ], dtype=np.float32)

    def _register_position(self, vehicle_id: str, cleaned: dict) -> None:
        t_bin = int(cleaned["timestamp"] / _DENSITY_BIN_S)
        gx    = int(cleaned["longitude"] * 111_320.0 / _GRID_SIZE_M)
        gy    = int(cleaned["latitude"]  * 111_320.0 / _GRID_SIZE_M)
        key   = (t_bin, gx, gy)
        self._spatial_registry[key].add(vehicle_id)

        if t_bin not in self._registry_bins:
            self._registry_bins.append(t_bin)
            self._registry_bins.sort()
            # Evict old bins
            cutoff = t_bin - self._max_registry_bins
            old = [b for b in self._registry_bins if b < cutoff]
            for b in old:
                self._registry_bins.remove(b)
                for k in [k for k in self._spatial_registry if k[0] == b]:
                    del self._spatial_registry[k]

    def _spatial_density(self, lat: float, lon: float, ts: float) -> float:
        t_bin = int(ts / _DENSITY_BIN_S)
        gx    = int(lon * 111_320.0 / _GRID_SIZE_M)
        gy    = int(lat * 111_320.0 / _GRID_SIZE_M)
        return float(len(self._spatial_registry.get((t_bin, gx, gy), set())))

    def _normalize(self, features: np.ndarray) -> np.ndarray:
        if self._scaler is not None:
            try:
                return self._scaler.transform(features.reshape(1, -1))[0].astype(np.float32)
            except Exception as exc:
                logger.warning("Scaler transform failed: %s — using Welford fallback", exc)

        # Welford online z-score (active before scaler is loaded)
        self._count += 1
        delta        = features - self._means
        self._means += delta / self._count
        delta2       = features - self._means
        self._vars  += (delta * delta2 - self._vars) / self._count
        std          = np.sqrt(np.maximum(self._vars, 1e-8))
        return ((features - self._means) / std).astype(np.float32)

    def _attack_surface_hints(self, cleaned: dict, vid: str) -> dict:
        hints   = {}
        history = self._vehicle_history.get(vid, [])

        if len(history) >= 2 and cleaned["signature"] == history[-2].get("signature", ""):
            hints["possible_replay"] = True

        now    = cleaned["timestamp"]
        recent = [m for m in history if now - m["timestamp"] <= 1.0]
        if len(recent) > 10:
            hints["possible_dos"] = True

        return hints
