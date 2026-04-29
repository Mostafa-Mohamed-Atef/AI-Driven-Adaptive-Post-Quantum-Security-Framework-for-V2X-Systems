"""
Sybil Attack Detector — K-Means clustering on spatial-temporal features.

Combines the PKI identity verification already present in the SCMS with
behavioural analysis: even when each certificate is individually valid,
coordinated movement of multiple identities from the same physical source
is flagged as a Sybil attack.

Target metric: F1 ≥ 95.1 % (per reference paper).
"""

import time
import logging
import numpy as np
from collections import defaultdict

from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from ids.config import (
    SYBIL_MIN_CLUSTER_SIZE,
    SYBIL_MAX_SPATIAL_DEVIATION,
    SYBIL_COORDINATION_THRESHOLD,
    KMEANS_N_CLUSTERS,
    KMEANS_MAX_ITER,
)

logger = logging.getLogger(__name__)


class SybilDetector:
    """Detect Sybil attacks using K-Means clustering on BSM features."""

    def __init__(self):
        # Sliding window of recent BSMs for clustering
        self._window: list[dict] = []
        self._window_duration = 10.0  # seconds to keep
        self._min_samples_for_clustering = 10

        self._scaler = StandardScaler()
        self._scaler_fitted = False

        # Track flagged vehicle groups (debounce)
        self._flagged_groups: dict[str, float] = {}  # group_key → timestamp
        self._flag_cooldown = 30.0  # seconds

    # ── Public API ───────────────────────────────────────────────────────────

    def detect(self, processed_msg: dict) -> list[dict]:
        """
        Ingest a new preprocessed BSM and run clustering if enough
        samples are available.

        Returns list of alerts (may be empty).
        """
        alerts = []

        # Add to sliding window
        self._window.append({
            "vehicle_id": processed_msg["vehicle_id"],
            "timestamp": processed_msg["timestamp"],
            "features": processed_msg["features"],
            "raw_data": processed_msg["raw_data"],
        })

        # Prune old entries
        now = time.time()
        self._window = [
            w for w in self._window
            if now - w["timestamp"] <= self._window_duration
        ]

        # Need enough distinct vehicles for meaningful clustering
        if len(self._window) < self._min_samples_for_clustering:
            return alerts

        # Run clustering periodically (every new message)
        alerts = self._run_clustering()
        return alerts

    # ── Clustering Logic ─────────────────────────────────────────────────────

    def _run_clustering(self) -> list[dict]:
        alerts = []

        # Build feature matrix  [lat, lon, speed, heading, timestamp_offset]
        feature_matrix = []
        vehicle_ids = []
        base_time = self._window[0]["timestamp"]

        for entry in self._window:
            raw = entry["raw_data"]
            feature_matrix.append([
                raw.get("latitude", 0.0),
                raw.get("longitude", 0.0),
                raw.get("speed", 0.0),
                raw.get("heading", 0.0),
                entry["timestamp"] - base_time,
            ])
            vehicle_ids.append(entry["vehicle_id"])

        X = np.array(feature_matrix, dtype=np.float32)

        # Scale features
        if not self._scaler_fitted and len(X) >= 5:
            self._scaler.fit(X)
            self._scaler_fitted = True

        if self._scaler_fitted:
            X = self._scaler.transform(X)

        # Adaptive K: don't request more clusters than samples
        n_clusters = min(KMEANS_N_CLUSTERS, len(X))
        if n_clusters < 2:
            return alerts

        try:
            kmeans = KMeans(
                n_clusters=n_clusters,
                max_iter=KMEANS_MAX_ITER,
                n_init=3,
                random_state=42,
            )
            labels = kmeans.fit_predict(X)
        except Exception as exc:
            logger.warning("K-Means failed: %s", exc)
            return alerts

        # Analyse each cluster for Sybil signatures
        cluster_map: dict[int, list[int]] = defaultdict(list)
        for idx, label in enumerate(labels):
            cluster_map[label].append(idx)

        for cluster_id, indices in cluster_map.items():
            # Count distinct vehicle IDs in this cluster
            vids_in_cluster = set(vehicle_ids[i] for i in indices)
            if len(vids_in_cluster) < SYBIL_MIN_CLUSTER_SIZE:
                continue

            # Check spatial compactness → suspiciously close positions
            cluster_features = X[indices]
            spatial_std = np.std(cluster_features[:, :2], axis=0).mean()

            # Check coordination score (similar speed + heading)
            speed_std = np.std(cluster_features[:, 2])
            heading_std = np.std(cluster_features[:, 3])
            coordination = 1.0 - min(1.0, (speed_std + heading_std) / 2.0)

            if (spatial_std < SYBIL_MAX_SPATIAL_DEVIATION and
                    coordination > SYBIL_COORDINATION_THRESHOLD):

                group_key = "_".join(sorted(vids_in_cluster))
                now = time.time()

                # Debounce: don't re-flag the same group within cooldown
                if group_key in self._flagged_groups:
                    if now - self._flagged_groups[group_key] < self._flag_cooldown:
                        continue

                self._flagged_groups[group_key] = now

                confidence = min(1.0, coordination * (len(vids_in_cluster) / 5.0))

                alert = {
                    "detector": "sybil",
                    "attack_type": "sybil",
                    "severity": "critical" if confidence > 0.85 else "high",
                    "vehicle_id": ", ".join(sorted(vids_in_cluster)),
                    "description": (
                        f"Sybil attack: {len(vids_in_cluster)} identities in cluster "
                        f"{cluster_id} showing coordinated behaviour "
                        f"(coordination={coordination:.2f}, "
                        f"spatial_std={spatial_std:.2f})"
                    ),
                    "confidence": round(confidence, 3),
                    "involved_vehicles": sorted(vids_in_cluster),
                    "timestamp": now,
                }
                alerts.append(alert)
                logger.warning(
                    "SYBIL DETECTED: %d vehicles — %s",
                    len(vids_in_cluster),
                    sorted(vids_in_cluster),
                )

        return alerts

    def get_cluster_summary(self) -> dict:
        """Return current clustering state for dashboard visualization."""
        return {
            "window_size": len(self._window),
            "flagged_groups": len(self._flagged_groups),
            "active_vehicles": len(
                set(w["vehicle_id"] for w in self._window)
            ),
        }
