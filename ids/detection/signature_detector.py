"""
Signature-based Detector — CRL verification, replay detection, and
known-threat matching.

This is the first layer of the detection pipeline and catches all threats
that have a deterministic signature (revoked certificates, replayed
messages, blacklisted patterns).  It is intentionally fast (<1 ms) so
that the heavier AI layers only process messages that pass this gate.
"""

import time
import hashlib
import logging
import requests
from collections import defaultdict

from ids.config import (
    MA_URL,
    REPLAY_MAX_AGE,
    DOS_RATE_LIMIT,
)

logger = logging.getLogger(__name__)


class SignatureDetector:
    """Deterministic, rule-based detection layer."""

    def __init__(self):
        # Local CRL cache  {certificate_id: revocation_entry}
        self._crl_cache: dict[str, dict] = {}
        self._crl_last_refresh: float = 0
        self._crl_refresh_interval: float = 30.0  # seconds

        # Replay tracking  {message_hash: timestamp}
        self._seen_signatures: dict[str, float] = {}
        self._seen_max_size = 10_000

        # Rate tracking per vehicle  {vehicle_id: [timestamps]}
        self._rate_tracker: dict[str, list[float]] = defaultdict(list)

    # ── Public API ───────────────────────────────────────────────────────────

    def detect(self, processed_msg: dict) -> list[dict]:
        """
        Run all signature-based checks.

        Parameters
        ----------
        processed_msg : dict
            Output from BSMPreprocessor.preprocess().

        Returns
        -------
        list[dict]
            List of alert dicts.  Empty if no threat detected.
        """
        alerts = []
        raw = processed_msg["raw_data"]
        vid = processed_msg["vehicle_id"]
        ts = processed_msg["timestamp"]

        # 1. CRL check
        alert = self._check_crl(raw)
        if alert:
            alerts.append(alert)

        # 2. Replay detection
        alert = self._check_replay(raw, ts)
        if alert:
            alerts.append(alert)

        # 3. DoS / rate-limit check
        alert = self._check_rate(vid, ts)
        if alert:
            alerts.append(alert)

        # 4. Heuristic hints from preprocessor
        hints = processed_msg.get("attack_surface", {})
        if hints.get("possible_replay"):
            alerts.append(self._make_alert(
                "replay", "medium", vid,
                "Duplicate signature detected by preprocessor heuristic",
            ))
        if hints.get("possible_dos"):
            alerts.append(self._make_alert(
                "dos", "high", vid,
                "Excessive message rate detected by preprocessor heuristic",
            ))

        return alerts

    def refresh_crl(self):
        """Pull the latest CRL from the Misbehavior Authority."""
        try:
            resp = requests.get(f"{MA_URL}/crl", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                self._crl_cache = {
                    entry["certificate_id"]: entry
                    for entry in data.get("crl", [])
                }
                self._crl_last_refresh = time.time()
                logger.info("CRL refreshed — %d entries", len(self._crl_cache))
        except Exception as exc:
            logger.warning("CRL refresh failed: %s", exc)

    # ── Internal checks ─────────────────────────────────────────────────────

    def _check_crl(self, raw: dict) -> dict | None:
        # Lazy refresh
        if time.time() - self._crl_last_refresh > self._crl_refresh_interval:
            self.refresh_crl()

        cert_id = raw.get("certificate_id", "")
        if cert_id and cert_id in self._crl_cache:
            entry = self._crl_cache[cert_id]
            return self._make_alert(
                "revoked_certificate", "critical",
                raw.get("vehicle_id", "unknown"),
                f"Certificate {cert_id} is revoked: {entry.get('reason', 'N/A')}",
            )
        return None

    def _check_replay(self, raw: dict, timestamp: float) -> dict | None:
        sig = raw.get("signature", "")
        if not sig:
            return None

        msg_hash = hashlib.sha256(sig.encode()).hexdigest()

        if msg_hash in self._seen_signatures:
            prev_ts = self._seen_signatures[msg_hash]
            return self._make_alert(
                "replay", "high",
                raw.get("vehicle_id", "unknown"),
                f"Replayed message detected (originally seen {timestamp - prev_ts:.1f}s ago)",
            )

        # Age-based filtering
        age = time.time() - timestamp
        if age > REPLAY_MAX_AGE:
            return self._make_alert(
                "replay", "medium",
                raw.get("vehicle_id", "unknown"),
                f"Stale message detected (age={age:.1f}s, threshold={REPLAY_MAX_AGE}s)",
            )

        # Store
        self._seen_signatures[msg_hash] = timestamp
        if len(self._seen_signatures) > self._seen_max_size:
            # Evict oldest
            oldest_key = min(self._seen_signatures, key=self._seen_signatures.get)
            del self._seen_signatures[oldest_key]

        return None

    def _check_rate(self, vehicle_id: str, timestamp: float) -> dict | None:
        window = self._rate_tracker[vehicle_id]
        window.append(timestamp)

        # Keep only last 1 second
        cutoff = timestamp - 1.0
        self._rate_tracker[vehicle_id] = [t for t in window if t > cutoff]

        if len(self._rate_tracker[vehicle_id]) > DOS_RATE_LIMIT:
            return self._make_alert(
                "dos", "high", vehicle_id,
                f"Rate limit exceeded: {len(self._rate_tracker[vehicle_id])} msgs/s "
                f"(limit={DOS_RATE_LIMIT})",
            )
        return None

    @staticmethod
    def _make_alert(attack_type: str, severity: str,
                    vehicle_id: str, description: str) -> dict:
        return {
            "detector": "signature",
            "attack_type": attack_type,
            "severity": severity,
            "vehicle_id": vehicle_id,
            "description": description,
            "timestamp": time.time(),
        }
