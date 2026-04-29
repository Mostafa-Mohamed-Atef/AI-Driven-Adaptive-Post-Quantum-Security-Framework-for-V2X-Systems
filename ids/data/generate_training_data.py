"""
Synthetic BSM Training Data Generator.

Produces labeled datasets of normal vehicle behaviour and injected
attack patterns for training the CNN and LSTM models.

Attack types generated:
  • Sybil — coordinated duplicate identities
  • False Data Injection (FDI) — manipulated position / speed
  • Replay — duplicate messages with stale timestamps
  • DoS — high-frequency message flooding
"""

import logging
import numpy as np
from sklearn.model_selection import train_test_split

from ids.config import (
    BSM_FEATURE_DIM,
    LSTM_WINDOW_SIZE,
    ATTACK_DISTRIBUTION,
)

logger = logging.getLogger(__name__)


class TrainingDataGenerator:
    """Generate synthetic BSM datasets with labeled attacks."""

    def __init__(self, seed: int = 42):
        self.rng = np.random.RandomState(seed)

    # ── Public API ───────────────────────────────────────────────────────

    def generate_cnn_dataset(self, n_normal: int = 5000,
                             n_attack: int = 1000,
                             test_size: float = 0.2) -> dict:
        """
        Generate a dataset for the CNN model (individual BSM vectors).

        Returns dict with X_train, X_test, y_train, y_test.
        """
        # Normal samples
        X_normal = self._generate_normal_bsms(n_normal)
        y_normal = np.zeros(n_normal)

        # Attack samples (mixed types)
        X_attack = self._generate_attack_bsms(n_attack)
        y_attack = np.ones(n_attack)

        # Combine and shuffle
        X = np.vstack([X_normal, X_attack])
        y = np.concatenate([y_normal, y_attack])

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        logger.info(
            "CNN dataset: %d train, %d test, %.1f%% attack",
            len(X_train), len(X_test),
            100 * y.mean()
        )

        return {
            "X_train": X_train.astype(np.float32),
            "X_test": X_test.astype(np.float32),
            "y_train": y_train.astype(np.float32),
            "y_test": y_test.astype(np.float32),
        }

    def generate_lstm_dataset(self, n_normal: int = 1000,
                              n_attack: int = 200,
                              window_size: int = LSTM_WINDOW_SIZE,
                              test_size: float = 0.2) -> dict:
        """
        Generate a dataset for the LSTM model (BSM sequences).

        Returns dict with X_train, X_test, y_train, y_test.
        Shapes: X = (n, window_size, feature_dim), y = (n,).
        """
        # Normal sequences
        X_normal = self._generate_normal_sequences(n_normal, window_size)
        y_normal = np.zeros(n_normal)

        # Attack sequences
        X_attack = self._generate_attack_sequences(n_attack, window_size)
        y_attack = np.ones(n_attack)

        # Combine
        X = np.vstack([X_normal, X_attack])
        y = np.concatenate([y_normal, y_attack])

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        logger.info(
            "LSTM dataset: %d train, %d test, shape=%s",
            len(X_train), len(X_test), X_train.shape
        )

        return {
            "X_train": X_train.astype(np.float32),
            "X_test": X_test.astype(np.float32),
            "y_train": y_train.astype(np.float32),
            "y_test": y_test.astype(np.float32),
        }

    # ── Normal Data Generation ───────────────────────────────────────────

    def _generate_normal_bsms(self, n: int) -> np.ndarray:
        """
        Generate realistic normal BSM feature vectors.

        Feature vector (10 dims):
          [lat, lon, speed, heading, acceleration,
           msg_frequency, inter_msg_gap, pos_delta,
           speed_consistency, heading_consistency]
        """
        X = np.zeros((n, BSM_FEATURE_DIM), dtype=np.float32)

        # Latitude: Detroit area ± small variation
        X[:, 0] = 42.33 + self.rng.normal(0, 0.01, n)
        # Longitude
        X[:, 1] = -83.05 + self.rng.normal(0, 0.01, n)
        # Speed (km/h): urban driving 20-80
        X[:, 2] = self.rng.uniform(20, 80, n)
        # Heading (degrees): random
        X[:, 3] = self.rng.uniform(0, 360, n)
        # Acceleration (m/s²): small values
        X[:, 4] = self.rng.normal(0, 1.5, n)
        # Message frequency (msgs/sec): ~1 Hz for CAM
        X[:, 5] = self.rng.normal(1.0, 0.2, n)
        # Inter-message gap (seconds): ~1s for CAM
        X[:, 6] = self.rng.normal(1.0, 0.15, n)
        # Position delta (meters): consistent with speed
        X[:, 7] = X[:, 2] / 3.6 * X[:, 6]  # speed_ms * dt
        # Speed consistency: low for normal (matched speed ≈ pos_delta / dt)
        X[:, 8] = self.rng.exponential(2.0, n)
        # Heading consistency: low for normal
        X[:, 9] = self.rng.exponential(1.0, n)

        return X

    def _generate_normal_sequences(self, n: int, window: int) -> np.ndarray:
        """Generate normal BSM sequences for LSTM training."""
        sequences = np.zeros((n, window, BSM_FEATURE_DIM), dtype=np.float32)

        for i in range(n):
            # Simulate a vehicle driving normally
            lat = 42.33 + self.rng.normal(0, 0.005)
            lon = -83.05 + self.rng.normal(0, 0.005)
            speed = self.rng.uniform(30, 70)
            heading = self.rng.uniform(0, 360)

            for t in range(window):
                # Smooth evolution
                speed += self.rng.normal(0, 2)
                speed = np.clip(speed, 0, 120)
                heading += self.rng.normal(0, 3)
                heading %= 360
                acc = self.rng.normal(0, 1)

                # Move position consistently
                dt = 1.0 + self.rng.normal(0, 0.1)
                speed_ms = speed / 3.6
                dlat = speed_ms * dt * np.cos(np.radians(heading)) / 111320
                dlon = speed_ms * dt * np.sin(np.radians(heading)) / (
                    111320 * np.cos(np.radians(lat))
                )
                lat += dlat
                lon += dlon

                pos_delta = speed_ms * dt

                sequences[i, t] = [
                    lat, lon, speed, heading, acc,
                    1.0 + self.rng.normal(0, 0.1),  # freq
                    dt,                               # gap
                    pos_delta,                        # pos_delta
                    self.rng.exponential(2),           # speed_consistency
                    self.rng.exponential(1),           # heading_consistency
                ]

        return sequences

    # ── Attack Data Generation ───────────────────────────────────────────

    def _generate_attack_bsms(self, n: int) -> np.ndarray:
        """Generate BSMs exhibiting various attack patterns."""
        X = np.zeros((n, BSM_FEATURE_DIM), dtype=np.float32)

        # Split by attack type
        dist = ATTACK_DISTRIBUTION
        n_sybil = int(n * dist.get("sybil", 0.3))
        n_fdi = int(n * dist.get("fdi", 0.3))
        n_replay = int(n * dist.get("replay", 0.2))
        n_dos = n - n_sybil - n_fdi - n_replay

        idx = 0

        # ── Sybil attacks ────────────────────────────────────────────
        # Multiple identities from same location, coordinated speed/heading
        base_lat = 42.33 + self.rng.normal(0, 0.001)
        base_lon = -83.05 + self.rng.normal(0, 0.001)
        base_speed = self.rng.uniform(40, 60)
        base_heading = self.rng.uniform(0, 360)

        for _ in range(n_sybil):
            X[idx, 0] = base_lat + self.rng.normal(0, 0.0002)   # very close
            X[idx, 1] = base_lon + self.rng.normal(0, 0.0002)
            X[idx, 2] = base_speed + self.rng.normal(0, 1)       # similar speed
            X[idx, 3] = base_heading + self.rng.normal(0, 2)     # similar heading
            X[idx, 4] = self.rng.normal(0, 0.5)
            X[idx, 5] = self.rng.normal(1.0, 0.1)               # normal freq
            X[idx, 6] = self.rng.normal(1.0, 0.1)
            X[idx, 7] = X[idx, 2] / 3.6 * X[idx, 6]
            X[idx, 8] = self.rng.exponential(1.5)
            X[idx, 9] = self.rng.exponential(0.5)
            idx += 1

        # ── FDI attacks ──────────────────────────────────────────────
        # Impossible speed/position combinations
        for _ in range(n_fdi):
            X[idx, 0] = 42.33 + self.rng.normal(0, 0.01)
            X[idx, 1] = -83.05 + self.rng.normal(0, 0.01)
            X[idx, 2] = self.rng.uniform(0, 200)                # wide speed range
            X[idx, 3] = self.rng.uniform(0, 360)
            X[idx, 4] = self.rng.normal(0, 5)                   # wild acceleration
            X[idx, 5] = self.rng.normal(1.0, 0.3)
            X[idx, 6] = self.rng.normal(1.0, 0.2)
            # Position delta inconsistent with speed
            X[idx, 7] = self.rng.uniform(0, 100)                # random pos_delta
            X[idx, 8] = self.rng.uniform(20, 80)                # HIGH speed inconsistency
            X[idx, 9] = self.rng.uniform(10, 50)                # HIGH heading inconsistency
            idx += 1

        # ── Replay attacks ───────────────────────────────────────────
        # Duplicate features with stale timestamps (large gap)
        for _ in range(n_replay):
            X[idx] = self._generate_normal_bsms(1)[0]
            X[idx, 6] = self.rng.uniform(10, 60)                # very large gap
            X[idx, 5] = self.rng.uniform(0.01, 0.1)             # very low freq
            idx += 1

        # ── DoS attacks ──────────────────────────────────────────────
        # Extremely high message frequency
        for _ in range(n_dos):
            X[idx] = self._generate_normal_bsms(1)[0]
            X[idx, 5] = self.rng.uniform(10, 100)               # very high freq
            X[idx, 6] = self.rng.uniform(0.001, 0.05)           # very small gap
            idx += 1

        return X

    def _generate_attack_sequences(self, n: int, window: int) -> np.ndarray:
        """Generate attack BSM sequences for LSTM training."""
        sequences = np.zeros((n, window, BSM_FEATURE_DIM), dtype=np.float32)

        for i in range(n):
            attack_type = self.rng.choice(
                list(ATTACK_DISTRIBUTION.keys()),
                p=list(ATTACK_DISTRIBUTION.values()),
            )

            if attack_type == "sybil":
                sequences[i] = self._sybil_sequence(window)
            elif attack_type == "fdi":
                sequences[i] = self._fdi_sequence(window)
            elif attack_type == "replay":
                sequences[i] = self._replay_sequence(window)
            else:
                sequences[i] = self._dos_sequence(window)

        return sequences

    def _fdi_sequence(self, window: int) -> np.ndarray:
        """FDI: normal at start, then position teleports mid-sequence."""
        seq = np.zeros((window, BSM_FEATURE_DIM))
        lat, lon = 42.33, -83.05
        speed, heading = 50.0, 90.0
        inject_at = self.rng.randint(window // 3, 2 * window // 3)

        for t in range(window):
            if t == inject_at:
                # Teleport position
                lat += self.rng.uniform(0.01, 0.05)
                lon += self.rng.uniform(0.01, 0.05)

            speed += self.rng.normal(0, 2)
            speed = max(0, speed)
            heading += self.rng.normal(0, 2)
            heading %= 360
            dt = 1.0

            if t >= inject_at:
                speed_consistency = self.rng.uniform(30, 70)
                heading_consistency = self.rng.uniform(20, 40)
            else:
                speed_consistency = self.rng.exponential(2)
                heading_consistency = self.rng.exponential(1)

            seq[t] = [
                lat, lon, speed, heading, self.rng.normal(0, 1),
                1.0, dt, speed / 3.6 * dt,
                speed_consistency, heading_consistency,
            ]

        return seq

    def _sybil_sequence(self, window: int) -> np.ndarray:
        """Sybil: extremely coordinated, near-identical behaviour."""
        seq = np.zeros((window, BSM_FEATURE_DIM))
        base = self._generate_normal_bsms(1)[0]
        for t in range(window):
            seq[t] = base + self.rng.normal(0, 0.001, BSM_FEATURE_DIM)
            seq[t, 8] = self.rng.exponential(0.3)  # very low speed inconsistency
            seq[t, 9] = self.rng.exponential(0.2)
        return seq

    def _replay_sequence(self, window: int) -> np.ndarray:
        """Replay: repeating the same BSM multiple times."""
        seq = np.zeros((window, BSM_FEATURE_DIM))
        base = self._generate_normal_bsms(1)[0]
        for t in range(window):
            seq[t] = base.copy()
            seq[t, 6] = self.rng.uniform(10, 30)   # large gaps (stale)
            seq[t, 5] = self.rng.uniform(0.01, 0.1)
        return seq

    def _dos_sequence(self, window: int) -> np.ndarray:
        """DoS: extremely high frequency bursts."""
        seq = np.zeros((window, BSM_FEATURE_DIM))
        for t in range(window):
            seq[t] = self._generate_normal_bsms(1)[0]
            seq[t, 5] = self.rng.uniform(20, 100)
            seq[t, 6] = self.rng.uniform(0.001, 0.02)
        return seq
