"""
Dataset Loader — Load and adapt real-world V2X / IDS datasets for training.

Supports:
  1. VeReMi (Vehicular Reference Misbehavior) dataset
  2. CICIoV2024 (CIC Internet of Vehicles)
  3. Car-Hacking Dataset (CAN bus)
  4. Generic CSV datasets with configurable column mapping

Each loader normalizes the data into the standard 10-feature BSM format
expected by the CNN and LSTM models.
"""

import os
import logging
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ids.config import BSM_FEATURE_DIM, LSTM_WINDOW_SIZE

logger = logging.getLogger(__name__)


# ── Feature column mapping per dataset ────────────────────────────────────────

VEREMI_COLUMNS = {
    "pos_x": "latitude",        # VeReMi uses X/Y coordinates
    "pos_y": "longitude",
    "spd_x": "speed",           # speed components
    "spd_y": "heading",
    "acl_x": "acceleration",
    "rcvTime": "timestamp",
    "senderId": "vehicle_id",
    "type": "label",            # 0 = normal, 1-5 = attack types
}

CICIV_COLUMNS = {
    "Latitude": "latitude",
    "Longitude": "longitude",
    "Vehicle_Speed": "speed",
    "Heading": "heading",
    "Acceleration": "acceleration",
    "Timestamp": "timestamp",
    "Vehicle_ID": "vehicle_id",
    "Label": "label",
}


class DatasetLoader:
    """Load and preprocess real-world datasets for IDS training."""

    def __init__(self):
        self.scaler = StandardScaler()

    # ── VeReMi Dataset ────────────────────────────────────────────────────

    def load_veremi(self, csv_path: str, test_size: float = 0.2) -> dict:
        """
        Load VeReMi dataset from a preprocessed CSV file.

        Expected CSV columns (may vary by preprocessed version):
            sender, receiver, pos_x, pos_y, spd_x, spd_y,
            acl_x, acl_y, hed_x, hed_y, rcvTime, type

        Where 'type' is the label:
            0 = Normal
            1 = Constant Position Attack
            2 = Constant Offset Position Attack
            4 = Random Position Attack
            8 = Random Speed Attack
            16 = Eventual Stop Attack

        Parameters
        ----------
        csv_path : str
            Path to the VeReMi CSV file.
        test_size : float
            Fraction for test split.

        Returns
        -------
        dict with X_train, X_test, y_train, y_test, attack_map
        """
        logger.info("Loading VeReMi dataset from %s", csv_path)
        df = pd.read_csv(csv_path)
        logger.info("VeReMi: %d rows, %d columns", len(df), len(df.columns))
        logger.info("Columns: %s", list(df.columns))

        # Map VeReMi attack types to binary (normal=0, attack=1)
        attack_map = {
            0: "normal",
            1: "constant_position",
            2: "constant_offset",
            4: "random_position",
            8: "random_speed",
            16: "eventual_stop",
        }

        # Identify label column
        label_col = None
        for candidate in ["type", "label", "class", "attack_type", "Label"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col is None:
            raise ValueError(
                f"No label column found. Available: {list(df.columns)}"
            )

        # Binary label: 0 = normal, 1 = attack
        y = (df[label_col] != 0).astype(np.float32).values

        # Extract features — adapt to whatever columns are available
        feature_cols = self._find_feature_columns(df)
        logger.info("Using feature columns: %s", feature_cols)

        X = df[feature_cols].fillna(0).values.astype(np.float32)

        # Pad or truncate to BSM_FEATURE_DIM
        X = self._pad_features(X)

        # Normalize
        X = self.scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        logger.info(
            "VeReMi loaded: %d train, %d test, %.1f%% attack",
            len(X_train), len(X_test), 100 * y.mean()
        )

        return {
            "X_train": X_train,
            "X_test": X_test,
            "y_train": y_train,
            "y_test": y_test,
            "attack_map": attack_map,
            "feature_columns": feature_cols,
        }

    # ── CICIoV2024 Dataset ────────────────────────────────────────────────

    def load_ciciv(self, csv_path: str, test_size: float = 0.2) -> dict:
        """
        Load CICIoV2024 or similar CIC-format dataset.

        Returns dict with X_train, X_test, y_train, y_test.
        """
        logger.info("Loading CICIoV dataset from %s", csv_path)
        df = pd.read_csv(csv_path)

        # Find label column
        label_col = None
        for candidate in ["Label", "label", "class", "Attack"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col is None:
            raise ValueError(f"No label column. Available: {list(df.columns)}")

        # Binary labels
        if df[label_col].dtype == object:
            y = (df[label_col].str.lower() != "normal").astype(np.float32).values
        else:
            y = (df[label_col] != 0).astype(np.float32).values

        # Extract numeric features
        feature_cols = self._find_feature_columns(df)
        X = df[feature_cols].fillna(0).values.astype(np.float32)
        X = self._pad_features(X)
        X = self.scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        return {
            "X_train": X_train, "X_test": X_test,
            "y_train": y_train, "y_test": y_test,
            "feature_columns": feature_cols,
        }

    # ── Generic CSV Loader ────────────────────────────────────────────────

    def load_csv(self, csv_path: str, label_column: str = "label",
                 feature_columns: list = None,
                 test_size: float = 0.2) -> dict:
        """
        Load any CSV dataset with configurable column mapping.

        Parameters
        ----------
        csv_path : str
        label_column : str
            Column name for labels (0=normal, nonzero=attack).
        feature_columns : list[str], optional
            Specific feature columns to use.  If None, auto-detected.
        """
        logger.info("Loading generic CSV from %s", csv_path)
        df = pd.read_csv(csv_path)

        if label_column not in df.columns:
            raise ValueError(
                f"Label column '{label_column}' not found. "
                f"Available: {list(df.columns)}"
            )

        if df[label_column].dtype == object:
            y = (df[label_column].str.lower() != "normal").astype(np.float32).values
        else:
            y = (df[label_column] != 0).astype(np.float32).values

        if feature_columns:
            X = df[feature_columns].fillna(0).values.astype(np.float32)
        else:
            feature_cols = self._find_feature_columns(df)
            X = df[feature_cols].fillna(0).values.astype(np.float32)

        X = self._pad_features(X)
        X = self.scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        return {
            "X_train": X_train, "X_test": X_test,
            "y_train": y_train, "y_test": y_test,
        }

    # ── LSTM Sequence Builder ─────────────────────────────────────────────

    def build_lstm_sequences(self, X: np.ndarray, y: np.ndarray,
                             window_size: int = LSTM_WINDOW_SIZE) -> tuple:
        """
        Convert flat feature arrays into LSTM-compatible sequences.

        Groups consecutive samples into sliding windows.
        Returns (X_sequences, y_sequences).
        """
        sequences = []
        labels = []

        for i in range(len(X) - window_size):
            seq = X[i:i + window_size]
            # Label = majority vote in the window
            lbl = 1.0 if y[i:i + window_size].mean() > 0.3 else 0.0
            sequences.append(seq)
            labels.append(lbl)

        return (
            np.array(sequences, dtype=np.float32),
            np.array(labels, dtype=np.float32),
        )

    # ── Helpers ───────────────────────────────────────────────────────────

    def _find_feature_columns(self, df: pd.DataFrame) -> list:
        """Auto-detect numeric feature columns, excluding IDs and labels."""
        exclude = {
            "type", "label", "class", "attack_type", "Label", "Attack",
            "sender", "receiver", "senderId", "receiverId",
            "vehicle_id", "Vehicle_ID", "id", "ID", "index",
        }
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        feature_cols = [c for c in numeric_cols if c not in exclude]
        return feature_cols[:BSM_FEATURE_DIM * 2]  # cap at 20 cols max

    def _pad_features(self, X: np.ndarray) -> np.ndarray:
        """Pad or truncate feature matrix to BSM_FEATURE_DIM columns."""
        n_samples, n_features = X.shape

        if n_features == BSM_FEATURE_DIM:
            return X
        elif n_features > BSM_FEATURE_DIM:
            return X[:, :BSM_FEATURE_DIM]
        else:
            padding = np.zeros((n_samples, BSM_FEATURE_DIM - n_features))
            return np.hstack([X, padding])
