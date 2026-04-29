"""
LSTM (Long Short-Term Memory) model for BSM temporal anomaly detection.

Analyses sequences of BSM feature vectors to detect temporal anomalies
such as trajectory manipulation, coordinated timing attacks, and
gradual data drift characteristic of sophisticated FDI attacks.

Architecture:
  Input(window, features) → LSTM(64) → LSTM(32) →
  Dense(32, relu) → Dropout → Dense(1, sigmoid)
"""

import os
import logging
import numpy as np

from ids.config import LSTM_WINDOW_SIZE, BSM_FEATURE_DIM

logger = logging.getLogger(__name__)

try:
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logger.warning("TensorFlow not available — LSTM model will use sklearn fallback")

try:
    from sklearn.neural_network import MLPClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class LSTMModel:
    """
    Stacked LSTM for BSM temporal anomaly detection.

    Falls back to sklearn MLPClassifier when TensorFlow is not installed.
    """

    def __init__(self, window_size: int = LSTM_WINDOW_SIZE,
                 feature_dim: int = BSM_FEATURE_DIM,
                 model_path: str = None):
        self.window_size = window_size
        self.feature_dim = feature_dim
        self.model = None
        self._use_tf = TF_AVAILABLE
        self._trained = False

        if model_path and os.path.exists(model_path):
            self.load(model_path)
        else:
            self._build_model()

    def _build_model(self):
        """Build the stacked LSTM architecture."""
        if self._use_tf:
            self.model = keras.Sequential([
                layers.Input(shape=(self.window_size, self.feature_dim)),
                layers.LSTM(64, return_sequences=True),
                layers.Dropout(0.2),
                layers.LSTM(32, return_sequences=False),
                layers.Dropout(0.2),
                layers.Dense(32, activation="relu"),
                layers.Dropout(0.3),
                layers.Dense(1, activation="sigmoid"),
            ])
            self.model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=0.001),
                loss="binary_crossentropy",
                metrics=["accuracy"],
            )
            logger.info("LSTM model built with TensorFlow/Keras")
        elif SKLEARN_AVAILABLE:
            self.model = MLPClassifier(
                hidden_layer_sizes=(128, 64, 32),
                activation="relu",
                max_iter=200,
                random_state=42,
            )
            logger.info("LSTM fallback: using sklearn MLPClassifier")
        else:
            logger.error("No ML backend available for LSTM model")

    def train(self, X: np.ndarray, y: np.ndarray,
              epochs: int = 50, batch_size: int = 64,
              validation_split: float = 0.2) -> dict:
        """
        Train the LSTM model.

        Parameters
        ----------
        X : np.ndarray
            Sequences, shape (n_samples, window_size, feature_dim).
        y : np.ndarray
            Labels, shape (n_samples,).  0 = normal, 1 = attack.
        """
        if self._use_tf:
            if X.ndim == 2:
                # Reshape flat features to sequences
                n_samples = X.shape[0]
                X = X.reshape(n_samples, self.window_size, self.feature_dim)

            history = self.model.fit(
                X, y,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=validation_split,
                verbose=0,
            )
            self._trained = True
            return {
                "loss": history.history["loss"][-1],
                "accuracy": history.history["accuracy"][-1],
                "val_loss": history.history.get("val_loss", [0])[-1],
                "val_accuracy": history.history.get("val_accuracy", [0])[-1],
            }
        elif SKLEARN_AVAILABLE:
            # Flatten sequences for sklearn
            X_flat = X.reshape(X.shape[0], -1) if X.ndim == 3 else X
            self.model.fit(X_flat, y)
            self._trained = True
            return {"accuracy": self.model.score(X_flat, y)}
        else:
            return {"error": "No ML backend available"}

    def predict_anomaly_score(self, X: np.ndarray) -> float:
        """
        Predict anomaly score for a single sequence.

        Parameters
        ----------
        X : np.ndarray
            Shape (1, window_size, feature_dim).

        Returns
        -------
        float — anomaly score in [0, 1].
        """
        if not self._trained:
            return 0.0

        try:
            if self._use_tf:
                if X.ndim == 2:
                    X = X.reshape(1, self.window_size, self.feature_dim)
                pred = self.model.predict(X, verbose=0)
                return float(pred[0][0])
            elif SKLEARN_AVAILABLE:
                X_flat = X.reshape(1, -1) if X.ndim == 3 else X
                proba = self.model.predict_proba(X_flat)
                return float(proba[0][1]) if proba.shape[1] > 1 else float(proba[0][0])
        except Exception as exc:
            logger.debug("LSTM predict failed: %s", exc)
            return 0.0

    def save(self, path: str):
        """Persist model to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if self._use_tf:
            self.model.save(path)
            logger.info("LSTM model saved to %s", path)
        elif SKLEARN_AVAILABLE:
            import joblib
            joblib.dump(self.model, path + ".pkl")

    def load(self, path: str):
        """Load model from disk."""
        try:
            if self._use_tf and os.path.exists(path):
                self.model = keras.models.load_model(path)
                self._trained = True
                logger.info("LSTM model loaded from %s", path)
            elif SKLEARN_AVAILABLE and os.path.exists(path + ".pkl"):
                import joblib
                self.model = joblib.load(path + ".pkl")
                self._trained = True
        except Exception as exc:
            logger.warning("Failed to load LSTM model: %s", exc)
            self._build_model()
