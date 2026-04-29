"""
1D Convolutional Neural Network for BSM spatial anomaly detection.

Analyses individual BSM feature vectors to detect spatial anomalies
such as impossible positions, inconsistent kinematics, and other
single-message indicators of attack.

Architecture:
  Input(10, 1) → Conv1D(32) → Conv1D(64) → Conv1D(128) →
  GlobalMaxPool → Dense(64) → Dropout → Dense(1, sigmoid)
"""

import os
import logging
import numpy as np

logger = logging.getLogger(__name__)

try:
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logger.warning("TensorFlow not available — CNN model will use sklearn fallback")

try:
    from sklearn.neural_network import MLPClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class CNNModel:
    """
    1D-CNN for BSM spatial anomaly detection.

    Falls back to an sklearn MLPClassifier when TensorFlow is not
    installed, ensuring the IDS still works in lightweight environments.
    """

    def __init__(self, input_dim: int = 10, model_path: str = None):
        self.input_dim = input_dim
        self.model = None
        self._use_tf = TF_AVAILABLE
        self._trained = False

        if model_path and os.path.exists(model_path):
            self.load(model_path)
        else:
            self._build_model()

    def _build_model(self):
        """Build the CNN architecture."""
        if self._use_tf:
            self.model = keras.Sequential([
                layers.Input(shape=(self.input_dim, 1)),
                layers.Conv1D(32, 3, activation="relu", padding="same"),
                layers.BatchNormalization(),
                layers.Conv1D(64, 3, activation="relu", padding="same"),
                layers.BatchNormalization(),
                layers.Conv1D(128, 3, activation="relu", padding="same"),
                layers.GlobalMaxPooling1D(),
                layers.Dense(64, activation="relu"),
                layers.Dropout(0.3),
                layers.Dense(1, activation="sigmoid"),
            ])
            self.model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=0.001),
                loss="binary_crossentropy",
                metrics=["accuracy"],
            )
            logger.info("CNN model built with TensorFlow/Keras")
        elif SKLEARN_AVAILABLE:
            self.model = MLPClassifier(
                hidden_layer_sizes=(64, 32),
                activation="relu",
                max_iter=200,
                random_state=42,
            )
            logger.info("CNN fallback: using sklearn MLPClassifier")
        else:
            logger.error("No ML backend available for CNN model")

    def train(self, X: np.ndarray, y: np.ndarray,
              epochs: int = 50, batch_size: int = 64,
              validation_split: float = 0.2) -> dict:
        """
        Train the model.

        Parameters
        ----------
        X : np.ndarray
            Features, shape (n_samples, input_dim) or (n_samples, input_dim, 1).
        y : np.ndarray
            Labels, shape (n_samples,).  0 = normal, 1 = attack.

        Returns
        -------
        dict with training history / metrics.
        """
        if self._use_tf:
            if X.ndim == 2:
                X = X.reshape(-1, self.input_dim, 1)
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
            if X.ndim == 3:
                X = X.reshape(X.shape[0], -1)
            self.model.fit(X, y)
            self._trained = True
            train_acc = self.model.score(X, y)
            return {"accuracy": train_acc}
        else:
            return {"error": "No ML backend available"}

    def predict_anomaly_score(self, X: np.ndarray) -> float:
        """
        Predict anomaly score for a single sample.

        Parameters
        ----------
        X : np.ndarray
            Shape (1, input_dim, 1) for TF or (1, input_dim) for sklearn.

        Returns
        -------
        float — anomaly score in [0, 1].
        """
        if not self._trained:
            return 0.0

        try:
            if self._use_tf:
                if X.ndim == 2:
                    X = X.reshape(1, self.input_dim, 1)
                pred = self.model.predict(X, verbose=0)
                return float(pred[0][0])
            elif SKLEARN_AVAILABLE:
                if X.ndim == 3:
                    X = X.reshape(1, -1)
                proba = self.model.predict_proba(X)
                return float(proba[0][1]) if proba.shape[1] > 1 else float(proba[0][0])
        except Exception as exc:
            logger.debug("CNN predict failed: %s", exc)
            return 0.0

    def save(self, path: str):
        """Save model to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if self._use_tf:
            self.model.save(path)
            logger.info("CNN model saved to %s", path)
        elif SKLEARN_AVAILABLE:
            import joblib
            joblib.dump(self.model, path + ".pkl")
            logger.info("CNN sklearn model saved to %s.pkl", path)

    def load(self, path: str):
        """Load model from disk."""
        try:
            if self._use_tf and os.path.exists(path):
                self.model = keras.models.load_model(path)
                self._trained = True
                logger.info("CNN model loaded from %s", path)
            elif SKLEARN_AVAILABLE and os.path.exists(path + ".pkl"):
                import joblib
                self.model = joblib.load(path + ".pkl")
                self._trained = True
                logger.info("CNN sklearn model loaded from %s.pkl", path)
        except Exception as exc:
            logger.warning("Failed to load CNN model: %s", exc)
            self._build_model()
