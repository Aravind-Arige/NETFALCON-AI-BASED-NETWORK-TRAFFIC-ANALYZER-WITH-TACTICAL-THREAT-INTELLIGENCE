# anomaly_engine/models.py

import numpy as np
import joblib
import os
from collections import deque
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


class IsolationForestDetector:
    """
    Fast, explainable anomaly detection via Isolation Forest.
    - Trains automatically once min_samples are buffered.
    - Returns a 0-100 anomaly score (higher = more anomalous).
    - Supports save/load so the model persists across restarts.
    """

    def __init__(self, contamination: float = 0.05, min_samples: int = 300):
        self.contamination   = contamination
        self.min_samples     = min_samples
        self.is_trained      = False
        self.training_buffer: list = []

        self.model = Pipeline([
            ("scaler",  StandardScaler()),
            ("iforest", IsolationForest(
                n_estimators=200,
                contamination=contamination,
                random_state=42,
                n_jobs=-1,
            )),
        ])

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def add_training_sample(self, features: np.ndarray):
        """Buffer a sample.  Auto-trains once min_samples reached."""
        self.training_buffer.append(features.flatten())
        if len(self.training_buffer) >= self.min_samples and not self.is_trained:
            self.train()

    def train(self):
        X = np.array(self.training_buffer)
        self.model.fit(X)
        self.is_trained = True
        print(f"[AnomalyEngine] IsolationForest trained on {len(X)} samples.")

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self, features: np.ndarray) -> dict:
        """
        Returns a result dict with keys:
            score           – float 0-100  (100 = most anomalous)
            label           – str  normal | low | medium | high | critical
            is_anomaly      – bool
            confidence      – float 0-1
            learning_progress – float 0-100
            message         – str (non-empty only during learning phase)
        """
        if not self.is_trained:
            self.add_training_sample(features)
            progress = min(len(self.training_buffer) / self.min_samples * 100, 100)
            return {
                "score": 0,
                "label": "learning",
                "is_anomaly": False,
                "confidence": 0.0,
                "learning_progress": progress,
                "message": f"Building AI baseline… {progress:.0f}% complete",
            }

        X        = features.reshape(1, -1)
        pred     = self.model.predict(X)[0]          # -1 = anomaly, 1 = normal
        raw      = self.model.decision_function(X)[0] # negative = anomalous

        # Normalise decision score to 0-100
        normalised = float(np.clip((0.5 - raw) * 100, 0, 100))

        label = self._to_label(normalised)

        return {
            "score":            round(float(normalised), 1), # type: ignore
            "label":            label,
            "is_anomaly":       bool(pred == -1),
            "confidence":       round(float(min(len(self.training_buffer) / 1000, 1.0)), 2), # type: ignore
            "learning_progress": 100.0,
            "message":          "",
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str = "models/isolation_forest.pkl"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self.model, "buffer_len": len(self.training_buffer)},
                    path)
        print(f"[AnomalyEngine] Model saved → {path}")

    def load(self, path: str = "models/isolation_forest.pkl") -> bool:
        if not os.path.exists(path):
            return False
        from sklearn.utils.validation import check_is_fitted
        from sklearn.exceptions import NotFittedError
        
        data = joblib.load(path)
        self.model      = data["model"]
        try:
            check_is_fitted(self.model)
            self.is_trained = True
            print(f"[AnomalyEngine] Model loaded and verified as trained from {path}")
        except NotFittedError:
            self.is_trained = False
            print(f"[AnomalyEngine] Loaded model from {path} but it is NOT trained yet.")
            
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_label(score: float) -> str:
        if score < 40:  return "normal"
        if score < 65:  return "low"
        if score < 80:  return "medium"
        if score < 92:  return "high"
        return "critical"
