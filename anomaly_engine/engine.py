# anomaly_engine/engine.py

import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable, List, Optional

from .feature_extractor import FeatureExtractor
from .models import IsolationForestDetector
from .explainer import AnomalyExplainer


class AnomalyDetectionEngine:
    """
    Main orchestrator for the AI anomaly detection layer.

    Usage:
        engine = AnomalyDetectionEngine()
        engine.load_models()                     # try to load saved model
        engine.on_anomaly(my_callback)           # register alert handler
        result = engine.ingest(metrics_dict)     # call every metrics cycle
    """

    SCORE_HISTORY_LEN = 720   # ~12 min at 1 sample/s
    ALERT_HISTORY_LEN = 200

    def __init__(self, alert_cooldown: int = 60):
        """
        alert_cooldown: minimum seconds between successive alert callbacks.
        """
        self.extractor   = FeatureExtractor(window_size=60)
        self.detector    = IsolationForestDetector(contamination=0.05, min_samples=300)
        self.explainer: Optional[AnomalyExplainer] = None

        self.score_history: deque = deque(maxlen=self.SCORE_HISTORY_LEN)
        self.alert_history: deque = deque(maxlen=self.ALERT_HISTORY_LEN)
        self._callbacks: List[Callable] = []

        self.alert_cooldown  = alert_cooldown
        self._last_alert_ts  = 0.0

        # Public state (read by REST endpoints)
        self.current_score     = 0.0
        self.current_label     = "learning"
        self.is_learning       = True
        self.learning_progress = 0.0

        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on_anomaly(self, callback: Callable):
        """Register a function to be called when an anomaly is detected."""
        self._callbacks.append(callback)

    def ingest(self, metrics: dict) -> dict:
        """
        Feed one metrics snapshot into the engine.
        Thread-safe.  Returns a result dict.
        """
        with self._lock:
            return self._process(metrics)

    def get_score_history(self) -> list:
        return list(self.score_history)

    def get_alert_history(self) -> list:
        return list(self.alert_history)

    def retrain(self):
        """Hard-reset the model so it relearns from scratch."""
        self.detector.is_trained      = False
        self.detector.training_buffer = []
        self.is_learning              = True
        self.current_score            = 0.0
        self.current_label            = "learning"
        self.learning_progress        = 0.0
        print("[AnomalyEngine] Reset — relearning baseline from scratch.")

    def save_models(self):
        try:
            self.detector.save("models/isolation_forest.pkl")
        except Exception as e:
            print(f"[AnomalyEngine] Save failed: {e}")

    def load_models(self) -> bool:
        try:
            return self.detector.load("models/isolation_forest.pkl")
        except Exception as e:
            print(f"[AnomalyEngine] Load failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Internal processing pipeline
    # ------------------------------------------------------------------

    def _process(self, metrics: dict) -> dict:
        # 1. Push into feature extractor
        self.extractor.add_sample(metrics)

        # 2. Get feature vector
        features = self.extractor.extract_features()
        if features is None:
            return self._learning_result()

        # 3. Lazy-init explainer
        explainer = self.explainer
        if explainer is None:
            explainer = AnomalyExplainer(self.extractor.get_feature_names())
            self.explainer = explainer

        # 4. Keep baseline for explainer updated
        explainer.update_baseline(features)

        # 5. Score
        result = self.detector.score(features)

        if result["label"] == "learning":
            self.learning_progress = result["learning_progress"]
            self.is_learning = True
            return self._learning_result()

        self.is_learning = False

        score = result["score"]
        label = result["label"]

        # 6. Explanations (only when anomalous enough)
        explanations = []
        if score > 60 and explainer:
            explanations = explainer.explain(features)
        result["explanations"] = explanations

        # 7. Suggested actions
        result["suggested_actions"] = self._suggest_actions(explanations)

        # 8. Record history entry
        ts = datetime.now().isoformat(timespec="seconds")
        entry = {"timestamp": ts, "score": score, "label": label}
        self.score_history.append(entry)

        # 9. Update public state
        self.current_score  = score
        self.current_label  = label
        self.learning_progress = 100.0

        # 10. Fire alert callbacks (throttled)
        if score > 70:
            self._maybe_alert({**result, "raw_metrics": metrics, "timestamp": ts})

        return {**result, "timestamp": ts, "learning_progress": 100.0}

    # ------------------------------------------------------------------
    # Alert firing
    # ------------------------------------------------------------------

    def _maybe_alert(self, full_result: dict):
        now = time.time()
        if now - self._last_alert_ts < self.alert_cooldown:
            return
        self._last_alert_ts = now
        self.alert_history.appendleft(full_result)
        for cb in self._callbacks:
            threading.Thread(target=self._safe_call, args=(cb, full_result),
                             daemon=True).start()

    @staticmethod
    def _safe_call(cb, arg):
        try:
            cb(arg)
        except Exception as e:
            print(f"[AnomalyEngine] Alert callback error: {e}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _learning_result(self) -> dict:
        return {
            "score":            0,
            "label":            "learning",
            "is_anomaly":       False,
            "explanations":     [],
            "suggested_actions":[],
            "confidence":       0,
            "learning_progress": self.learning_progress,
            "message":          f"Building AI baseline… {self.learning_progress:.0f}% complete",
        }

    @staticmethod
    def _suggest_actions(explanations: list) -> list:
        actions = []
        for exp in explanations:
            feat = exp["feature"]
            dire = exp.get("direction", "")
            if "bandwidth_out" in feat and dire == "higher":
                actions.append("Investigate potential data exfiltration — outbound traffic spike detected")
            elif "packet_loss" in feat:
                actions.append("Check physical network layer and upstream provider — abnormal packet loss")
            elif "active_flows" in feat and dire == "higher":
                actions.append("Possible port scan or connection flood — review top talkers table")
            elif "unique_ips" in feat and dire == "higher":
                actions.append("Unusual number of unique sources — possible DDoS or botnet activity")
            elif "packets_per_sec" in feat and dire == "higher":
                actions.append("High packet rate detected — consider rate limiting on edge devices")
            elif "error_rate" in feat and dire == "higher":
                actions.append("Elevated error rate — check interface health and upstream link")
        if not actions:
            actions.append("Review traffic patterns in the historical timeline")
        return list(dict.fromkeys(actions))   # deduplicate, preserve order
