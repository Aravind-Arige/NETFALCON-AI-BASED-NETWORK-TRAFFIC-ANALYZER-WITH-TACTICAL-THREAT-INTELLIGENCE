# anomaly_engine/feature_extractor.py

import numpy as np
import time
from collections import deque


class FeatureExtractor:
    """
    Converts raw network metrics into a fixed-length statistical
    feature vector suitable for ML models.

    Call add_sample() every time new metrics arrive, then call
    extract_features() to get the current feature vector.
    """

    def __init__(self, window_size: int = 60):
        """
        window_size: how many recent samples to keep in the sliding window.
        At 1 sample/second this equals 60 seconds of history.
        """
        self.window_size = window_size
        self.history: deque = deque(maxlen=window_size)

    def add_sample(self, metrics: dict):
        """
        Push a new metrics snapshot into the sliding window.

        Expected keys (all numeric, missing keys default to 0):
            bandwidth_in  – inbound KB/s
            bandwidth_out – outbound KB/s  (we derive from bandwidth if absent)
            packet_loss   – percentage 0‑100
            latency       – ms
            jitter        – ms
            error_rate    – errors/sec
            active_flows  – int
            packets_per_sec – int
            unique_ips    – int  (optional; 0 if not tracked)
            timestamp     – unix epoch (optional)
        """
        self.history.append(metrics)

    def extract_features(self) -> "np.ndarray | None":
        """
        Returns a (1, N) numpy array, or None if not enough data yet.
        """
        if len(self.history) < 10:
            return None

        import pandas as pd

        df = pd.DataFrame(list(self.history))

        numeric_cols = [
            "bandwidth_in", "bandwidth_out", "packet_loss",
            "latency", "jitter", "error_rate",
            "active_flows", "packets_per_sec", "unique_ips",
        ]

        # Fill any missing columns with 0
        for col in numeric_cols:
            if col not in df.columns:
                df[col] = 0.0

        features = []

        # --- Per-metric statistical features ---
        stats = ["mean", "std", "max", "min", "last", "dev", "p95"]
        for col in numeric_cols:
            series = df[col].fillna(0).values.astype(float)
            mean   = series.mean()
            std    = series.std()
            mx     = series.max()
            mn     = series.min()
            last   = series[-1]
            dev    = last - mean
            p95    = float(np.percentile(series, 95))
            features.extend([mean, std, mx, mn, last, dev, p95])

        # --- Derived ratio ---
        bw_in  = df["bandwidth_in"].fillna(0).values.astype(float)
        bw_out = df["bandwidth_out"].fillna(0).values.astype(float)
        ratio  = bw_in / (bw_out + 1e-4)
        features.extend([ratio.mean(), ratio.std(), ratio[-1]])

        # --- Velocity / acceleration ---
        for col in ["bandwidth_in", "packets_per_sec", "active_flows"]:
            series = df[col].fillna(0).values.astype(float)
            vel    = np.diff(series).mean() if len(series) >= 2 else 0.0
            accel  = np.diff(np.diff(series)).mean() if len(series) >= 3 else 0.0
            features.extend([vel, accel])

        # --- Time-of-day cyclical features ---
        t     = time.localtime()
        hour  = t.tm_hour / 24.0
        wday  = t.tm_wday / 7.0
        features.extend([hour, wday])

        return np.array(features, dtype=float).reshape(1, -1)

    def get_feature_names(self) -> list:
        names = []
        cols  = [
            "bandwidth_in", "bandwidth_out", "packet_loss",
            "latency", "jitter", "error_rate",
            "active_flows", "packets_per_sec", "unique_ips",
        ]
        stats = ["mean", "std", "max", "min", "current", "deviation", "p95"]
        for col in cols:
            for stat in stats:
                names.append(f"{col}_{stat}")
        names += ["bw_ratio_mean", "bw_ratio_std", "bw_ratio_current"]
        names += [
            "bw_in_velocity", "bw_in_accel",
            "pps_velocity",   "pps_accel",
            "flows_velocity", "flows_accel",
        ]
        names += ["hour_of_day", "day_of_week"]
        return names
