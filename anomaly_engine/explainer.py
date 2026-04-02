# anomaly_engine/explainer.py

import numpy as np
from typing import Optional


class AnomalyExplainer:
    """
    Given an anomalous feature vector and a running baseline, explains
    WHICH features deviate the most and provides human-readable descriptions.
    """

    def __init__(self, feature_names: list):
        self.feature_names   = feature_names
        self.baseline_mean: Optional[np.ndarray] = None
        self.baseline_std:  Optional[np.ndarray] = None
        self._samples: list = []

    # ------------------------------------------------------------------
    # Baseline maintenance
    # ------------------------------------------------------------------

    def update_baseline(self, features: np.ndarray):
        self._samples.append(features.flatten())
        if len(self._samples) > 1000:
            self._samples.pop(0)
        arr = np.array(self._samples)
        self.baseline_mean = arr.mean(axis=0)
        self.baseline_std  = arr.std(axis=0) + 1e-8

    # ------------------------------------------------------------------
    # Explanation
    # ------------------------------------------------------------------

    def explain(self, features: np.ndarray, top_n: int = 5) -> list:
        """
        Returns a list of dicts (sorted by z-score desc) describing the
        top contributing features.
        """
        baseline_mean = self.baseline_mean
        baseline_std = self.baseline_std
        if baseline_mean is None or baseline_std is None:
            return []

        flat     = features.flatten()
        z_scores = np.abs((flat - baseline_mean) / baseline_std)

        top_idx  = np.argsort(z_scores)[::-1][:top_n]
        results  = []

        for idx in top_idx:
            if idx >= len(self.feature_names):
                continue
            z = float(z_scores[idx])
            if z < 1.5:
                continue  # not significant

            name      = self.feature_names[idx]
            current   = float(flat[idx])
            normal    = float(baseline_mean[idx]) # type: ignore
            direction = "higher" if current > normal else "lower"
            pct_diff  = abs((current - normal) / (abs(normal) + 1e-8)) * 100

            results.append({
                "feature":       name,
                "z_score":       round(float(z), 2),      # type: ignore
                "current_value": round(float(current), 3),# type: ignore
                "normal_value":  round(float(normal), 3), # type: ignore
                "direction":     direction,
                "percent_diff":  round(float(pct_diff), 1),# type: ignore
                "description":   self._humanize(name, direction, current, normal, pct_diff),
            })

        return results

    # ------------------------------------------------------------------
    # Human-readable messages
    # ------------------------------------------------------------------

    _TEMPLATES = {
        "bandwidth_in_current":  "Inbound bandwidth is {dir} than normal ({pct:.0f}% deviation)",
        "bandwidth_out_current": "Outbound bandwidth is {dir} than normal ({pct:.0f}% deviation) — possible exfiltration",
        "packet_loss_current":   "Packet loss is significantly {dir} — possible network degradation or attack",
        "latency_current":       "Network latency is {pct:.0f}% {dir} than baseline",
        "jitter_current":        "Jitter is {dir}, suggesting unstable network conditions",
        "error_rate_current":    "Error rate is {pct:.0f}% {dir} — check for hardware issues or DoS",
        "active_flows_current":  "Active connection count is unusually {dir} ({pct:.0f}% from normal)",
        "packets_per_sec_current": "Packet rate is {dir} by {pct:.0f}% — potential flood attack",
        "unique_ips_current":    "Number of unique IPs is {dir} — possible scanning or botnet activity",
        "bw_ratio_current":      "In/Out traffic ratio is abnormal — possible data exfiltration",
        "bw_in_velocity":        "Bandwidth is rapidly {'increasing' if True else 'dropping'} — sudden traffic surge",
    }

    def _humanize(self, feature: str, direction: str, current: float,
                  normal: float, pct: float) -> str:
        for key, tpl in self._TEMPLATES.items():
            if key in feature:
                try:
                    return tpl.format(dir=direction, pct=pct)
                except Exception:
                    return tpl
        # Generic fallback
        return f"{feature.replace('_', ' ').title()} is {direction} than normal ({pct:.0f}% deviation)"
