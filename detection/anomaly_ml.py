"""
Layer 4 of the detection pipeline: unsupervised ML anomaly scoring.

We don't have a labeled dataset of confirmed tunneling traffic for this
network, so a supervised classifier isn't viable yet — this is exactly
the situation the design doc calls out for Isolation Forest / LOF /
clustering instead of a supervised model. This wrapper:

  - buffers recent feature vectors (global, per detector instance)
  - periodically refits an IsolationForest against that rolling buffer
  - scores each new event against the current model

Isolation Forest partitions data with random splits; points that isolate
in fewer splits (closer to the tree root) are scored as more anomalous.
It needs no labels and adapts as the buffer's contents shift over time.

If scikit-learn isn't installed, this degrades gracefully to a neutral
(0.0) score rather than failing — the rule-based and statistical layers
still function fully without it.
"""
from collections import deque

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

FEATURE_ORDER = [
    "fqdn_length", "max_label_length", "label_count", "avg_label_length",
    "leftmost_entropy", "entropy_mean", "digit_ratio", "alpha_ratio",
    "special_ratio", "unique_subdomain_ratio", "queries_per_second",
]


class AnomalyDetector:
    def __init__(self, buffer_size: int = 500, retrain_every: int = 50, min_samples: int = 30):
        self.buffer = deque(maxlen=buffer_size)
        self.retrain_every = retrain_every
        self.min_samples = min_samples
        self._model = None
        self._since_retrain = 0

    @staticmethod
    def vectorize(features: dict) -> list:
        return [float(features.get(k, 0.0)) for k in FEATURE_ORDER]

    def observe_and_score(self, features: dict) -> float:
        if not SKLEARN_AVAILABLE:
            return 0.0

        vec = self.vectorize(features)
        self.buffer.append(vec)
        self._since_retrain += 1

        if len(self.buffer) < self.min_samples:
            return 0.0  # not enough history yet to fit a meaningful model

        if self._model is None or self._since_retrain >= self.retrain_every:
            x = np.array(self.buffer)
            self._model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
            self._model.fit(x)
            self._since_retrain = 0

        raw = self._model.decision_function([vec])[0]  # higher = more "normal"
        anomaly = max(0.0, min(1.0, 0.5 - raw))          # rough normalization to 0..1
        return anomaly
