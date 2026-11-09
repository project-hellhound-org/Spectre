"""
Layer 2 of the detection pipeline: statistical baselining.

Rather than a global fixed threshold ("qps > 5 is suspicious" for every
host on the network), this asks "is this abnormal for *this* host?" by
maintaining a rolling mean/std per key and scoring new values as a
z-score against their own recent history. A host that normally does
150 q/min and jumps to 1800 stands out even if 1800 wouldn't trip a
static global threshold tuned for busier hosts.
"""
import math
from collections import defaultdict, deque


class RollingBaseline:
    def __init__(self, maxlen: int = 200, min_history: int = 10):
        self.maxlen = maxlen
        self.min_history = min_history
        self._history = defaultdict(lambda: deque(maxlen=maxlen))

    def update_and_score(self, key: str, value: float) -> float:
        hist = self._history[key]
        z = 0.0
        if len(hist) >= self.min_history:
            mean = sum(hist) / len(hist)
            variance = sum((x - mean) ** 2 for x in hist) / len(hist)
            std = math.sqrt(variance)
            if std > 0:
                z = (value - mean) / std
        hist.append(value)
        return z
