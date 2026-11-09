"""
Behavioral / temporal feature tracking.

Replaces the original analyzer.py's `query_history` — a single unbounded,
lifetime, per-process dict with no time dimension. These trackers instead:
  - use a real sliding time window (default 5 minutes, configurable)
  - evict old entries automatically
  - are thread-safe, since the detector now runs the sniffer and the
    dashboard as threads in one process sharing this state
"""
import threading
import time
from collections import defaultdict, deque


class SlidingWindowTracker:
    """Tracks, per registered domain, the unique-subdomain ratio, and per
    source host, the query rate — both over a rolling time window."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self._domain_events = defaultdict(deque)   # domain -> deque[(ts, subdomain)]
        self._host_events = defaultdict(deque)      # host -> deque[ts]
        self._lock = threading.Lock()

    def record(self, host: str, registered_domain: str, subdomain: str, now: float = None):
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._domain_events[registered_domain]
            dq.append((now, subdomain))
            while dq and now - dq[0][0] > self.window_seconds:
                dq.popleft()

            hdq = self._host_events[host]
            hdq.append(now)
            while hdq and now - hdq[0] > self.window_seconds:
                hdq.popleft()

    def domain_stats(self, registered_domain: str) -> dict:
        with self._lock:
            dq = self._domain_events.get(registered_domain, deque())
            total = len(dq)
            unique = len({s for _, s in dq})
            return {
                "window_query_count": total,
                "unique_subdomain_count": unique,
                "unique_subdomain_ratio": (unique / total) if total else 0.0,
            }

    def host_rate(self, host: str) -> dict:
        with self._lock:
            hdq = self._host_events.get(host, deque())
            n = len(hdq)
            qps = (n / self.window_seconds) if self.window_seconds else 0.0
            return {"host_window_count": n, "queries_per_second": qps}


class RecordTypeTracker:
    """Tracks, per registered domain, TXT-ratio and NXDOMAIN-ratio from
    observed DNS *responses* over a rolling window. This closes the
    original tool's blind spot of only ever inspecting queries (qr == 0)
    and never the answer side of the exchange."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self._events = defaultdict(deque)  # domain -> deque[(ts, qtype, rcode)]
        self._lock = threading.Lock()

    def record(self, registered_domain: str, qtype: str, rcode: str, now: float = None):
        now = now if now is not None else time.time()
        with self._lock:
            dq = self._events[registered_domain]
            dq.append((now, qtype, rcode))
            while dq and now - dq[0][0] > self.window_seconds:
                dq.popleft()

    def stats(self, registered_domain: str) -> dict:
        with self._lock:
            dq = self._events.get(registered_domain, deque())
            total = len(dq)
            txt = sum(1 for _, qt, _ in dq if qt == "TXT")
            nx = sum(1 for _, _, rc in dq if rc == "NXDOMAIN")
            return {
                "record_window_count": total,
                "txt_ratio": (txt / total) if total else 0.0,
                "nxdomain_ratio": (nx / total) if total else 0.0,
            }
