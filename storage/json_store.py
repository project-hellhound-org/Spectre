"""
Thread-safe event store with atomic JSON persistence.

Replaces two problems in the original tool:
  1. analyzer.py's read-modify-rewrite of the whole logs.json file on
     every single flagged query (O(n) per write, and non-atomic — a crash
     mid-write could corrupt the file).
  2. The multiprocessing architecture, where the sniffer and the Flask
     dashboard ran in separate OS processes with separate memory, so
     state (like query_history) couldn't be shared. This tool now runs
     as one process with the sniffer on a background thread, so the
     dashboard can read live in-memory state directly instead of only
     ever seeing what's been flushed to disk.
"""
import json
import os
import threading
from collections import deque

from core.paths import default_log_path


class EventStore:
    def __init__(self, path: str = None, max_memory: int = 2000, flush_every: int = 1):
        self.path = path or default_log_path()
        self.max_memory = max_memory
        self.flush_every = flush_every
        self._events = deque(maxlen=max_memory)
        self._lock = threading.Lock()
        self._since_flush = 0
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._load_existing()

    def _load_existing(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            for entry in data[-self.max_memory:]:
                self._events.append(entry)
        except (json.JSONDecodeError, OSError):
            pass  # start clean rather than crash on a corrupt/empty log file

    def add(self, entry: dict, force_flush: bool = False):
        with self._lock:
            self._events.append(entry)
            self._since_flush += 1
            if force_flush or self._since_flush >= self.flush_every:
                self._flush_locked()

    def _flush_locked(self):
        tmp_path = self.path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(list(self._events), f, indent=2)
        os.replace(tmp_path, self.path)  # atomic on POSIX and Windows
        self._since_flush = 0

    def all(self) -> list:
        with self._lock:
            return list(self._events)

    def recent(self, n: int = 300) -> list:
        with self._lock:
            return list(self._events)[-n:]

    def summary(self) -> dict:
        with self._lock:
            counts = {"CRITICAL": 0, "HIGH": 0, "SUSPICIOUS": 0, "LOW": 0, "BENIGN": 0}
            for e in self._events:
                sev = e.get("severity", "BENIGN")
                counts[sev] = counts.get(sev, 0) + 1
            return counts
