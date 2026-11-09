"""
The detection engine ties every layer together for each incoming event:

  query event  -> features -> rules (L1) -> baseline z-score (L2)
                            -> ML anomaly (L4) -> correlation -> risk verdict
  response event -> record-type tracker only (feeds txt_ratio/nxdomain_ratio
                     for whichever query events follow)

`colorama` was a listed but unused dependency in the original tool; it's
now wired into the console output for severity-colored live output.
"""
import time

from colorama import Fore, Style, init as colorama_init

from features.aggregator import build_query_features, registered_domain
from features.frequency import SlidingWindowTracker, RecordTypeTracker
from detection.rules import RuleEngine
from detection.baseline import RollingBaseline
from detection.anomaly_ml import AnomalyDetector
from detection.correlation import correlate

colorama_init(autoreset=True)

SEVERITY_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "SUSPICIOUS": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "BENIGN": Fore.WHITE,
}
SEVERITY_MARKER = {
    "CRITICAL": "\U0001F6A8",
    "HIGH": "\U0001F6A8",
    "SUSPICIOUS": "\u26A0\uFE0F",
    "LOW": "\u00B7",
    "BENIGN": "\u00B7",
}


class DetectionEngine:
    def __init__(self, config, store):
        self.config = config
        self.store = store
        self.rule_engine = RuleEngine(config)
        self.baseline = RollingBaseline()
        self.anomaly = AnomalyDetector()
        self.query_tracker = SlidingWindowTracker(window_seconds=config.window_seconds)
        self.record_tracker = RecordTypeTracker(window_seconds=config.window_seconds)

    def handle_event(self, raw: dict):
        now = time.time()
        domain = raw["query"]
        reg = registered_domain(domain)

        if raw["direction"] == "response":
            self.record_tracker.record(reg, raw.get("qtype"), raw.get("rcode"), now=now)
            return

        self.query_tracker.record(raw["src_ip"], reg, domain, now=now)
        host_stats = self.query_tracker.host_rate(raw["src_ip"])

        features = build_query_features(domain, self.query_tracker, host_stats)
        features.update(self.record_tracker.stats(reg))

        rule_score, evidence = self.rule_engine.evaluate(features)
        z = self.baseline.update_and_score(f"{raw['src_ip']}::qps", host_stats["queries_per_second"])
        ml_score = self.anomaly.observe_and_score(features)
        verdict = correlate(rule_score, evidence, z, ml_score)

        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "src_ip": raw["src_ip"],
            "dst_ip": raw["dst_ip"],
            "query": domain,
            "transport": raw.get("transport", "udp"),
            "score": verdict.score,
            "severity": verdict.severity,
            "evidence": verdict.evidence,
        }
        self.store.add(entry)
        self._print(entry)
        return entry

    @staticmethod
    def _print(entry: dict):
        color = SEVERITY_COLOR.get(entry["severity"], Fore.WHITE)
        marker = SEVERITY_MARKER.get(entry["severity"], "\u00B7")
        print(
            color + f"[{entry['time']}] {marker} {entry['src_ip']} -> {entry['dst_ip']} "
            f"[{entry['transport']}] {entry['query']}  "
            f"score={entry['score']} ({entry['severity']})" + Style.RESET_ALL
        )
        for ev in entry["evidence"]:
            print(color + f"      - {ev}" + Style.RESET_ALL)
