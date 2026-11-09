"""
Layer 1 of the detection pipeline: deterministic, explainable rules.

Each rule contributes a fixed weight (configurable in config.yaml) rather
than being an all-or-nothing verdict on its own — the correlation engine
combines this with statistical and ML signals downstream.
"""
from core.config import DetectionConfig


class RuleEngine:
    def __init__(self, config: DetectionConfig):
        self.cfg = config

    def evaluate(self, features: dict) -> tuple[int, list[str]]:
        # Reverse-DNS lookups are structurally excluded from every lexical
        # rule below — they always have >4 labels by construction, which
        # made Rule 1 fire on 100% of PTR traffic in the original tool.
        if features.get("is_reverse_lookup"):
            return 0, []

        score = 0
        evidence = []
        w = self.cfg.weights

        if features["label_count"] > self.cfg.max_label_count:
            score += w["long_subdomain_chain"]
            evidence.append(
                f"Long subdomain chain: {features['label_count']} labels "
                f"(threshold {self.cfg.max_label_count})"
            )

        if features["leftmost_entropy"] > self.cfg.entropy_threshold:
            score += w["high_entropy_label"]
            evidence.append(
                f"High entropy in leftmost label: {features['leftmost_entropy']:.2f} "
                f"(threshold {self.cfg.entropy_threshold})"
            )

        if (features["fqdn_length"] > self.cfg.max_fqdn_length
                or features["max_label_length"] > self.cfg.max_label_length):
            score += w["long_query_name"]
            evidence.append(
                f"Long query name: {features['fqdn_length']} chars total, "
                f"longest label {features['max_label_length']} chars "
                f"(threshold {self.cfg.max_fqdn_length})"
            )

        if (features.get("unique_subdomain_ratio", 0.0) > self.cfg.unique_ratio_threshold
                and features.get("window_query_count", 0) >= self.cfg.min_queries_for_ratio):
            score += w["high_unique_subdomain_ratio"]
            evidence.append(
                f"High unique-subdomain ratio: {features['unique_subdomain_ratio']:.0%} "
                f"over last {features['window_query_count']} queries"
            )

        if features.get("queries_per_second", 0.0) > self.cfg.qps_threshold:
            score += w["high_query_rate"]
            evidence.append(
                f"High query rate: {features['queries_per_second']:.2f} q/s "
                f"(threshold {self.cfg.qps_threshold})"
            )

        if features.get("txt_ratio", 0.0) > self.cfg.txt_ratio_threshold:
            score += w["txt_heavy"]
            evidence.append(f"TXT-heavy response traffic: {features['txt_ratio']:.0%}")

        if features.get("nxdomain_ratio", 0.0) > self.cfg.nxdomain_ratio_threshold:
            score += w["nxdomain_spike"]
            evidence.append(f"NXDOMAIN spike: {features['nxdomain_ratio']:.0%}")

        enc_scores = {
            "hex": features.get("hex_score", 0.0),
            "base32": features.get("base32_score", 0.0),
            "base64": features.get("base64_score", 0.0),
        }
        if any(enc_scores.values()):
            best = max(enc_scores, key=enc_scores.get)
            score += w["encoding_match"]
            evidence.append(f"Leftmost label matches {best} encoding pattern")

        return score, evidence
