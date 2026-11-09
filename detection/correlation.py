"""
Correlation engine: combines rule score, statistical z-score, and ML
anomaly score into one explainable 0-100 risk verdict with an evidence
trail — never a bare "TUNNEL DETECTED", always the reasons behind it.
"""
from dataclasses import dataclass

SEVERITY_BANDS = (
    (85, "CRITICAL"),
    (70, "HIGH"),
    (50, "SUSPICIOUS"),
    (25, "LOW"),
    (0, "BENIGN"),
)


def classify(score: int) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "BENIGN"


@dataclass
class Verdict:
    score: int
    severity: str
    evidence: list


def correlate(rule_score: int, rule_evidence: list, z_score: float, ml_anomaly: float) -> Verdict:
    score = rule_score
    evidence = list(rule_evidence)

    if z_score > 3:
        score += 15
        evidence.append(f"Query rate {z_score:.1f}\u03c3 above this host's own baseline")
    elif z_score > 2:
        score += 8
        evidence.append(f"Query rate {z_score:.1f}\u03c3 above this host's own baseline")

    if ml_anomaly > 0.7:
        score += 20
        evidence.append(f"ML anomaly score {ml_anomaly:.2f} (isolation forest)")
    elif ml_anomaly > 0.5:
        score += 10
        evidence.append(f"ML anomaly score {ml_anomaly:.2f} (isolation forest)")

    score = max(0, min(100, score))
    return Verdict(score=score, severity=classify(score), evidence=evidence)
