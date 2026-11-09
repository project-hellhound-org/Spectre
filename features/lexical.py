"""
Lexical feature extraction: length, label structure, entropy, character
distribution.

Two bug fixes from the original analyzer.py live here:

1. Entropy is now computed WITHOUT lowercasing first. Base64/Base32
   encodings rely on mixed-case alphabets for information density;
   folding case before scoring measurably suppresses the entropy signal
   for exactly the payload style DNS tunneling tools actually use.

2. Reverse-DNS lookups (*.in-addr.arpa, *.ip6.arpa) are explicitly
   identified so the rule engine can exempt them from the subdomain-count
   rule. PTR queries always exceed 5 labels by construction (4 octets +
   in-addr.arpa), which was producing guaranteed false positives.
"""
import math

REVERSE_LOOKUP_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")


def is_reverse_lookup(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return d.endswith(REVERSE_LOOKUP_SUFFIXES)


def shannon_entropy(s: str) -> float:
    """Case-sensitive Shannon entropy in bits per character."""
    if not s:
        return 0.0
    length = len(s)
    probs = (s.count(c) / length for c in set(s))
    return -sum(p * math.log2(p) for p in probs)


def label_stats(domain: str) -> dict:
    d = domain.rstrip(".")
    labels = d.split(".") if d else [""]
    label_entropies = [shannon_entropy(l) for l in labels]

    return {
        "domain": d,
        "fqdn_length": len(d),
        "label_count": len(labels),
        "max_label_length": max((len(l) for l in labels), default=0),
        "avg_label_length": (sum(len(l) for l in labels) / len(labels)) if labels else 0.0,
        "leftmost_label": labels[0] if labels else "",
        "leftmost_entropy": label_entropies[0] if label_entropies else 0.0,
        "entropy_mean": (sum(label_entropies) / len(label_entropies)) if label_entropies else 0.0,
        "entropy_max": max(label_entropies, default=0.0),
        "is_reverse_lookup": is_reverse_lookup(d),
    }


def char_distribution(label: str) -> dict:
    if not label:
        return {"digit_ratio": 0.0, "alpha_ratio": 0.0, "special_ratio": 0.0}
    n = len(label)
    digits = sum(c.isdigit() for c in label)
    alpha = sum(c.isalpha() for c in label)
    special = n - digits - alpha
    return {
        "digit_ratio": digits / n,
        "alpha_ratio": alpha / n,
        "special_ratio": special / n,
    }
