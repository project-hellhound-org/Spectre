"""
Combines lexical, encoding, and behavioral features into a single feature
dict for a query event. This is the contract between capture and detection.

Note on registered_domain(): this uses a simple last-two-labels heuristic
rather than a full public-suffix-list lookup (e.g. via tldextract). That's
a known simplification — it will misclassify multi-part public suffixes
like "co.uk" (treating "co.uk" itself as if it were the registrable
domain). Acceptable for a first iteration; swap in a PSL-aware library if
false groupings on ccTLD-SLD traffic become a problem in your environment.
"""
from features.lexical import label_stats, char_distribution
from features.encoding import encoding_scores


def registered_domain(fqdn: str) -> str:
    d = fqdn.rstrip(".").lower()
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    return ".".join(parts[-2:])


def build_query_features(domain: str, tracker, host_stats: dict) -> dict:
    feats = label_stats(domain)
    feats.update(char_distribution(feats["leftmost_label"]))
    feats.update(encoding_scores(feats["leftmost_label"]))

    reg_domain = registered_domain(domain)
    feats["registered_domain"] = reg_domain
    feats.update(tracker.domain_stats(reg_domain))
    feats.update(host_stats)
    return feats
