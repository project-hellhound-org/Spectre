from core.config import DetectionConfig
from detection.rules import RuleEngine
from features.aggregator import build_query_features, registered_domain
from features.frequency import SlidingWindowTracker


def make_engine():
    return RuleEngine(DetectionConfig()), SlidingWindowTracker(window_seconds=300)


def eval_query(query, engine, tracker, host="10.0.0.5"):
    reg = registered_domain(query)
    tracker.record(host, reg, query)
    features = build_query_features(query, tracker, {"queries_per_second": 0.0})
    return engine.evaluate(features)


def test_ptr_lookup_no_longer_flagged():
    """Regression test for the confirmed false positive: this exact query
    appeared flagged in the original tool's shipped logs.json."""
    engine, tracker = make_engine()
    score, evidence = eval_query("252.168.168.192.in-addr.arpa.", engine, tracker)
    assert score == 0
    assert evidence == []


def test_benign_query_not_flagged():
    engine, tracker = make_engine()
    score, evidence = eval_query("www.google.com", engine, tracker)
    assert score == 0


def test_long_high_entropy_label_flagged():
    engine, tracker = make_engine()
    score, evidence = eval_query(
        "xK9pQ7vN3mR2sT8wY1zA4bC6dE0fGhJkL5.example.com", engine, tracker
    )
    assert score > 0
    assert any("entropy" in e.lower() for e in evidence)


def test_long_subdomain_chain_flagged_for_non_ptr():
    engine, tracker = make_engine()
    score, evidence = eval_query("a.b.c.d.e.f.example.com", engine, tracker)
    assert score > 0
    assert any("subdomain chain" in e.lower() for e in evidence)


def test_length_rule_catches_long_low_entropy_label():
    """The original tool had no length rule at all, so a long but
    low-entropy (repetitive) label passed both existing checks undetected.
    This is the length rule the report described but never implemented."""
    engine, tracker = make_engine()
    padded = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"
    score, evidence = eval_query(padded, engine, tracker)
    assert score > 0
    assert any("long query name" in e.lower() for e in evidence)
