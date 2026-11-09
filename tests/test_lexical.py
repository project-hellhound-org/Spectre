from features.lexical import shannon_entropy, is_reverse_lookup, label_stats


def test_reverse_lookup_detected():
    assert is_reverse_lookup("252.168.168.192.in-addr.arpa.")
    assert is_reverse_lookup("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.")
    assert not is_reverse_lookup("www.google.com")


def test_entropy_is_case_sensitive():
    """Regression test for the case-folding bug. Uses a realistic base64
    chunk that contains genuine case collisions (e.g. both 'a' and 'A'
    appear) — lowercasing merges those into one symbol and measurably
    reduces character diversity, which is exactly the signal loss that
    made the original tool under-score real base64 tunneling payloads.
    (A string with no case collisions at all would score identically
    either way, so the test fixture matters here.)"""
    mixed = "TWFuSXNEaXN0aW5ndWlzaGVk"
    lowered = mixed.lower()
    assert shannon_entropy(mixed) > shannon_entropy(lowered)


def test_entropy_empty_string_no_crash():
    assert shannon_entropy("") == 0.0


def test_label_stats_flags_reverse_lookup():
    stats = label_stats("252.168.168.192.in-addr.arpa.")
    assert stats["is_reverse_lookup"] is True
    assert stats["label_count"] == 6  # still counted; exemption happens in the rule engine
