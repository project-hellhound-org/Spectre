from core.target import TargetScope
from core.target_parser import parse_target, build_scope
from collector.scapy_collector import ScapyCollector


# ---------- TargetScope: IP matching ----------

def test_unrestricted_scope_matches_everything():
    scope = TargetScope()
    assert scope.matches(ips=["10.0.0.5"])
    assert scope.bpf_clause() == ""


def test_host_scope_matching():
    scope = TargetScope(hosts=["10.0.0.99"])
    assert scope.matches(ips=["10.0.0.99"])
    assert not scope.matches(ips=["10.0.0.5"])


def test_cidr_scope_matching():
    scope = TargetScope(networks=["10.0.0.0/24"])
    assert scope.matches(ips=["10.0.0.200"])
    assert not scope.matches(ips=["192.168.1.5"])


def test_invalid_cidr_rejected():
    try:
        TargetScope(networks=["not-a-cidr"])
        assert False, "expected ValueError"
    except ValueError:
        pass


# ---------- TargetScope: domain matching ----------

def test_domain_scope_matches_exact_and_subdomains():
    scope = TargetScope(domains=["fitgirl-repacks.site"])
    assert scope.matches(domain="fitgirl-repacks.site")
    assert scope.matches(domain="sub.fitgirl-repacks.site")
    assert scope.matches(domain="data.exfil.fitgirl-repacks.site")
    assert not scope.matches(domain="fitgirl-repacks.site.evil.com")
    assert not scope.matches(domain="notfitgirl-repacks.site")


def test_domain_scope_has_no_bpf_clause():
    """Domain matching can't be expressed in BPF (it requires inspecting
    DNS payload content, not packet headers) — a domain-only scope must
    NOT narrow the BPF filter at all, or DNS traffic to the resolver
    (which is what actually needs to be seen) gets filtered out."""
    scope = TargetScope(domains=["fitgirl-repacks.site"])
    assert scope.bpf_clause() == ""


def test_mixed_ip_and_domain_scope_is_or_not_and():
    scope = TargetScope(hosts=["8.8.8.8"], domains=["fitgirl-repacks.site"])
    assert scope.matches(ips=["8.8.8.8"], domain="unrelated.com")
    assert scope.matches(ips=["1.2.3.4"], domain="fitgirl-repacks.site")
    assert not scope.matches(ips=["1.2.3.4"], domain="unrelated.com")


# ---------- Regression test for the reported crash ----------

def test_url_target_no_longer_crashes_the_bpf_filter():
    """This is the exact input that crashed the sniffer thread:
    `dnstune --target-host https://fitgirl-repacks.site/` fed the literal
    URL string into a BPF 'host' clause, which failed to compile. The
    fix routes non-IP targets into the domain scope instead, which
    produces no BPF host clause at all (see test above) — so the filter
    stays valid regardless of what kind of target is configured."""
    kind, value = parse_target("https://fitgirl-repacks.site/")
    assert kind == "domain"
    assert value == "fitgirl-repacks.site"

    scope_kwargs = build_scope(["https://fitgirl-repacks.site/"])
    scope = TargetScope(**scope_kwargs)
    collector = ScapyCollector(on_event=lambda e: None, target_scope=scope)

    bpf = collector.bpf_filter()
    assert "https" not in bpf
    assert "fitgirl-repacks.site" not in bpf  # not BPF-expressible; must not appear here
    assert bpf == "((udp port 53) or (tcp port 53))"  # falls back to port-only, still valid BPF


# ---------- parse_target coverage ----------

def test_parse_target_ip():
    assert parse_target("10.0.0.5") == ("host", "10.0.0.5")


def test_parse_target_cidr():
    assert parse_target("10.0.0.0/24") == ("net", "10.0.0.0/24")


def test_parse_target_bare_hostname():
    assert parse_target("fitgirl-repacks.site") == ("domain", "fitgirl-repacks.site")


def test_parse_target_url_with_path_and_scheme():
    assert parse_target("https://fitgirl-repacks.site/some/path") == ("domain", "fitgirl-repacks.site")


def test_parse_target_url_with_port():
    assert parse_target("https://sub.example.com:8443/x") == ("domain", "sub.example.com")


def test_parse_target_all_keyword():
    assert parse_target("all")[0] == "all"
    assert parse_target("*")[0] == "all"


def test_parse_target_empty_raises():
    try:
        parse_target("   ")
        assert False, "expected ValueError"
    except ValueError:
        pass


# ---------- BPF filter construction (host/net scope) ----------

def test_bpf_filter_correctly_scopes_port_clause():
    """Regression test for a precedence bug found during review: BPF's
    'and' binds tighter than 'or', so a port clause joined with a target
    clause via a bare 'and' parses wrong unless the port clause is
    explicitly grouped first."""
    scope = TargetScope(hosts=["10.0.0.99"])
    collector = ScapyCollector(on_event=lambda e: None, target_scope=scope)
    bpf = collector.bpf_filter()
    assert bpf == "((udp port 53) or (tcp port 53)) and (host 10.0.0.99)"
    assert bpf.startswith("((udp port 53) or (tcp port 53))")


def test_bpf_filter_unrestricted_has_no_dangling_and():
    collector = ScapyCollector(on_event=lambda e: None, target_scope=TargetScope())
    assert collector.bpf_filter() == "((udp port 53) or (tcp port 53))"


# ---------- swap_target / replace_with ----------

def test_replace_with_mutates_in_place():
    """The dashboard and collector both hold a reference to the SAME
    TargetScope object; swap must mutate it in place rather than
    rebinding a new object, or one of those references would go stale."""
    scope = TargetScope(hosts=["10.0.0.5"])
    held_reference = scope  # simulates the dashboard's reference

    new_scope = TargetScope(domains=["fitgirl-repacks.site"])
    scope.replace_with(new_scope)

    assert held_reference.matches(domain="fitgirl-repacks.site")
    assert not held_reference.matches(ips=["10.0.0.5"])
    assert held_reference is scope  # same object, contents swapped
