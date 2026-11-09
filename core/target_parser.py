"""
Target string parsing.

This module exists because of a real crash: passing a full URL
(`https://fitgirl-repacks.site/`) into `--target-host` fed the literal
string straight into a BPF `host` clause, which cannot parse a URL and
failed to compile, killing the sniffer thread while the dashboard kept
running with no data.

Root cause: the tool had no concept of "target" other than "a literal IP
or CIDR to push into BPF." A hostname, FQDN, or URL is a different kind
of target entirely, and needs different handling:

  - An IP or CIDR narrows capture at the kernel level via BPF — cheap,
    correct, well-defined.
  - A domain (hostname/FQDN/URL) CANNOT be pushed into BPF at all,
    because BPF filters packet headers (IP/port/protocol), not DNS
    payload content. A domain target has to be matched against the
    query name (qname) of each DNS packet in Python, after capture.

    Worth being explicit about why resolving the domain to an IP and
    using THAT as a BPF host filter would be actively wrong here: DNS
    queries for "sub.example.com" are sent by the client to its
    configured resolver (e.g. the router or 8.8.8.8) — NOT to
    example.com's own web-server IP. Filtering on example.com's
    resolved IP would filter OUT exactly the query/response packets
    you're trying to observe.

So this module classifies the input; the caller (core/target.py's
TargetScope) routes IP/CIDR into the BPF-eligible host/network scope,
and everything else into the domain scope, which is matched at the
application layer against parsed qnames instead.
"""
import ipaddress
from urllib.parse import urlsplit


def parse_target(raw: str):
    """Classify a single target string.

    Returns a ("host" | "net" | "domain", value) tuple.
    Raises ValueError if the string can't be parsed as any of the three.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")

    if raw.lower() in ("all", "*", "any"):
        return "all", None

    # CIDR network, e.g. "10.0.0.0/24" — but don't let a URL with a path
    # segment containing "/" fall into this branch.
    if "/" in raw and "://" not in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return "net", raw
        except ValueError:
            pass

    # Bare IP address
    try:
        ipaddress.ip_address(raw)
        return "host", raw
    except ValueError:
        pass

    # Anything else: hostname, FQDN, or full URL. Prepend "//" if there's
    # no scheme so urlsplit parses it into .hostname correctly either way
    # ("example.com" and "https://example.com/x" both resolve cleanly).
    candidate = raw if "://" in raw else "//" + raw
    parsed = urlsplit(candidate)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError(f"could not parse '{raw}' as an IP, CIDR, or domain/URL")

    return "domain", hostname.lower().rstrip(".")


def build_scope(raw_targets):
    """Parse a list of raw target strings into the kwargs for TargetScope."""
    hosts, networks, domains = [], [], []
    for raw in raw_targets:
        kind, value = parse_target(raw)
        if kind == "all":
            continue  # "all"/"*" clears scope; caller handles the empty-list case
        elif kind == "host":
            hosts.append(value)
        elif kind == "net":
            networks.append(value)
        elif kind == "domain":
            domains.append(value)
    return {"hosts": hosts, "networks": networks, "domains": domains}
