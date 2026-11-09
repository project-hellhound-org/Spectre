"""
Target scope: what this detector instance is authorized/configured to
monitor. Two independent kinds of restriction, because they're matched
at two different layers:

  - IP scope (hosts / networks): BPF-eligible, narrows capture at the
    kernel level.
  - Domain scope: NOT BPF-eligible (BPF can't inspect DNS payload
    content) — matched against each packet's parsed query name in
    Python, after capture. See core/target_parser.py for why resolving
    a domain to an IP and using that for BPF would be wrong here.

An unrestricted scope (nothing configured) matches everything, preserving
the original "monitor the whole segment" behavior.
"""
import ipaddress
import threading


class TargetScope:
    def __init__(self, hosts=None, networks=None, domains=None):
        self.hosts = set(hosts or [])
        self.networks = []
        for n in (networks or []):
            try:
                self.networks.append(ipaddress.ip_network(n, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid target network '{n}': {exc}") from exc
        self.domains = {self._normalize_domain(d) for d in (domains or [])}
        self._lock = threading.RLock()

    @staticmethod
    def _normalize_domain(d: str) -> str:
        return d.lower().rstrip(".")

    @property
    def has_ip_scope(self) -> bool:
        with self._lock:
            return bool(self.hosts or self.networks)

    @property
    def has_domain_scope(self) -> bool:
        with self._lock:
            return bool(self.domains)

    @property
    def is_restricted(self) -> bool:
        return self.has_ip_scope or self.has_domain_scope

    def _ip_matches(self, ip: str) -> bool:
        if ip in self.hosts:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)

    def _domain_matches(self, domain: str) -> bool:
        d = self._normalize_domain(domain)
        for target in self.domains:
            if d == target or d.endswith("." + target):
                return True
        return False

    def matches(self, ips=(), domain: str = None) -> bool:
        """True if any given IP falls in the IP scope, OR the domain falls
        in the domain scope. True unconditionally if scope is unrestricted."""
        with self._lock:
            if not self.is_restricted:
                return True
            if self.has_ip_scope and any(self._ip_matches(ip) for ip in ips if ip):
                return True
            if self.has_domain_scope and domain and self._domain_matches(domain):
                return True
            return False

    def bpf_clause(self) -> str:
        """IP-level BPF clause only. Returns '' if there's no IP-level
        restriction — including when a domain-only restriction is
        configured, since domain matching can't be expressed in BPF and
        is instead applied in Python after capture."""
        with self._lock:
            if not self.has_ip_scope:
                return ""
            clauses = [f"host {h}" for h in sorted(self.hosts)]
            clauses += [f"net {n}" for n in self.networks]
            return "(" + " or ".join(clauses) + ")"

    def describe(self) -> str:
        with self._lock:
            parts = sorted(self.hosts) + [str(n) for n in self.networks]
            parts += [f"*.{d}" for d in sorted(self.domains)]
            return ", ".join(parts) if parts else "unrestricted (monitoring all visible traffic)"

    def replace_with(self, other: "TargetScope"):
        """In-place swap so any object already holding a reference to this
        TargetScope (the dashboard, the collector) sees the new scope
        immediately without needing to be handed a new object."""
        with self._lock:
            self.hosts = other.hosts
            self.networks = other.networks
            self.domains = other.domains
