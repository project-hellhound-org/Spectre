"""
Packet capture via Scapy's AsyncSniffer.

Changed from the original blocking `sniff()` call to `AsyncSniffer`
specifically to support live target swapping: AsyncSniffer exposes
`.start()`/`.stop()`, so a target change can tear down and rebuild the
capture thread with a new BPF filter without restarting the whole
process (and without losing the dashboard, detection engine, or event
history, none of which live in the capture thread).

Scope matching now happens in two stages:
  1. BPF filter (kernel-level) — only ever narrows by IP/port, per
     TargetScope.bpf_clause(). Empty for a domain-only scope.
  2. Python-level check in _handle(), after the qname is parsed — this is
     the only place a domain-scoped target can actually be matched,
     since BPF has no visibility into DNS payload content.

Requires elevated privileges to open a raw socket.
"""
import threading

from scapy.sendrecv import AsyncSniffer
from scapy.layers.dns import DNS
from scapy.layers.inet import IP

QTYPE_MAP = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 12: "PTR", 33: "SRV"}
RCODE_MAP = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


class ScapyCollector:
    def __init__(self, on_event, target_scope, interface=None):
        self.on_event = on_event
        self.target_scope = target_scope
        self.interface = interface
        self._sniffer = None
        self._lock = threading.RLock()

    def bpf_filter(self) -> str:
        # Port clause MUST stay grouped as one unit before 'and': BPF's
        # 'and' binds tighter than 'or', so an unwrapped
        # "(udp port 53) or (tcp port 53) and (host X)" would parse as
        # "(udp port 53) or ((tcp port 53) and (host X))" — silently
        # capturing ALL udp/53 traffic regardless of target.
        base = "((udp port 53) or (tcp port 53))"
        clause = self.target_scope.bpf_clause()
        return f"{base} and {clause}" if clause else base

    def _handle(self, packet):
        if not packet.haslayer(DNS) or not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        dns_layer = packet[DNS]

        if dns_layer.qd is None:
            return

        qname = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")

        if not self.target_scope.matches(ips=[ip_layer.src, ip_layer.dst], domain=qname):
            return

        transport = "tcp" if packet.haslayer("TCP") else "udp"
        qtype = QTYPE_MAP.get(dns_layer.qd.qtype, str(dns_layer.qd.qtype))

        if dns_layer.qr == 0:
            self.on_event({
                "direction": "query",
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "query": qname,
                "qtype": qtype,
                "transport": transport,
            })
        else:
            rcode = RCODE_MAP.get(dns_layer.rcode, str(dns_layer.rcode))
            self.on_event({
                "direction": "response",
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "query": qname,
                "qtype": qtype,
                "rcode": rcode,
                "transport": transport,
            })

    def start(self):
        with self._lock:
            if self._sniffer is not None:
                return  # already running
            bpf = self.bpf_filter()
            print(f"[collector] interface={self.interface or 'default'} scope={self.target_scope.describe()}")
            print(f"[collector] BPF filter: {bpf}")
            self._sniffer = AsyncSniffer(filter=bpf, iface=self.interface, store=False, prn=self._handle)
            self._sniffer.start()

    def stop(self):
        with self._lock:
            if self._sniffer is not None:
                self._sniffer.stop()
                self._sniffer = None

    def is_running(self) -> bool:
        with self._lock:
            return self._sniffer is not None

    def swap_target(self, new_scope):
        """Stop capture, replace the scope in place (so anything else
        holding a reference — the dashboard — sees it immediately), and
        restart with the new BPF filter. The detection engine, event
        store, and dashboard are untouched."""
        with self._lock:
            was_running = self.is_running()
            if was_running:
                self.stop()
            self.target_scope.replace_with(new_scope)
            if was_running:
                self.start()
