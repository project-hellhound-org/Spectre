"""
DNS Tunnel Detector — CLI entry point (installed globally as `dnstune`,
see pyproject.toml).

Flow: self-elevate to root if needed (raw sockets require it) -> resolve
a target (from flags, or an interactive prompt if none given) -> start
capture + dashboard as background threads in ONE process -> open the
dashboard in the browser -> drop into an interactive REPL for
`swap` / `status` / `logs` / `quit`, so the dashboard keeps running and
stays reachable in the browser independent of what the REPL is doing.

For running fully detached from the terminal (surviving the shell that
launched it), use `--no-repl` with standard Unix backgrounding, e.g.:
    nohup dnstune --target fitgirl-repacks.site --no-repl > dnstune.log 2>&1 &
or install the systemd unit described in README.md. This tool doesn't
implement its own daemonization (double-fork/detach) — that's what the
OS's own tooling is for, and reinventing it would be a lot of surface
area for something `nohup`/`systemd` already do correctly.
"""
import argparse
import os
import sys
import threading
import webbrowser

from core.config import load_config
from core.target import TargetScope
from core.target_parser import build_scope, parse_target
from storage.json_store import EventStore
from detection.engine import DetectionEngine
from collector.scapy_collector import ScapyCollector
from dashboard.app import create_app

BANNER = r"""
 ______  _   _  _____   _____                       _
 |  _  \| \ | |/  ___| |_   _|                     | |
 | | | ||  \| |\ `--.    | |_   _ _ __  _ __   ___ | |
 | | | || . ` | `--. \   | | | | | '_ \| '_ \ / _ \| |
 | |/ / | |\  |/\__/ /   | | |_| | | | | | | |  __/| |
 |___/  \_| \_/\____/    \_/\__,_|_| |_|_| |_|\___||_|
"""


def parse_args():
    p = argparse.ArgumentParser(description="DNS Tunnel Detector")
    p.add_argument("targets", nargs="*", help="Target(s): IP, CIDR, hostname, or URL. Prompted if omitted.")
    p.add_argument("--target-host", action="append", default=[], help=argparse.SUPPRESS)  # back-compat
    p.add_argument("--target-net", action="append", default=[], help=argparse.SUPPRESS)    # back-compat
    p.add_argument("--interface", default=None, help="Network interface to sniff on")
    p.add_argument("--config", default=None, help="Path to config.yaml (default: ~/.dnstune/config.yaml)")
    p.add_argument("--port", type=int, default=5000, help="Dashboard port")
    p.add_argument("--no-browser", action="store_true", help="Don't auto-open the dashboard in a browser")
    p.add_argument("--no-repl", action="store_true",
                    help="Skip the interactive console after startup (for use with nohup/systemd)")
    p.add_argument("--no-elevate", action="store_true",
                    help="Don't attempt to self-elevate via sudo even if not running as root")
    p.add_argument("--self-test", action="store_true",
                    help="Run the built-in detection self-test against sample queries and exit")
    return p.parse_args()


def ensure_privileges(no_elevate: bool):
    """Raw packet capture needs CAP_NET_RAW. Re-exec via sudo instead of
    making the user type it themselves, unless explicitly disabled."""
    if no_elevate or os.name != "posix":
        return
    if os.geteuid() == 0:
        return
    print("[dnstune] Raw packet capture requires root — re-executing with sudo...")
    try:
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)
    except FileNotFoundError:
        print("[dnstune] 'sudo' not found on this system. Please re-run as root manually.")
        sys.exit(1)


def resolve_targets(args) -> list:
    """Collect target strings from positional args + legacy flags, or
    prompt interactively if none were given at all."""
    raw = list(args.targets) + list(args.target_host) + list(args.target_net)
    if raw:
        return raw

    print("No target specified.")
    entry = input("Enter target — IP, CIDR, hostname, or URL (or 'all' to monitor everything): ").strip()
    return [entry] if entry else []


def build_scope_or_exit(raw_targets: list) -> TargetScope:
    try:
        kwargs = build_scope(raw_targets)
    except ValueError as exc:
        print(f"[dnstune] {exc}")
        sys.exit(1)
    return TargetScope(**kwargs)


def run_self_test(config):
    from features.aggregator import build_query_features, registered_domain
    from features.frequency import SlidingWindowTracker
    from detection.rules import RuleEngine

    tracker = SlidingWindowTracker(window_seconds=config.window_seconds)
    rule_engine = RuleEngine(config)

    samples = [
        ("a.b.c.d.e.f.example.com", "long subdomain chain"),
        ("xF3sdK9Lk20SdN4slKv0.example.com", "mixed-case payload, moderate entropy"),
        ("abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789.example.com", "long label"),
        ("www.google.com", "benign"),
        ("c3VwZXJzZWNyZXRwYXlsb2FkLmV4YW1wbGUuY29t", "base64-style single label"),
        ("chunk001.chunk002.chunk003.data.exfil.tunnel.com", "tunneling-style chunking"),
        ("252.168.168.192.in-addr.arpa.", "legitimate PTR lookup — must NOT flag"),
    ]

    print("=== DNS Tunnel Detector — Self-Test ===\n")
    for query, note in samples:
        reg = registered_domain(query)
        tracker.record("127.0.0.1", reg, query)
        features = build_query_features(query, tracker, {"queries_per_second": 0.0})
        score, evidence = rule_engine.evaluate(features)

        print(f"Query : {query}")
        print(f"Note  : {note}")
        print(f"Score : {score}")
        for e in evidence:
            print(f"   - {e}")
        if not evidence:
            print("   (no rule flags)")
        print("-" * 70)

    print("\n=== Target parser checks ===")
    for sample in ["https://fitgirl-repacks.site/", "fitgirl-repacks.site", "10.0.0.5", "10.0.0.0/24"]:
        kind, value = parse_target(sample)
        print(f"  {sample!r:35s} -> ({kind}, {value!r})")


def print_help():
    print(
        "\nCommands:\n"
        "  swap <target>[,<target2>,...]   Change target(s) without restarting (or 'swap all')\n"
        "  status                          Show current scope, capture state, and event counts\n"
        "  logs                            Open the live log viewer (Ctrl+C to return here)\n"
        "  help                            Show this message\n"
        "  quit / exit                     Stop capture and exit\n"
    )


def run_repl(store, collector, port):
    print_help()
    while True:
        try:
            raw = input("dnstune> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue

        cmd, _, rest = raw.partition(" ")
        cmd = cmd.lower()

        if cmd in ("quit", "exit"):
            break

        elif cmd == "help":
            print_help()

        elif cmd == "status":
            summary = store.summary()
            print(f"  Scope     : {collector.target_scope.describe()}")
            print(f"  Capturing : {'yes' if collector.is_running() else 'no'}")
            print(f"  Dashboard : http://127.0.0.1:{port}")
            print(f"  Events    : " + ", ".join(f"{k}={v}" for k, v in summary.items()))

        elif cmd == "swap":
            targets_raw = rest.strip()
            if not targets_raw:
                print("  Usage: swap <target>[,<target2>,...]  or  swap all")
                continue
            raw_targets = [] if targets_raw.lower() == "all" else [t.strip() for t in targets_raw.split(",") if t.strip()]
            try:
                new_scope = build_scope_or_exit(raw_targets) if raw_targets else TargetScope()
            except SystemExit:
                continue
            collector.swap_target(new_scope)
            print(f"  Now monitoring: {collector.target_scope.describe()}")

        elif cmd == "logs":
            import Loggings
            print("  (entering log viewer — Ctrl+C to return)")
            Loggings.run_from_store(store)

        else:
            print(f"  Unknown command: {cmd!r}. Type 'help' for a list of commands.")

    print("[dnstune] Stopping capture...")
    collector.stop()


def main():
    args = parse_args()
    config = load_config(args.config)

    if args.self_test:
        run_self_test(config)
        return

    ensure_privileges(args.no_elevate)

    print(BANNER)

    raw_targets = resolve_targets(args)
    scope = build_scope_or_exit(raw_targets)

    store = EventStore()
    engine = DetectionEngine(config, store)
    collector = ScapyCollector(on_event=engine.handle_event, target_scope=scope, interface=args.interface)
    collector.start()

    app = create_app(store, collector)
    dashboard_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False),
        daemon=True,
    )
    dashboard_thread.start()

    url = f"http://127.0.0.1:{args.port}"
    print(f"[*] Dashboard: {url}")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass  # headless environment or no browser available — the URL is printed either way

    if args.no_repl:
        print("[*] Running headless (--no-repl). Ctrl+C to stop.")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        collector.stop()
        return

    run_repl(store, collector, args.port)


if __name__ == "__main__":
    main()
