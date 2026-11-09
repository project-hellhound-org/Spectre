"""
Loggings.py — a dedicated portal for viewing historical and real-time
detection logs, separate from the main dashboard.

Two ways to run it:

  1. Standalone, in its own terminal, whether or not `dnstune` is
     currently running elsewhere:
         python3 Loggings.py                    # follow live
         python3 Loggings.py --no-follow --limit 50
         python3 Loggings.py --severity HIGH

     Standalone mode re-reads ~/.dnstune/logs.json from disk on every
     poll, since a separate process can't see another process's
     in-memory state.

  2. In-process, via the `logs` command inside dnstune's own REPL
     (see main.py) — that path calls run_from_store() directly against
     the live, shared EventStore for zero-lag updates, no file I/O.

Also installed as the `dnstune-logs` global command (see pyproject.toml).
"""
import argparse
import json
import time

from colorama import Fore, Style, init as colorama_init

from core.paths import default_log_path

colorama_init(autoreset=True)

SEVERITY_ORDER = ["BENIGN", "LOW", "SUSPICIOUS", "HIGH", "CRITICAL"]
SEVERITY_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "SUSPICIOUS": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "BENIGN": Fore.WHITE,
}
CLEAR_AND_HOME = "\033[2J\033[H"


def read_events_from_file(path: str) -> list:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def filter_events(events: list, min_severity: str = None, limit: int = None) -> list:
    if min_severity and min_severity in SEVERITY_ORDER:
        floor = SEVERITY_ORDER.index(min_severity)
        events = [e for e in events if SEVERITY_ORDER.index(e.get("severity", "BENIGN")) >= floor]
    if limit:
        events = events[-limit:]
    return events


def render(events: list, clear_screen: bool = True, max_shown: int = 200):
    out = [CLEAR_AND_HOME] if clear_screen else []
    out.append(Fore.RED + Style.BRIGHT + "=== DNS TUNNEL DETECTOR \u2014 LOG VIEWER ===" + Style.RESET_ALL)
    out.append(Fore.WHITE + f"{len(events)} matching events \u00b7 Ctrl+C to exit" + Style.RESET_ALL)
    out.append("-" * 78)

    if not events:
        out.append(Fore.WHITE + "(no matching events yet)" + Style.RESET_ALL)

    for e in events[-max_shown:]:
        color = SEVERITY_COLOR.get(e.get("severity", "BENIGN"), Fore.WHITE)
        out.append(
            color + f"[{e.get('time', '?')}] {e.get('src_ip', '?')} -> {e.get('dst_ip', '?')} "
            f"[{e.get('transport', 'udp')}] {e.get('query', '?')}  "
            f"score={e.get('score', '?')} ({e.get('severity', '?')})" + Style.RESET_ALL
        )
        for ev in e.get("evidence", []):
            out.append(color + f"      - {ev}" + Style.RESET_ALL)

    print("\n".join(out))


def run_standalone(source: str, severity: str, limit: int, follow: bool, interval: float):
    print(f"Reading from: {source}")
    try:
        while True:
            events = filter_events(read_events_from_file(source), severity, limit)
            render(events)
            if not follow:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print(Style.RESET_ALL + "\nExiting log viewer.")


def run_from_store(store, min_severity: str = None, interval: float = 2.0):
    """In-process viewer for dnstune's own REPL — reads the live
    EventStore directly rather than re-reading a file."""
    try:
        while True:
            events = filter_events(store.all(), min_severity, None)
            render(events)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(Style.RESET_ALL + "\nReturning to dnstune console.")


def parse_args():
    p = argparse.ArgumentParser(description="DNS Tunnel Detector — standalone log viewer")
    p.add_argument("--source", default=None, help="Path to logs.json (default: ~/.dnstune/logs.json)")
    p.add_argument("--severity", choices=SEVERITY_ORDER, default=None, help="Only show this severity and above")
    p.add_argument("--limit", type=int, default=None, help="Only show the N most recent matching entries")
    p.add_argument("--interval", type=float, default=2.0, help="Refresh interval in seconds (follow mode)")
    p.add_argument("--no-follow", dest="follow", action="store_false", help="Print once and exit instead of polling")
    return p.parse_args()


def main():
    args = parse_args()
    source = args.source or default_log_path()
    run_standalone(source, args.severity, args.limit, args.follow, args.interval)


if __name__ == "__main__":
    main()
