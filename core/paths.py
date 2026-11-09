"""
Resolves where dnstune keeps its persistent files (logs, config) on disk.

This didn't matter when the tool was only ever run as `python3 main.py`
from inside its own project directory — "logs/logs.json" and
"config.yaml" were reliably relative to that directory. Now that it's
installed as a global `dnstune` command runnable from anywhere, a
CWD-relative path would scatter a new logs/ folder into whatever
directory the user happened to be standing in when they typed the
command. Everything now lives under one stable, predictable location
instead.
"""
import os

_ENV_OVERRIDE = "DNSTUNE_HOME"


def data_dir() -> str:
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        path = override
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = xdg if xdg else os.path.join(os.path.expanduser("~"), ".dnstune")
        path = base if xdg is None else os.path.join(xdg, "dnstune")
    os.makedirs(path, exist_ok=True)
    return path


def default_log_path() -> str:
    return os.path.join(data_dir(), "logs.json")


def default_config_path() -> str:
    return os.path.join(data_dir(), "config.yaml")
