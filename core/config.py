"""
Detection configuration. Every threshold below was previously a hardcoded
magic number scattered across analyzer.py; they now live in one place and
are overridable via config.yaml without touching code.
"""
from dataclasses import dataclass, field

DEFAULT_WEIGHTS = {
    "long_subdomain_chain": 10,
    "high_entropy_label": 20,
    "long_query_name": 15,
    "high_unique_subdomain_ratio": 20,
    "high_query_rate": 10,
    "txt_heavy": 10,
    "nxdomain_spike": 10,
    "encoding_match": 10,
}


@dataclass
class DetectionConfig:
    # Lexical rules
    max_label_count: int = 5
    entropy_threshold: float = 4.2
    max_fqdn_length: int = 50          # was documented in the original report, never implemented
    max_label_length: int = 50

    # Behavioral rules (sliding-window based)
    window_seconds: int = 300
    unique_ratio_threshold: float = 0.85
    min_queries_for_ratio: int = 10
    qps_threshold: float = 5.0

    # Record-type rules
    txt_ratio_threshold: float = 0.5
    nxdomain_ratio_threshold: float = 0.3

    # Rule scoring weights (0-100 scale correlation engine)
    weights: dict = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))


def load_config(path: str = None) -> DetectionConfig:
    """Load order: explicit `path` argument if given, else
    ~/.dnstune/config.yaml (or $DNSTUNE_HOME / $XDG_DATA_HOME override —
    see core/paths.py), else built-in defaults if neither exists."""
    cfg = DetectionConfig()

    if path is None:
        from core.paths import default_config_path
        path = default_config_path()

    try:
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return cfg
    except ImportError:
        return cfg

    for key, value in data.get("detection", {}).items():
        if hasattr(cfg, key) and key != "weights":
            setattr(cfg, key, value)

    if "weights" in data:
        cfg.weights.update(data["weights"])

    return cfg
