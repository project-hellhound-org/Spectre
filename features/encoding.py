"""
Encoding-pattern heuristics. A label matching one of these character sets
doesn't prove tunneling by itself (plenty of legitimate identifiers happen
to be hex or base64url), but it's a useful contributing signal for the
correlation engine — matches contribute a modest score rather than an
automatic flag.
"""
import re

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+=*$")

MIN_ENCODED_LENGTH = 8  # short labels match these patterns too often by chance


def encoding_scores(label: str) -> dict:
    if not label or len(label) < MIN_ENCODED_LENGTH:
        return {"hex_score": 0.0, "base32_score": 0.0, "base64_score": 0.0}

    return {
        "hex_score": 1.0 if _HEX_RE.match(label) else 0.0,
        "base32_score": 1.0 if _BASE32_RE.match(label) else 0.0,
        "base64_score": 1.0 if (_BASE64_RE.match(label) or _BASE64URL_RE.match(label)) else 0.0,
    }
