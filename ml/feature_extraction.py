"""Hostname-only feature extraction, shared by training and (later) the FastAPI backend.

Only the hostname is used. PhiUSIIL's legitimate URLs are all https homepages starting
with 'www.', so scheme, path and 'www.' would teach dataset shortcuts (docs/DATA_DICTIONARY.md).
No network access: the Public Suffix List snapshot bundled with tldextract is used.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline, deterministic

SUSPICIOUS_HOST_WORDS = ("login", "signin", "verify", "secure", "account", "update", "support",
                         "billing", "wallet", "auth", "confirm", "webscr", "recovery", "unlock")
SHARED_HOSTING_SUFFIXES = ("firebaseapp.com", "web.app", "github.io", "netlify.app", "vercel.app",
                           "pages.dev", "workers.dev", "herokuapp.com", "blogspot.com", "wixsite.com",
                           "weebly.com", "000webhostapp.com", "ipfs.io", "glitch.me", "repl.co",
                           "azurewebsites.net", "appspot.com", "r2.dev", "webflow.io", "square.site")
VOWELS = set("aeiou")

FEATURE_NAMES = [
    "host_length", "num_labels", "num_dots", "num_hyphens", "num_digits", "digit_ratio",
    "num_special_chars", "longest_label_length", "avg_label_length", "num_numeric_labels",
    "registered_domain_length", "subdomain_count", "subdomain_length", "tld_length",
    "host_entropy", "max_consonant_run", "vowel_ratio", "is_ip", "has_punycode",
    "suspicious_word_count", "is_shared_hosting",
]
# Computed (for audit and the later rule engine) but not fed to the model; measured on the
# train split (reports/metrics/feature_univariate_train.csv), see docs/DATA_DICTIONARY.md.
EXCLUDED_FROM_MODEL = {
    "is_shared_hosting": "never 1 for a legitimate PhiUSIIL host (0 of 94,346) -> acts as a label proxy",
    "is_ip": "never 1 for a legitimate host (0 vs 108 phishing) -> label proxy; handled by rules later",
    "has_punycode": "never 1 for a legitimate host (0 vs 103 phishing) -> label proxy; handled by rules later",
    "num_special_chars": "constant 0 in the data (hostnames rarely contain characters other than a-z0-9.-)",
}
MODEL_FEATURES = [f for f in FEATURE_NAMES if f not in EXCLUDED_FROM_MODEL]


class InvalidURLError(ValueError):
    """The input cannot be parsed into an http(s) URL with a hostname."""


def normalize_url(raw) -> str:
    """Trim, add 'http://' if the scheme is missing, and validate."""
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string")
    url = raw.strip()
    if not url or len(url) > 2048:
        raise InvalidURLError("URL is empty or longer than 2048 characters")
    if "://" not in url:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d)", url):  # javascript:, mailto:, data:
            raise InvalidURLError("Unsupported scheme")
        url = "http://" + url
    try:
        parts = urlsplit(url)
    except ValueError as exc:  # e.g. unbalanced '[' -> "Invalid IPv6 URL"
        raise InvalidURLError(str(exc)) from exc
    if parts.scheme.lower() not in ("http", "https"):
        raise InvalidURLError(f"Unsupported scheme: {parts.scheme}")
    try:
        _ = parts.port  # raises ValueError for malformed ports
    except ValueError as exc:
        raise InvalidURLError("Malformed port") from exc
    if not parts.hostname:
        raise InvalidURLError("URL has no hostname")
    return url


def get_host(url) -> str:
    """Lower-case ASCII hostname: no leading 'www.', no trailing dot, IDNs as punycode."""
    host = (urlsplit(normalize_url(url)).hostname or "").rstrip(".").lower()
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")  # IDNA 2003 (stdlib codec)
        except UnicodeError as exc:
            raise InvalidURLError("Invalid internationalised hostname") from exc
    if not host or not re.fullmatch(r"[a-z0-9._\-\[\]:]+", host):
        raise InvalidURLError("Hostname contains invalid characters")
    return host.removeprefix("www.")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    """eTLD+1 ('a.b.example.co.uk' -> 'example.co.uk'); IPs map to themselves;
    hosts without a known public suffix fall back to their last two labels."""
    if is_ip(host):
        return host
    # shortcut: a host that is itself a public suffix (e.g. rr.gov.br) falls back to 'gov.br'; affects 30 PhiUSIIL
    # hosts, so fixing it would change the frozen baseline split - fix when the baseline is next retrained.
    return _EXTRACT(host).top_domain_under_public_suffix or ".".join(host.split(".")[-2:])


def site_domain(host: str) -> str:
    """PSL-aware registrable domain for NEW code (rules, evidence, API). The frozen baseline keeps registered_domain().

    eTLD+1 for normal hosts ('a.b.example.co.uk' -> 'example.co.uk'). An IP, a host that is itself a public suffix
    ('rr.gov.br') or a host without a known suffix ('intranet.local') is returned unchanged - no guessed grouping.
    """
    if not isinstance(host, str) or not re.fullmatch(r"[a-z0-9._\-\[\]:]+", host) or host.startswith(".") or ".." in host:
        raise InvalidURLError(f"Invalid host: {host!r}")
    if is_ip(host):
        return host
    return _EXTRACT(host).top_domain_under_public_suffix or host


def is_public_suffix(host: str) -> bool:
    """True for hosts that are themselves public suffixes (rr.gov.br, k12.az.us): not one owner's site."""
    e = _EXTRACT(host)
    return not e.domain and e.suffix == host


def _entropy(text: str) -> float:
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values()) if n else 0.0


def _max_consonant_run(text: str) -> int:
    best = run = 0
    for ch in text:
        run = run + 1 if ch.isalpha() and ch not in VOWELS else 0
        best = max(best, run)
    return best


def extract_features(url) -> dict[str, float]:
    """FEATURE_NAMES for one URL, computed from its hostname only."""
    host = get_host(url)
    ip = is_ip(host)
    ext = _EXTRACT(host)
    labels = [p for p in host.split(".") if p] if not ip else [host]
    subdomain = "" if ip else ext.subdomain
    letters = [c for c in host if c.isalpha()]
    digits = sum(c.isdigit() for c in host)
    return {
        "host_length": len(host),
        "num_labels": len(labels),
        "num_dots": host.count("."),
        "num_hyphens": host.count("-"),
        "num_digits": digits,
        "digit_ratio": digits / len(host),
        "num_special_chars": sum(not (c.isalnum() or c in ".-") for c in host),
        "longest_label_length": max(len(p) for p in labels),
        "avg_label_length": sum(len(p) for p in labels) / len(labels),
        "num_numeric_labels": 0 if ip else sum(p.isdigit() for p in labels),
        "registered_domain_length": len(registered_domain(host)),
        "subdomain_count": len(subdomain.split(".")) if subdomain else 0,
        "subdomain_length": len(subdomain),
        "tld_length": 0 if ip else len(ext.suffix),
        "host_entropy": round(_entropy(host), 6),
        "max_consonant_run": _max_consonant_run(host),
        "vowel_ratio": sum(c in VOWELS for c in letters) / len(letters) if letters else 0.0,
        "is_ip": int(ip),
        "has_punycode": int("xn--" in host),
        "suspicious_word_count": sum(w in host for w in SUSPICIOUS_HOST_WORDS),
        "is_shared_hosting": int(any(host == s or host.endswith("." + s) for s in SHARED_HOSTING_SUFFIXES)),
    }
