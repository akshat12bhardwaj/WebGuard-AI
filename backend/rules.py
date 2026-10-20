"""Deterministic rule engine, separate from the ML model.

Severity policy (docs/DECISIONS.md D20):
  critical  independently verified threat-intelligence listing
  high      deception pattern with little legitimate use (credentials in URL, suspected brand impersonation)
  medium    suspicious but with real legitimate use (raw IP host, plain-http login page, brand in subdomain/path)
  low/info  context only (punycode, shared hosting, shortener, port, long URL) - never raises the score
Indicators such as IP hosts, punycode or shared hosting are never treated as proof of phishing.
Each underlying fact feeds at most one rule (e.g. plain http is reported once).
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from backend.evidence import CHECKED, RuleFinding, TIResult
from ml.feature_extraction import (
    extract_features,
    get_host,
    is_public_suffix,
    normalize_url,
    site_domain,
)

BRANDS = ("paypal", "apple", "microsoft", "office365", "outlook", "google", "amazon", "netflix", "facebook",
          "instagram", "whatsapp", "linkedin", "dropbox", "docusign", "adobe", "binance", "coinbase", "metamask",
          "dhl", "fedex", "usps", "chase", "wellsfargo", "hsbc", "sbi", "hdfc", "icici")  # assumption: curated
# Brand-owned domains whose name is not the brand token. Source: Microsoft 365 URLs and IP address ranges
# (learn.microsoft.com/microsoft-365/enterprise/urls-and-ip-address-ranges, checked 2026-10-16). Add only cited entries.
OFFICIAL_DOMAINS = ("live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "sharepoint.com",
                    "office.net")
CREDENTIAL_WORDS = ("login", "signin", "sign-in", "logon", "verify", "password", "passwd", "account",
                    "secure", "update", "wallet", "otp", "kyc", "unlock")
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "rb.gy", "t.ly", "s.id")


@dataclass
class Ctx:
    url: str
    scheme: str
    netloc: str
    port: int | None
    host: str
    reg: str
    reg_label: str  # registrant-chosen name ('paypal-login' in paypal-login.co.uk); '' if the host is a public suffix
    sub_tokens: list[str]  # tokens left of the registrable domain
    rest: str  # decoded, lower-case path + query
    features: dict
    ti: dict[str, TIResult]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    requires: str  # evidence the rule needs
    check: Callable[[Ctx], tuple[bool | None, str]]  # None = required evidence missing


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text) if t]


def _brand_owned(ctx: Ctx) -> bool:
    return ctx.reg_label in BRANDS or ctx.reg in OFFICIAL_DOMAINS


def _brand_in(tokens: list[str]) -> str | None:
    # Whole tokens only: 'applebees' or 'purchase' never match; public-suffix tokens (blog.google) are never passed in.
    return next((b for b in BRANDS if b in tokens), None)


def _impersonation(ctx: Ctx) -> str | None:
    """Brand in the registrant-chosen name, or brand in a subdomain together with login-type words."""
    if _brand_owned(ctx):
        return None
    label_toks = _tokens(ctx.reg_label)
    if b := _brand_in(label_toks):
        return f"The registered name '{ctx.reg}' contains '{b}' but is not a known {b} domain."
    if (b := _brand_in(ctx.sub_tokens)) and set(ctx.sub_tokens + label_toks) & set(CREDENTIAL_WORDS):
        return f"'{b}' appears with login/account words on '{ctx.reg}', which is not a known {b} domain."
    return None


def _brand_subdomain(ctx: Ctx):
    b = None if _brand_owned(ctx) or _impersonation(ctx) else _brand_in(ctx.sub_tokens)
    return b is not None, (f"'{b}' appears in the subdomain of '{ctx.reg}'. This is common for delegated hosting and "
                           "CDNs (e.g. <name>.microsoft.com.edgekey.net) but is also a phishing trick." if b else "")


def _brand_path(ctx: Ctx):
    hit = not _brand_owned(ctx) and not _brand_in(ctx.sub_tokens) and not _impersonation(ctx)
    b = _brand_in(_tokens(ctx.rest)) if hit else None
    return b is not None, (f"The path mentions '{b}' on a site registered as '{ctx.reg}' (common on news sites too)." if b else "")


def _ti(source: str):
    def check(ctx: Ctx):
        r = ctx.ti.get(source)
        if r is None or r.status not in CHECKED:
            return None, f"{source} was not checked ({r.status if r else 'no result'})"
        return r.status == "match", f"{source}: {r.detail}"
    return check


def _http_creds(ctx: Ctx):
    hit = ctx.scheme == "http" and any(w in ctx.rest or w in ctx.host for w in CREDENTIAL_WORDS)
    return hit, "The page is not encrypted (http) and its address uses login/account words."


RULES: list[Rule] = [
    Rule("TI_PHISHTANK_VERIFIED", "critical", "Verified phishing listing (PhishTank)", "PhishTank result",
         _ti("PhishTank")),
    Rule("TI_URLHAUS_LISTED", "critical", "Listed as malware-distribution URL (URLhaus)", "URLhaus result",
         _ti("URLhaus")),
    Rule("TI_SAFE_BROWSING_MATCH", "critical", "Flagged by Google Safe Browsing", "Google Safe Browsing result",
         _ti("Google Safe Browsing")),
    Rule("TI_OPENPHISH_LISTED", "critical", "Listed in the OpenPhish feed (local snapshot)", "OpenPhish local snapshot",
         _ti("OpenPhish (local snapshot)")),
    Rule("URL_CREDENTIALS_IN_AUTHORITY", "high", "'@' hides the real destination", "URL",
         lambda c: ("@" in c.netloc, f"Everything before '@' is ignored; the browser actually goes to '{c.host}'.")),
    Rule("BRAND_IN_HOST_MISMATCH", "high", "Suspected brand impersonation", "URL",
         lambda c: ((why := _impersonation(c)) is not None, why or "")),
    Rule("BRAND_IN_SUBDOMAIN", "medium", "Brand name in the subdomain of another domain", "URL", _brand_subdomain),
    Rule("BRAND_IN_PATH", "medium", "Brand name in the page path", "URL", _brand_path),
    Rule("IP_ADDRESS_HOST", "medium", "Raw IP address instead of a domain name", "URL",
         lambda c: (bool(c.features["is_ip"]), "Legitimate public sites rarely use bare IP addresses, but some do.")),
    Rule("HTTP_WITH_CREDENTIAL_WORDS", "medium", "Unencrypted page with login words", "URL", _http_creds),
    Rule("NO_HTTPS", "low", "Connection is not encrypted", "URL",
         lambda c: (c.scheme == "http" and not _http_creds(c)[0], "Plain http alone does not mean the site is malicious.")),
    Rule("PUNYCODE_HOST", "low", "Internationalised (punycode) domain", "URL",
         lambda c: (bool(c.features["has_punycode"]), "Normal for non-English names; check it is not imitating a familiar one.")),
    Rule("SHARED_HOSTING_PLATFORM", "info", "Hosted on a shared/free platform", "URL",
         lambda c: (bool(c.features["is_shared_hosting"]), "Anyone can publish here; the platform's reputation says nothing about this page.")),
    Rule("UNUSUAL_HOST_CHARACTERS", "low", "Unusual characters in the host name", "URL",
         lambda c: (c.features["num_special_chars"] > 0, "Host names normally contain only letters, digits, dots and hyphens.")),
    Rule("NONSTANDARD_PORT", "low", "Unusual network port", "URL",
         lambda c: (c.port not in (None, 80, 443), f"The address uses port {c.port}.")),
    Rule("URL_SHORTENER", "info", "Link shortener hides the destination", "URL",
         lambda c: (c.host in SHORTENERS, "The final destination is not visible before you open it.")),
    Rule("VERY_LONG_URL", "low", "Very long address", "URL",
         lambda c: (len(c.url) > 200, "Very long addresses can hide the real destination.")),
]


def evaluate(url: str, ti: list[TIResult] | None = None) -> list[RuleFinding]:
    """Run every rule. Raises ml.feature_extraction.InvalidURLError for invalid URLs."""
    url = normalize_url(url)
    p = urlsplit(url)
    host = get_host(url)
    reg = site_domain(host)
    label = "" if is_public_suffix(host) else reg.split(".")[0]
    sub = host[: -len(reg)].rstrip(".") if host != reg else ""
    ctx = Ctx(url, p.scheme.lower(), p.netloc, p.port, host, reg, label, _tokens(sub),
              unquote(f"{p.path}?{p.query}").lower(), extract_features(url), {r.source: r for r in ti or []})
    out = []
    for rule in RULES:
        fired, why = rule.check(ctx)
        status = "not_evaluated" if fired is None else "fired" if fired else "not_fired"
        out.append(RuleFinding(rule.rule_id, status, rule.severity, rule.title, why if status != "not_fired" else ""))
    return out
