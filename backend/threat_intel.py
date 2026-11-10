"""PhishTank and URLhaus lookups (checked against their docs and live responses on 2026-10-15).

Results are evidence only: never model features or training labels. API failures are reported as
error/rate_limited, never as a clean result. Secrets come from the environment and are never logged.
"""
from __future__ import annotations

import hashlib
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from backend.evidence import TIResult
from ml.feature_extraction import InvalidURLError, get_host
from ml.kaggle_data import url_key
from ml.utils import ROOT

PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"  # documented http:// now 301-redirects here
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"  # v4 Lookup API (v5 is alpha, 2026-10-16)
GSB_THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
OPENPHISH_SOURCE = "OpenPhish (local snapshot)"
OPENPHISH_DIRS = (ROOT / "data" / "feeds" / "openphish", ROOT / "data" / "raw" / "openphish")  # newest file wins
OPENPHISH_STALE_HOURS = float(os.getenv("OPENPHISH_STALE_HOURS", "24"))
TIMEOUT = float(os.getenv("TI_TIMEOUT_SECONDS", "5"))
CACHE_TTL = int(os.getenv("TI_CACHE_TTL_SECONDS", "900"))  # 15 min; only checked results are cached
_cache: dict[tuple[str, str], tuple[float, TIResult]] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _truthy(v) -> bool:
    return v is True or str(v).strip().lower() in ("true", "y", "yes", "1")


def _cached(source: str, url: str, fn) -> TIResult:
    key = (source, hashlib.sha256(url.encode()).hexdigest())
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_TTL:
        return TIResult(**{**hit[1].__dict__, "cached": True})
    result = fn()
    if result.status in ("match", "no_match", "unverified"):
        _cache[key] = (time.monotonic(), result)
    return result


def parse_phishtank(status_code: int, body: dict | None) -> TIResult:
    if status_code == 509:
        return TIResult("PhishTank", "rate_limited", "HTTP 509 (over request limit)", _now())
    if status_code != 200 or not isinstance(body, dict):
        return TIResult("PhishTank", "error", f"HTTP {status_code}", _now())
    res = body.get("results")
    if not isinstance(res, dict) or "in_database" not in res:
        return TIResult("PhishTank", "error", "unexpected response schema", _now())
    ref = str(res.get("phish_detail_page") or "")
    if not _truthy(res["in_database"]):
        return TIResult("PhishTank", "no_match", "not in PhishTank database", _now())
    if _truthy(res.get("verified")) and _truthy(res.get("valid")):
        return TIResult("PhishTank", "match", f"verified phish (id {res.get('phish_id')})", _now(), reference=ref)
    return TIResult("PhishTank", "unverified", "reported to PhishTank but not verified as a valid phish", _now(), reference=ref)


def parse_urlhaus(status_code: int, body: dict | None) -> TIResult:
    if status_code == 429:
        return TIResult("URLhaus", "rate_limited", "HTTP 429", _now())
    if status_code in (401, 403):
        return TIResult("URLhaus", "error", f"HTTP {status_code}: Auth-Key rejected", _now())
    if status_code != 200 or not isinstance(body, dict):
        return TIResult("URLhaus", "error", f"HTTP {status_code}", _now())
    qs = body.get("query_status")
    if qs == "ok":
        tags = ",".join(body.get("tags") or [])
        detail = f"threat={body.get('threat')}, url_status={body.get('url_status')}, added={body.get('date_added')}"
        return TIResult("URLhaus", "match", detail + (f", tags={tags}" if tags else ""), _now(),
                        reference=str(body.get("urlhaus_reference") or ""))
    if qs == "no_results":
        return TIResult("URLhaus", "no_match", "not in URLhaus (malware URLs only)", _now())
    if qs == "invalid_url":
        return TIResult("URLhaus", "invalid_input", "URLhaus rejected the URL", _now())
    return TIResult("URLhaus", "error", f"query_status={qs}", _now())


def parse_safe_browsing(status_code: int, body: dict | None) -> TIResult:
    src = "Google Safe Browsing"
    if status_code == 429:
        return TIResult(src, "rate_limited", "HTTP 429 (quota exhausted)", _now())
    if status_code in (400, 401, 403):
        return TIResult(src, "error", f"HTTP {status_code}: request or API key rejected", _now())
    if status_code != 200 or not isinstance(body, dict):
        return TIResult(src, "error", f"HTTP {status_code}", _now())
    matches = body.get("matches", [])
    if not isinstance(matches, list):
        return TIResult(src, "error", "unexpected response schema", _now())
    if not matches:  # documented: an empty object means no match
        return TIResult(src, "no_match", "not on Safe Browsing lists", _now())
    kinds = sorted({str(m.get("threatType", "?")) for m in matches if isinstance(m, dict)})
    return TIResult(src, "match", "threat types: " + ",".join(kinds), _now())


def _post(url: str, data: dict | None, headers: dict, client: httpx.Client | None,
          json: dict | None = None, params: dict | None = None) -> tuple[int, dict | None]:
    c = client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    try:
        r = c.post(url, data=data, json=json, params=params, headers=headers)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, None
    finally:
        if client is None:
            c.close()


def check_phishtank(url: str, client: httpx.Client | None = None) -> TIResult:
    """Works without a key at a lower limit (observed: 250 requests / 300 s)."""
    headers = {"User-Agent": f"phishtank/{os.getenv('PHISHTANK_USERNAME') or 'website-risk-analyzer'}"}
    data = {"url": url, "format": "json"}
    if os.getenv("PHISHTANK_APP_KEY"):
        data["app_key"] = os.environ["PHISHTANK_APP_KEY"]

    def call() -> TIResult:
        try:
            return parse_phishtank(*_post(PHISHTANK_URL, data, headers, client))
        except httpx.TimeoutException:
            return TIResult("PhishTank", "error", "timeout", _now())
        except httpx.HTTPError as exc:
            return TIResult("PhishTank", "error", type(exc).__name__, _now())
    return _cached("PhishTank", url, call)


def check_urlhaus(url: str, client: httpx.Client | None = None) -> TIResult:
    key = os.getenv("URLHAUS_AUTH_KEY")
    if not key:
        return TIResult("URLhaus", "not_configured", "set URLHAUS_AUTH_KEY to enable", _now())

    def call() -> TIResult:
        try:
            return parse_urlhaus(*_post(URLHAUS_URL, {"url": url}, {"Auth-Key": key}, client))
        except httpx.TimeoutException:
            return TIResult("URLhaus", "error", "timeout", _now())
        except httpx.HTTPError as exc:
            return TIResult("URLhaus", "error", type(exc).__name__, _now())
    return _cached("URLhaus", url, call)


def check_safe_browsing(url: str, client: httpx.Client | None = None) -> TIResult:
    """Lookup API v4. The URL is sent to Google; free tier is for non-commercial use only."""
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return TIResult("Google Safe Browsing", "not_configured", "set GOOGLE_SAFE_BROWSING_KEY to enable", _now())
    body = {"client": {"clientId": "website-risk-analyzer-student", "clientVersion": "0.4"},
            "threatInfo": {"threatTypes": GSB_THREATS, "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}

    def call() -> TIResult:
        try:  # the key travels as a query parameter: never put request URLs or exception text in results/logs
            return parse_safe_browsing(*_post(GSB_URL, None, {}, client, json=body, params={"key": key}))
        except httpx.TimeoutException:
            return TIResult("Google Safe Browsing", "error", "timeout", _now())
        except httpx.HTTPError as exc:
            return TIResult("Google Safe Browsing", "error", type(exc).__name__, _now())
    return _cached("Google Safe Browsing", url, call)


_feeds: dict[Path, tuple[set, set]] = {}


def latest_openphish_snapshot(dirs=OPENPHISH_DIRS) -> Path | None:
    """Newest feed_<YYYYmmddTHHMMSSZ>.txt across the snapshot folders (names sort chronologically)."""
    files = [f for d in dirs if d.exists() for f in d.glob("feed_*.txt")]
    return max(files, key=lambda f: f.name) if files else None


def check_openphish_local(url: str, dirs=OPENPHISH_DIRS, now: datetime | None = None) -> TIResult:
    """Look the URL up in a locally stored OpenPhish Community feed snapshot (no network call)."""
    snap = latest_openphish_snapshot(dirs)
    if snap is None:
        return TIResult(OPENPHISH_SOURCE, "not_configured", "no snapshot; run python -m backend.openphish_update", _now())
    taken = datetime.strptime(snap.stem.removeprefix("feed_"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    age_h = ((now or datetime.now(UTC)) - taken).total_seconds() / 3600
    if snap not in _feeds:
        urls = [u.strip() for u in snap.read_text(encoding="utf-8").splitlines() if u.strip() and not u.startswith("#")]
        hosts = set()
        for u in urls:
            try:
                hosts.add(get_host(u))
            except InvalidURLError:
                pass
        _feeds[snap] = ({k for k in map(url_key, urls) if k}, hosts)
    keys, hosts = _feeds[snap]
    when = f"snapshot {taken:%Y-%m-%d %H:%M} UTC, {age_h:.0f} h old"
    try:
        key, host = url_key(url), get_host(url)
    except InvalidURLError:
        return TIResult(OPENPHISH_SOURCE, "invalid_input", "URL could not be parsed", _now())
    if key in keys:
        if age_h > OPENPHISH_STALE_HOURS:  # a listing in an old snapshot may have been taken down or cleaned
            return TIResult(OPENPHISH_SOURCE, "unverified", f"listed, but the {when} is stale", _now())
        return TIResult(OPENPHISH_SOURCE, "match", f"exact URL listed ({when})", _now())
    if host in hosts:
        return TIResult(OPENPHISH_SOURCE, "unverified", f"same host listed with a different URL ({when})", _now())
    return TIResult(OPENPHISH_SOURCE, "no_match", when, _now())
