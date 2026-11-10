"""Phase 4: PSL-aware domains, brand rules, Google Safe Browsing (mocked), local OpenPhish, fusion, API contract.
All hostnames and feed contents here are synthetic; no real OpenPhish data is used in fixtures."""
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import api, rules
from backend import threat_intel as ti
from backend.evidence import Evidence, ModelEvidence, RuleFinding, TIResult
from backend.fusion import fuse
from ml.feature_extraction import InvalidURLError, registered_domain, site_domain
from ml.utils import MODELS


# ---------- PSL-aware registrable domain ----------
@pytest.mark.parametrize("host,expected", [
    ("example.com", "example.com"), ("a.b.example.com", "example.com"),
    ("x.example.co.uk", "example.co.uk"), ("k12.example.or.us", "example.or.us"),  # multi-label suffixes
    ("rr.gov.br", "rr.gov.br"), ("gov.br", "gov.br"), ("k12.az.us", "k12.az.us"),  # host is itself a public suffix
    ("blog.google", "blog.google"), ("192.0.2.1", "192.0.2.1"), ("2001:db8::1", "2001:db8::1"),
    ("intranet.local", "intranet.local")])  # unknown suffix: no guessed grouping
def test_site_domain(host, expected):
    assert site_domain(host) == expected


@pytest.mark.parametrize("bad", ["", "Example.com", "exa mple.com", ".example.com", "a..b.com", None])
def test_site_domain_rejects_malformed(bad):
    with pytest.raises(InvalidURLError):
        site_domain(bad)


def test_frozen_baseline_function_unchanged():
    assert registered_domain("rr.gov.br") == "gov.br"  # documented shortcut kept for the frozen split


# ---------- brand rules (independent synthetic fixtures) ----------
def brand(url):
    return {r.rule_id: r.severity for r in rules.evaluate(url) if r.status == "fired" and r.rule_id.startswith("BRAND")}


@pytest.mark.parametrize("url,expected", [
    # legitimate / brand-owned / delegated hosting
    ("https://www.paypal.com/signin", {}),
    ("https://outlook.live.com/mail", {}),                       # cited Microsoft-owned domain
    ("https://contoso.sharepoint.com/", {}),
    ("https://blog.google/", {}),                                # brand TLD: suffix token ignored
    ("https://www.applebees.com/", {}),                          # whole-token match only
    ("https://shop.example.com/purchase", {}),
    ("https://img01.microsoft.com.edgekey.net/", {"BRAND_IN_SUBDOMAIN": "medium"}),   # CDN naming: medium only
    ("https://download.apple.com.cdn.example.net/", {"BRAND_IN_SUBDOMAIN": "medium"}),
    ("https://news.example.com/paypal-earnings", {"BRAND_IN_PATH": "medium"}),
    # suspected impersonation
    ("https://secure-paypal.com/", {"BRAND_IN_HOST_MISMATCH": "high"}),
    ("https://paypal-verify.example.net/", {"BRAND_IN_HOST_MISMATCH": "high"}),
    ("https://paypal.secure-verify.com/", {"BRAND_IN_HOST_MISMATCH": "high"}),
    ("https://login.microsoft.com.account-check.net/", {"BRAND_IN_HOST_MISMATCH": "high"}),
    ("https://paypal.com.cdn.example.net/signin", {"BRAND_IN_SUBDOMAIN": "medium"}),  # login word only in path
])
def test_brand_rules(url, expected):
    assert brand(url) == expected


def test_brand_rules_never_double_count():
    for u in ("https://secure-paypal.com/paypal", "https://img.microsoft.com.edgekey.net/microsoft"):
        assert len(brand(u)) == 1


# ---------- Google Safe Browsing (mocked) ----------
@pytest.fixture(autouse=True)
def clean(monkeypatch):
    ti._cache.clear()
    ti._feeds.clear()
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)


def gsb(handler, monkeypatch, key="k-secret"):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", key)
    return ti.check_safe_browsing("https://a.example/", httpx.Client(transport=httpx.MockTransport(handler)))


def test_gsb_not_configured_without_key():
    assert ti.check_safe_browsing("https://a.example/").status == "not_configured"


@pytest.mark.parametrize("status,body,expected", [
    (200, {}, "no_match"),
    (200, {"matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM",
                        "threat": {"url": "https://a.example/"}, "cacheDuration": "300s"}]}, "match"),
    (200, {"matches": "bad"}, "error"), (400, {"error": {}}, "error"), (403, {"error": {}}, "error"),
    (429, {"error": {}}, "rate_limited"), (500, None, "error")])
def test_gsb_parsing(monkeypatch, status, body, expected):
    r = gsb(lambda req: httpx.Response(status, json=body), monkeypatch)
    assert r.status == expected and "k-secret" not in r.detail


def test_gsb_request_shape_and_timeout(monkeypatch):
    seen = {}

    def handler(req):
        seen["key"], seen["body"] = req.url.params["key"], req.read().decode()
        return httpx.Response(200, json={})
    gsb(handler, monkeypatch)
    info = json.loads(seen["body"])["threatInfo"]
    assert seen["key"] == "k-secret" and info["threatEntryTypes"] == ["URL"] and "SOCIAL_ENGINEERING" in info["threatTypes"]

    def slow(req):
        raise httpx.ConnectTimeout("t", request=req)
    ti._cache.clear()
    r = gsb(slow, monkeypatch)
    assert (r.status, r.detail) == ("error", "timeout") and "k-secret" not in r.detail


# ---------- local OpenPhish (synthetic snapshots) ----------
def snapshot(tmp_path, when: datetime, lines):
    d = tmp_path / "op"
    d.mkdir(exist_ok=True)
    (d / f"feed_{when:%Y%m%dT%H%M%SZ}.txt").write_text("\n".join(lines), encoding="utf-8")
    return (d,)


def test_openphish_local(tmp_path):
    now = datetime(2026, 10, 16, 12, tzinfo=UTC)
    dirs = snapshot(tmp_path, now - timedelta(hours=2), ["https://phish.example.net/login/", "garbage line"])
    chk = lambda u, t=now: ti.check_openphish_local(u, dirs, t)
    assert chk("http://PHISH.example.net/login").status == "match"            # normalised URL key
    assert chk("https://phish.example.net/other").status == "unverified"      # host only
    assert chk("https://fine.example.org/").status == "no_match"
    assert chk("https://phish.example.net/login/", now + timedelta(days=3)).status == "unverified"  # stale
    assert chk("javascript:x").status == "invalid_input"
    assert ti.check_openphish_local("https://a.example/", (tmp_path / "none",)).status == "not_configured"


def test_openphish_uses_newest_snapshot(tmp_path):
    now = datetime(2026, 10, 16, 12, tzinfo=UTC)
    snapshot(tmp_path, now - timedelta(hours=30), ["https://old.example.net/"])
    dirs = snapshot(tmp_path, now - timedelta(hours=1), ["https://new.example.net/"])
    assert ti.check_openphish_local("https://new.example.net/", dirs, now).status == "match"
    assert ti.check_openphish_local("https://old.example.net/", dirs, now).status == "no_match"


# ---------- fusion across sources ----------
TH = {"alert": 0.366171, "high": 0.5671}


def evidence(p, ti_list, url="https://a.example.com/"):
    return Evidence(url, "a.example.com", "example.com", "t", ModelEvidence(True, p, "isotonic", TH, "v"),
                    ti_list, rules.evaluate(url, ti_list))


def test_conflicting_sources_confirmed_match_wins():
    ev = evidence(0.02, [TIResult("Google Safe Browsing", "match", "SOCIAL_ENGINEERING"),
                         TIResult("PhishTank", "no_match"), TIResult("URLhaus", "error", "timeout")])
    r = fuse(ev, ["host has a subdomain"])  # a safeguard never discards a confirmed listing
    assert r.category == "dangerous" and any("URLhaus not checked" in n for n in r.notes)


def test_openphish_local_match_is_critical():
    ev = evidence(0.02, [TIResult(ti.OPENPHISH_SOURCE, "match", "exact URL listed")])
    assert fuse(ev, []).category == "dangerous"


def test_all_sources_unavailable_is_unverified_not_clean():
    ev = evidence(0.05, [TIResult(s, st) for s, st in (("PhishTank", "rate_limited"), ("URLhaus", "not_configured"),
                                                         ("Google Safe Browsing", "error"), (ti.OPENPHISH_SOURCE, "not_configured"))])
    r = fuse(ev, [])
    assert r.category == "low_risk" and r.confidence == "low" and len([n for n in r.notes if "not checked" in n]) == 4


def test_cdn_host_is_caution_not_high_and_impersonation_is_high():
    cdn = "https://img01.microsoft.com.edgekey.net/"
    ev = Evidence(cdn, "img01.microsoft.com.edgekey.net", "edgekey.net", "t", ModelEvidence(True, 0.99, "isotonic", TH, "v"),
                  [TIResult("PhishTank", "no_match")], rules.evaluate(cdn))
    assert fuse(ev, ["host has a subdomain"]).category == "caution"
    imp = evidence(0.10, [TIResult("PhishTank", "no_match")], "https://secure-paypal.com/")
    assert fuse(imp, []).category == "high_risk"


def test_safeguard_policy_d35_default():
    ev = Evidence("u", "h", "d", "t", ModelEvidence(True, 0.99, "isotonic", TH, "v"), [TIResult("PhishTank", "no_match")],
                  [RuleFinding("PUNYCODE_HOST", "fired", "low", "x"), RuleFinding("SHARED_HOSTING_PLATFORM", "fired", "info", "x")])
    r = fuse(ev, ["IP-address host"])
    assert r.category == "caution" and r.confidence == "low" and ev.model.probability == 0.99  # raw probability kept


# ---------- API contract ----------
pytestmark_api = pytest.mark.skipif(not (MODELS / "model_bundle.joblib").exists(), reason="needs the trained bundle")

TYPES = {"api_version": str, "assessment": dict, "evidence": dict, "disclaimer": str}
ASSESSMENT = {"risk_score": int, "safety_score": (int, type(None)), "category": str, "confidence": str,
              "decision_basis": str, "notes": list}
EVIDENCE = {"url": str, "host": str, "registered_domain": str, "collected_at": str, "model": dict,
            "threat_intel": list, "rules": list, "errors": list}
MODEL = {"available": bool, "probability": (float, type(None)), "calibration": (str, type(None)), "thresholds": dict,
         "model_version": (str, type(None)), "out_of_training_range": list, "top_shap": list, "error": str}
TI_FIELDS = {"source": str, "status": str, "detail": str, "checked_at": str, "cached": bool, "reference": str}
RULE_FIELDS = {"rule_id": str, "status": str, "severity": str, "title": str, "explanation": str}


def check(obj, spec):
    assert set(obj) == set(spec), set(obj) ^ set(spec)
    for k, t in spec.items():
        assert isinstance(obj[k], t), (k, type(obj[k]))


@pytestmark_api
def test_api_contract(monkeypatch):
    with TestClient(api.app) as c:
        api.state["analyzer"].lookups = {
            "PhishTank": lambda u: TIResult("PhishTank", "no_match"),
            "Google Safe Browsing": lambda u: TIResult("Google Safe Browsing", "error", "timeout")}
        body = c.post("/api/v1/analyze", json={"url": "https://img01.microsoft.com.edgekey.net/x"}).json()
        check(body, TYPES)
        check(body["assessment"], ASSESSMENT)
        check(body["evidence"], EVIDENCE)
        check(body["evidence"]["model"], MODEL)
        for t in body["evidence"]["threat_intel"]:
            check(t, TI_FIELDS)
            assert t["status"] in ("match", "no_match", "unverified", "error", "rate_limited", "not_configured", "invalid_input")
        for r in body["evidence"]["rules"]:
            check(r, RULE_FIELDS)
            assert r["status"] in ("fired", "not_fired", "not_evaluated")
        assert body["assessment"]["category"] in ("dangerous", "high_risk", "caution", "low_risk", "unknown")
        assert body["evidence"]["registered_domain"] == "edgekey.net"
        for bad in ({"url": "javascript:alert(1)"}, {"url": ""}, {}, {"url": "x" * 3000}):
            r = c.post("/api/v1/analyze", json=bad)
            assert r.status_code == 422 and "detail" in r.json()
