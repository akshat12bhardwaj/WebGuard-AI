"""URLhaus / Safe Browsing: request shapes, failure handling and their effect on the final verdict (mocked, no network).

Endpoints and formats checked against the official docs on 2026-10-20 (urlhaus-api.abuse.ch, Safe Browsing v4 Lookup API).
"""
import httpx
import pytest

from backend import rules
from backend import threat_intel as ti
from backend.evidence import Evidence, ModelEvidence, TIResult
from backend.fusion import fuse
from backend.service import Analyzer

URL = "https://a.example/login"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    ti._cache.clear()
    for k in ("URLHAUS_AUTH_KEY", "GOOGLE_SAFE_BROWSING_KEY"):
        monkeypatch.delenv(k, raising=False)


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_urlhaus_request_shape(monkeypatch):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "uh-secret")
    seen = {}

    def handler(req):
        seen.update(method=req.method, url=str(req.url), key=req.headers.get("Auth-Key"), body=req.read().decode())
        return httpx.Response(200, json={"query_status": "no_results"})
    r = ti.check_urlhaus(URL, client(handler))
    assert r.status == "no_match"
    assert seen["method"] == "POST" and seen["url"] == "https://urlhaus-api.abuse.ch/v1/url/"
    assert seen["key"] == "uh-secret" and seen["body"] == "url=https%3A%2F%2Fa.example%2Flogin"


@pytest.mark.parametrize("handler", [
    lambda req: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=req)),
    lambda req: (_ for _ in ()).throw(httpx.ConnectError("down", request=req)),
    lambda req: httpx.Response(200, text="<html>maintenance</html>"),
    lambda req: httpx.Response(200, json=["not", "an", "object"]),
    lambda req: httpx.Response(503, text="")])
def test_urlhaus_failures_are_never_clean(monkeypatch, handler):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "uh-secret")
    r = ti.check_urlhaus(URL, client(handler))
    assert r.status == "error" and "uh-secret" not in r.detail


def test_safe_browsing_non_json_reply_is_error(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "gsb-secret")
    r = ti.check_safe_browsing(URL, client(lambda req: httpx.Response(200, text="oops")))
    assert r.status == "error" and "gsb-secret" not in r.detail


def _verdict(ti_results):
    model = ModelEvidence(True, 0.05, "isotonic", {"alert": 0.3662, "high": 0.5671}, "host-v1")
    ev = Evidence(URL, "a.example", "a.example", "t", model, ti_results, rules.evaluate(URL, ti_results))
    return ev, fuse(ev, [])


@pytest.mark.parametrize("source,rule_id", [("URLhaus", "TI_URLHAUS_LISTED"), ("Google Safe Browsing", "TI_SAFE_BROWSING_MATCH")])
def test_a_listing_changes_the_final_verdict(source, rule_id):
    ev, result = _verdict([TIResult(source, "match", "listed", "t")])
    assert next(r for r in ev.rules if r.rule_id == rule_id).status == "fired"
    assert result.category == "dangerous" and result.risk_score == 95


@pytest.mark.parametrize("status", ["not_configured", "error", "rate_limited"])
def test_an_unchecked_source_is_never_a_clean_result(status):
    ev, result = _verdict([TIResult("URLhaus", status, "x", "t"), TIResult("Google Safe Browsing", status, "x", "t")])
    states = {r.rule_id: r.status for r in ev.rules}
    assert states["TI_URLHAUS_LISTED"] == states["TI_SAFE_BROWSING_MATCH"] == "not_evaluated"
    assert f"URLhaus not checked: {status}" in result.notes
    assert result.confidence == "low"  # no source was checked


def test_analyzer_calls_every_configured_source_and_records_its_status(monkeypatch):
    calls = []

    def fake(name, status):
        def f(url):
            calls.append(name)
            return TIResult(name, status, "", "t")
        return f
    a = Analyzer(lookups={"URLhaus": fake("URLhaus", "no_match"), "Google Safe Browsing": fake("Google Safe Browsing", "match")})
    ev, _ = a.collect(URL)
    assert sorted(calls) == ["Google Safe Browsing", "URLhaus"]
    assert {t.source: t.status for t in ev.threat_intel} == {"URLhaus": "no_match", "Google Safe Browsing": "match"}
