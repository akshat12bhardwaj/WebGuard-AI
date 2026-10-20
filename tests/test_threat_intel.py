"""Mocked PhishTank/URLhaus tests (no network). Response shapes copied from live replies on 2026-10-15."""
import httpx
import pytest

from backend import threat_intel as ti


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    ti._cache.clear()
    for k in ("URLHAUS_AUTH_KEY", "PHISHTANK_APP_KEY", "PHISHTANK_USERNAME"):
        monkeypatch.delenv(k, raising=False)


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def reply(status=200, json=None, text=None):
    return lambda request: httpx.Response(status, json=json, text=text)


PT_MISS = {"meta": {"status": "success"}, "results": {"url": "x", "in_database": False}}
PT_UNVERIFIED = {"meta": {"status": "success"}, "results": {"url": "https://www.wikipedia.org/", "in_database": True,
                 "phish_id": 5535959, "phish_detail_page": "http://www.phishtank.com/phish_detail.php?phish_id=5535959",
                 "verified": False, "verified_at": None, "valid": False}}
PT_HIT = {"meta": {"status": "success"}, "results": {"url": "x", "in_database": True, "phish_id": 1,
          "phish_detail_page": "http://p/1", "verified": "y", "valid": "y"}}


@pytest.mark.parametrize("body,status", [(PT_MISS, "no_match"), (PT_UNVERIFIED, "unverified"), (PT_HIT, "match")])
def test_phishtank_parsing(body, status):
    r = ti.check_phishtank("https://a.example/", client(reply(json=body)))
    assert r.status == status and r.source == "PhishTank"


def test_phishtank_reported_but_unverified_is_not_a_match():
    assert ti.parse_phishtank(200, PT_UNVERIFIED).status == "unverified"


@pytest.mark.parametrize("resp,status", [(reply(509, text="limit"), "rate_limited"), (reply(500, text="x"), "error"),
                                         (reply(200, text="<html>"), "error"), (reply(200, json={"meta": {}}), "error")])
def test_phishtank_failures_are_never_clean(resp, status):
    assert ti.check_phishtank("https://a.example/", client(resp)).status == status


def test_phishtank_sends_user_agent_and_optional_key(monkeypatch):
    monkeypatch.setenv("PHISHTANK_APP_KEY", "k123")
    seen = {}

    def handler(request):
        seen["ua"], seen["body"] = request.headers["user-agent"], request.content.decode()
        return httpx.Response(200, json=PT_MISS)
    ti.check_phishtank("https://a.example/", client(handler))
    assert seen["ua"].startswith("phishtank/") and "app_key=k123" in seen["body"] and "format=json" in seen["body"]


def test_timeout_is_error():
    def boom(request):
        raise httpx.ReadTimeout("slow", request=request)
    assert ti.check_phishtank("https://a.example/", client(boom)).detail == "timeout"


def test_urlhaus_missing_key_is_not_configured():
    called = []
    r = ti.check_urlhaus("https://a.example/", client(lambda req: called.append(1)))
    assert r.status == "not_configured" and not called


@pytest.mark.parametrize("resp,status", [
    (reply(json={"query_status": "ok", "threat": "malware_download", "url_status": "online", "tags": ["elf"],
                 "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/", "date_added": "2026-10-01"}), "match"),
    (reply(json={"query_status": "no_results"}), "no_match"),
    (reply(json={"query_status": "invalid_url"}), "invalid_input"),
    (reply(json={"query_status": "http_post_expected"}), "error"),
    (reply(401, json={"error": "Unauthorized"}), "error"),
    (reply(429, text=""), "rate_limited")])
def test_urlhaus_parsing(monkeypatch, resp, status):
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "secret")
    r = ti.check_urlhaus("https://a.example/", client(resp))
    assert r.status == status and "secret" not in r.detail


def test_cache_keeps_checked_results_but_not_errors():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json=PT_MISS)
    c = client(handler)
    first, second = ti.check_phishtank("https://a.example/", c), ti.check_phishtank("https://a.example/", c)
    assert len(calls) == 1 and not first.cached and second.cached
    bad = client(reply(500, text="x"))
    ti.check_phishtank("https://b.example/", bad)
    ti.check_phishtank("https://b.example/", client(handler))
    assert len(calls) == 2  # the error was not cached
