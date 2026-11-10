"""DOM schema/rule/hybrid regressions; no network or historical research writes."""
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend import api
from backend.dom_rules import evaluate, site
from backend.dom_schema import DomSnapshot
from backend.evidence import ModelEvidence, TIResult
from backend.fusion import FusionResult
from backend.hybrid import combine
from backend.service import Analyzer


def snapshot(**changes):
    features = {"form_count": 1, "password_count": 1, "orphan_password_count": 0,
                "hidden_password_count": 0, "credential_forms": [{"action_origin": "https://example.org",
                    "action_scheme": "https", "method": "post", "password_count": 1,
                    "hidden_password_count": 0, "has_action": False, "action_same_page": True}],
                "link_count": 0, "placeholder_link_count": 0, "unusual_link_count": 0, "link_origins": [],
                "iframe_count": 0, "inaccessible_frame_count": 0, "iframe_origins": [],
                "accessible_frame_form_count": 0, "script_count": 0, "resource_count": 0,
                "resource_origins": [], "title_present": True, "title_length": 20, "title_has_host": False,
                "meta_refresh": [], "truncated": False}
    features.update(changes)
    return {"schema_version": "dom-v1", "state": "inspected", "page_origin": "https://example.org", "features": features}


def fired(data):
    return {r["rule_id"]: r["severity"] for r in evaluate(DomSnapshot.model_validate(data), "https://example.org/")["rules"] if r["status"] == "fired"}


def test_benign_login_and_missing_action():
    assert fired(snapshot()) == {}


def test_password_http_is_strong_but_does_not_claim_phishing():
    data = snapshot()
    data["features"]["credential_forms"][0].update(action_origin="http://example.org", action_scheme="http")
    assert fired(data)["DOM_PASSWORD_HTTP"] == "high"


def test_external_identity_provider_is_contextual_not_high_risk():
    data = snapshot()
    data["features"]["credential_forms"][0]["action_origin"] = "https://accounts.google.com"
    assert fired(data) == {"DOM_CROSS_SITE_FORM": "info"}


def test_hidden_multistep_password_is_info_only():
    data = snapshot(hidden_password_count=1)
    data["features"]["credential_forms"][0]["hidden_password_count"] = 1
    assert fired(data) == {"DOM_HIDDEN_PASSWORD": "info"}


def test_fast_external_refresh_requires_visible_credential_context():
    refresh = [{"origin": "https://other.org", "delay_seconds": 2.0}]
    assert fired(snapshot(meta_refresh=refresh))["DOM_CREDENTIAL_REDIRECT"] == "medium"
    assert "DOM_CREDENTIAL_REDIRECT" not in fired(snapshot(meta_refresh=refresh, password_count=0, credential_forms=[]))
    assert "DOM_CREDENTIAL_REDIRECT" not in fired(snapshot(meta_refresh=[{"origin": "https://example.org", "delay_seconds": 2.0}]))
    assert "DOM_CREDENTIAL_REDIRECT" not in fired(snapshot(meta_refresh=[{"origin": "https://other.org", "delay_seconds": 120.0}]))


def test_combined_indicators_still_only_caution():
    data = snapshot(hidden_password_count=1, meta_refresh=[{"origin": "https://other.org", "delay_seconds": 0.0}])
    data["features"]["credential_forms"][0].update(action_origin="https://other.org", hidden_password_count=1)
    assert fired(data)["DOM_STRUCTURAL_COMBINATION"] == "medium"
    assert "high" not in fired(data).values()


def test_external_resources_and_placeholder_links_alone_do_not_raise_risk():
    data = snapshot(link_count=100, placeholder_link_count=90, link_origins=[{"origin": "https://other.org", "count": 10}],
                    resource_count=100, resource_origins=[{"origin": "https://analytics.example.net", "count": 100}])
    assert fired(data) == {}


@pytest.mark.parametrize("state", ["unavailable", "not_requested", "failed", "incompatible"])
def test_missing_dom_never_becomes_a_success(state):
    result = evaluate(DomSnapshot(schema_version="dom-v1", state=state), "https://example.org")
    assert result["state"] == state and result["rules"] == []
    assert "model" not in result


def test_wrong_schema_and_mismatched_origin_are_not_assessed():
    data = snapshot()
    data["schema_version"] = "dom-v99"
    assert evaluate(DomSnapshot.model_validate(data), "https://example.org")["state"] == "incompatible"
    data["schema_version"] = "dom-v1"
    assert evaluate(DomSnapshot.model_validate(data), "https://other.example.org")["state"] == "unavailable"


def test_psl_uses_private_domains_and_public_suffixes():
    assert site("https://login.example.co.uk") == site("https://www.example.co.uk")
    assert site("https://one.github.io") != site("https://two.github.io")


@pytest.mark.parametrize("patch", [
    {"password_count": -1}, {"password_count": 5001}, {"password_count": "1"},
    {"password_count": True}, {"hidden_password_count": 2},
    {"html": "not allowed"}, {"input_values": ["never allowed"]},
    {"link_origins": [{"origin": "https://example.org/?token=secret", "count": 1}]},
    {"link_origins": [{"origin": "https://u:secret@example.org", "count": 1}]},
    {"link_origins": [{"origin": "https://example.org", "count": 2}]},
])
def test_invalid_and_sensitive_payloads_rejected(patch):
    with pytest.raises(ValidationError):
        DomSnapshot.model_validate(snapshot(**patch))


def test_bounds_on_arrays_and_missing_features():
    data = snapshot()
    data["features"]["credential_forms"] *= 33
    with pytest.raises(ValidationError):
        DomSnapshot.model_validate(data)
    with pytest.raises(ValidationError):
        DomSnapshot(schema_version="dom-v1", state="inspected")


@pytest.mark.parametrize("category,score", [("low_risk", 17), ("unknown", 50), ("caution", 45), ("high_risk", 80), ("dangerous", 95)])
def test_hybrid_only_raises_and_preserves_listing_precedence(category, score):
    base = FusionResult(score, None if category == "unknown" else 100-score, category, "high", "URL", [])
    strong = {"state": "inspected", "rules": [{"status": "fired", "severity": "high"}]}
    result = combine(base, strong, {"alert": .3662, "high": .5671})
    assert result.category == (category if category in ("high_risk", "dangerous") else "high_risk")
    assert result.risk_score >= (0 if category == "unknown" else score)
    assert combine(base, {"state": "unavailable"}, {}) is base
    assert combine(base, {"state": "inspected", "rules": [{"status": "fired", "severity": "info"}]}, {}) is base


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(Analyzer, "model_evidence", lambda self, url: ModelEvidence(False, error="unavailable"))
    with TestClient(api.app) as c:
        api.state["analyzer"].lookups = {}
        yield c


def test_api_optional_dom_and_url_only_compatibility(client):
    url = "https://example.org/"
    base = client.post("/api/v1/analyze", json={"url": url}).json()
    assert base["assessment"]["category"] == "unknown" and "dom" not in base["evidence"]
    data = snapshot()
    data["features"]["credential_forms"][0].update(action_origin="http://other.org", action_scheme="http")
    response = client.post("/api/v1/analyze", json={"url": url, "dom": data})
    assert response.status_code == 200
    body = response.json()
    assert body["assessment"]["category"] == "high_risk" and body["assessment"]["risk_score"] == 57
    assert body["evidence"]["dom"]["state"] == "inspected"
    assert body["assessment_version"] == "url-dom-r2"
    assert body["evidence"]["model"]["probability"] is None
    assert data == snapshot_with_http()  # request parsing does not mutate caller data


def snapshot_with_http():
    data = snapshot()
    data["features"]["credential_forms"][0].update(action_origin="http://other.org", action_scheme="http")
    return data


def test_api_invalid_dom_rejected_but_incompatible_version_falls_back(client):
    assert client.post("/api/v1/analyze", json={"url": "https://example.org", "dom": snapshot(password_count=-1)}).status_code == 422
    data = snapshot()
    data["schema_version"] = "future"
    body = client.post("/api/v1/analyze", json={"url": "https://example.org", "dom": data}).json()
    assert body["evidence"]["dom"]["state"] == "incompatible"
    assert body["assessment"]["category"] == "unknown"


def test_dom_critical_reputation_precedence(client):
    api.state["analyzer"].lookups = {"PhishTank": lambda url: TIResult("PhishTank", "match")}
    body = client.post("/api/v1/analyze", json={"url": "https://example.org", "dom": snapshot_with_http()}).json()
    assert body["assessment"]["category"] == "dangerous" and body["assessment"]["risk_score"] == 95


def test_dom_output_is_deterministic_and_input_unchanged():
    data = snapshot()
    before = deepcopy(data)
    assert evaluate(DomSnapshot.model_validate(data), "https://example.org") == evaluate(DomSnapshot.model_validate(data), "https://example.org")
    assert data == before


def test_oversized_payload_rejected_before_analysis(client):
    assert client.post("/api/v1/analyze", content=b"x" * 65537, headers={"Content-Type": "application/json"}).status_code == 413


def test_dialog_does_not_submit_credentials_over_http():
    data = snapshot_with_http()
    data["features"]["credential_forms"][0]["method"] = "dialog"
    assert "DOM_PASSWORD_HTTP" not in fired(data)


def test_truncated_or_cross_origin_frame_snapshot_is_partial():
    assert evaluate(DomSnapshot.model_validate(snapshot(truncated=True)), "https://example.org")["state"] == "partial"
    assert evaluate(DomSnapshot.model_validate(snapshot(iframe_count=1, inaccessible_frame_count=1)), "https://example.org")["state"] == "partial"


def test_chunked_body_limit_does_not_call_analysis():
    import asyncio

    from backend.request_limits import AnalysisBodyLimit

    messages = iter([{"type": "http.request", "body": b"x" * 33000, "more_body": True},
                     {"type": "http.request", "body": b"x" * 33000, "more_body": False}])
    sent = []

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    async def forbidden(*args):
        raise AssertionError("Oversized body reached JSON parsing")

    asyncio.run(AnalysisBodyLimit(forbidden)({"type": "http", "method": "POST", "path": "/api/v1/analyze"}, receive, send))
    assert sent[0]["status"] == 413


@pytest.mark.parametrize("data", [snapshot(), snapshot(truncated=True),
    {"schema_version": "dom-v1", "state": "unavailable"}])
def test_api_has_rule_only_dom_contract_and_no_classifier_at_startup(client, data):
    body = client.post("/api/v1/analyze", json={"url": "https://example.org", "dom": data}).json()
    assert "model" not in body["evidence"]["dom"]
    assert "dom_predictor" not in api.state
    assert "model" in body["evidence"]  # Existing URL model evidence remains.


def test_obsolete_classifier_evidence_cannot_change_rule_policy():
    base = FusionResult(17, 83, "low_risk", "high", "URL", [])
    dom = {"state": "inspected", "rules": [],
           "model": {"available": True, "enabled": True, "risk_signal": "high"}}
    assert combine(base, dom, {}) is base
