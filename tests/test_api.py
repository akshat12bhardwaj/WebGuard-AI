"""API tests with fake threat-intelligence lookups (no network). Needs models/model_bundle.joblib."""
import pytest
from fastapi.testclient import TestClient

from backend import api
from backend.evidence import TIResult
from backend.service import Analyzer
from ml.utils import MODELS

pytestmark = pytest.mark.skipif(not (MODELS / "model_bundle.joblib").exists(), reason="run the ML pipeline first")


@pytest.fixture
def client():
    with TestClient(api.app) as c:
        yield c


def use(lookups):
    api.state["analyzer"].lookups = lookups


def test_health(client):
    assert client.get("/api/v1/health").json() == {"status": "ok", "model_loaded": True, "api_version": "1.0"}


def test_analyze_structure_and_no_safe_claim(client):
    use({"PhishTank": lambda u: TIResult("PhishTank", "no_match"), "URLhaus": lambda u: TIResult("URLhaus", "not_configured")})
    body = client.post("/api/v1/analyze", json={"url": "https://www.wikipedia.org"}).json()
    assert set(body) == {"api_version", "assessment", "evidence", "disclaimer"}
    assert body["evidence"]["model"]["available"] and 0 <= body["evidence"]["model"]["probability"] <= 1
    assert len(body["evidence"]["model"]["top_shap"]) == 5
    assert body["assessment"]["category"] != "safe" and "not proof" in body["disclaimer"]


def test_ti_match_is_dangerous_and_failure_is_low_confidence(client):
    use({"PhishTank": lambda u: TIResult("PhishTank", "match", "verified phish")})
    assert client.post("/api/v1/analyze", json={"url": "https://x.example.org"}).json()["assessment"]["category"] == "dangerous"
    use({"PhishTank": lambda u: TIResult("PhishTank", "error", "timeout")})
    a = client.post("/api/v1/analyze", json={"url": "https://example.org"}).json()["assessment"]
    assert a["confidence"] == "low" and any("not checked" in n for n in a["notes"])


def test_private_hosts_are_not_sent_to_third_parties(client):
    def boom(u):
        raise AssertionError("third party called")
    use({"PhishTank": boom})
    ti = client.post("/api/v1/analyze", json={"url": "http://192.168.1.10/admin"}).json()["evidence"]["threat_intel"]
    assert ti[0]["detail"].startswith("skipped")


def test_invalid_input_is_422(client):
    assert client.post("/api/v1/analyze", json={"url": "javascript:alert(1)"}).status_code == 422
    assert client.post("/api/v1/analyze", json={}).status_code == 422


def test_missing_model_degrades_to_unknown():
    a = Analyzer(bundle=None, lookups={})
    a.bundle, a.load_error = None, "FileNotFoundError"
    ev, _ = a.collect("https://example.net")
    assert not ev.model.available and ev.errors
