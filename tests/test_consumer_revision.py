"""Consumer r1 reliability regressions. No live reputation requests or research runs."""
import runpy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import api
from backend.evidence import Evidence, ModelEvidence, RuleFinding, TIResult
from backend.fusion import fuse
from backend.service import Analyzer


@pytest.mark.parametrize("url,category,score", [
    ("https://example.org/", "unknown", 50),
    ("http://example.org/login", "caution", 37),
    ("https://paypal.secure-verify.com/", "high_risk", 57),
])
def test_unavailable_model_returns_valid_api_result(monkeypatch, url, category, score):
    # Same shape returned by Analyzer.model_evidence on missing bundle/inference failure:
    # probability None and thresholds {}, not a fake successful model with thresholds.
    monkeypatch.setattr(Analyzer, "model_evidence", lambda self, url: ModelEvidence(False, error="OSError"))
    with TestClient(api.app) as client:
        api.state["analyzer"].lookups = {"URLhaus": lambda url: TIResult("URLhaus", "error", "timeout")}
        response = client.post("/api/v1/analyze", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["assessment"]["category"] == category
    assert data["assessment"]["risk_score"] == score
    assert data["assessment"]["confidence"] == "low"
    assert not data["evidence"]["model"]["available"]
    assert data["evidence"]["model"]["thresholds"] == {}
    assert data["evidence"]["errors"]
    assert data["assessment"]["safety_score"] == (None if category == "unknown" else 100 - score)


@pytest.mark.parametrize("thresholds,probability", [({}, .9), ({"alert": .3}, .9),
    ({"alert": .7, "high": .2}, .9), ({"alert": .3, "high": .6}, None),
    ({"alert": .3, "high": .6}, float("nan")), ({"alert": .3, "high": .6}, 1.1)])
def test_incomplete_model_cannot_contribute_a_score(thresholds, probability):
    ev = Evidence("https://example.org", "example.org", "example.org", "", ModelEvidence(
        True, probability=probability, thresholds=thresholds), [], [])
    assert fuse(ev, []).category == "unknown"
    ev.rules = [RuleFinding("TEST", "fired", "high", "Address warning")]
    assert (fuse(ev, []).category, fuse(ev, []).risk_score) == ("high_risk", 57)


def test_critical_listing_still_overrides_missing_model():
    ev = Evidence("https://example.org", "example.org", "example.org", "", ModelEvidence(False),
                  [TIResult("PhishTank", "match")], [RuleFinding("TI_TEST", "fired", "critical", "Listed")])
    assert (fuse(ev, []).category, fuse(ev, []).risk_score) == ("dangerous", 95)


def test_valid_model_results_match_preserved_frozen_implementation(tmp_path):
    original = Path(__file__).parent / "fixtures/frozen_fusion.py"
    baseline = runpy.run_path(str(original))["fuse"]
    for probability in (0, .17, .36619, .3662, .5, .5671, .99, 1):
        for severity in ("low", "medium", "high", "critical"):
            for caveats in ([], ["subdomain"]):
                ev = Evidence("https://example.org", "example.org", "example.org", "", ModelEvidence(
                    True, probability=probability, thresholds={"alert": .3662, "high": .5671}),
                    [TIResult("PhishTank", "no_match")], [RuleFinding("TEST", "fired", severity, "Test")])
                assert fuse(ev, caveats).to_dict() == baseline(ev, caveats).to_dict()
