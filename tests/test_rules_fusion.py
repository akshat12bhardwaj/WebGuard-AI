import json

import pytest

from backend import rules
from backend.evidence import Evidence, ModelEvidence, RuleFinding, TIResult
from backend.fusion import fuse
from ml.feature_extraction import InvalidURLError

TH = {"alert": 0.3662, "high": 0.5671}


def fired(url, ti=None):
    return {r.rule_id: r.severity for r in rules.evaluate(url, ti) if r.status == "fired"}


def test_every_rule_reports_and_ids_are_unique():
    out = rules.evaluate("https://example.com/")
    assert len(out) == len(rules.RULES) == len({r.rule_id for r in out})


def test_ordinary_urls_fire_nothing_that_raises_risk():
    for u in ("https://www.paypal.com/signin", "https://accounts.google.com/", "https://shop.example.com/purchase"):
        assert not {s for s in fired(u).values() if s in ("critical", "high", "medium")}, u


def test_indicators_are_not_proof():
    assert fired("http://192.0.2.1/")["IP_ADDRESS_HOST"] == "medium"
    assert fired("https://xn--bcher-kva.de/")["PUNYCODE_HOST"] == "low"
    assert fired("https://site.web.app/")["SHARED_HOSTING_PLATFORM"] == "info"


def test_deception_patterns():
    assert fired("http://bank.com@evil.example/")["URL_CREDENTIALS_IN_AUTHORITY"] == "high"
    assert fired("https://paypal.secure-verify.com/")["BRAND_IN_HOST_MISMATCH"] == "high"
    assert fired("https://news.example.com/paypal-earnings") == {"BRAND_IN_PATH": "medium"}


def test_plain_http_is_counted_once():
    f = fired("http://example.com/login")
    assert "HTTP_WITH_CREDENTIAL_WORDS" in f and "NO_HTTPS" not in f
    assert "NO_HTTPS" in fired("http://example.com/about")


def test_ti_rules_need_ti_evidence():
    by_id = {r.rule_id: r for r in rules.evaluate("https://a.example.com/")}
    assert by_id["TI_PHISHTANK_VERIFIED"].status == "not_evaluated"
    err = [TIResult("PhishTank", "error", "timeout"), TIResult("URLhaus", "no_match")]
    by_id = {r.rule_id: r for r in rules.evaluate("https://a.example.com/", err)}
    assert by_id["TI_PHISHTANK_VERIFIED"].status == "not_evaluated" and by_id["TI_URLHAUS_LISTED"].status == "not_fired"
    hit = [TIResult("PhishTank", "match", "verified phish")]
    assert fired("https://a.example.com/", hit)["TI_PHISHTANK_VERIFIED"] == "critical"
    unv = [TIResult("PhishTank", "unverified", "reported")]
    assert "TI_PHISHTANK_VERIFIED" not in fired("https://a.example.com/", unv)


def test_invalid_url_raises():
    with pytest.raises(InvalidURLError):
        rules.evaluate("javascript:alert(1)")


# ---------- fusion and evidence ----------
def ev(p=0.1, ti=(("PhishTank", "no_match"),), rule_list=(), available=True, oor=()):
    return Evidence("https://a.example.com/", "a.example.com", "example.com", "t",
                    ModelEvidence(available, p if available else None, "isotonic", TH, "host-v1", list(oor)),
                    [TIResult(s, st) for s, st in ti], [RuleFinding(i, "fired", sev, i) for i, sev in rule_list])


def test_ti_match_overrides_low_model_score():
    r = fuse(ev(0.02, rule_list=[("TI_PHISHTANK_VERIFIED", "critical")]), [])
    assert (r.category, r.risk_score, r.confidence) == ("dangerous", 95, "high")


def test_model_categories_never_say_safe():
    assert fuse(ev(0.80), []).category == "high_risk"
    assert fuse(ev(0.45), []).category == "caution"
    low = fuse(ev(0.05), [])
    assert (low.category, low.risk_score, low.safety_score) == ("low_risk", 5, 95)


def test_rule_floor_is_max_not_average():
    r = fuse(ev(0.05, rule_list=[("BRAND_IN_HOST_MISMATCH", "high")]), [])
    assert (r.category, r.risk_score, r.decision_basis) == ("high_risk", 57, "Rule engine")
    assert fuse(ev(0.05, rule_list=[("IP_ADDRESS_HOST", "medium")]), []).category == "caution"
    assert fuse(ev(0.05, rule_list=[("PUNYCODE_HOST", "low")]), []).category == "low_risk"


def test_reliability_guard_caps_only_the_model():
    r = fuse(ev(0.95), ["host has a subdomain"])
    assert r.category == "caution" and r.confidence == "low" and r.risk_score == 56
    # a high rule still sets its floor even when the model score is capped (regression: live smoke test)
    r = fuse(ev(0.99, rule_list=[("BRAND_IN_HOST_MISMATCH", "high")]), ["host has a subdomain"])
    assert (r.category, r.risk_score, r.decision_basis) == ("high_risk", 57, "Rule engine")


def test_missing_and_failed_evidence():
    assert fuse(ev(available=False), []).category == "unknown"
    assert fuse(ev(available=False), []).safety_score is None
    failed = fuse(ev(0.05, ti=(("PhishTank", "error"), ("URLhaus", "not_configured"))), [])
    assert failed.category == "low_risk" and failed.confidence == "low"
    assert any("not checked" in n for n in failed.notes)
    assert fuse(ev(0.05, oor=["host_length"]), []).confidence == "low"


def test_evidence_serializes_to_json():
    e = ev(0.3, rule_list=[("NO_HTTPS", "low")])
    d = json.loads(json.dumps({"evidence": e.to_dict(), "assessment": fuse(e, []).to_dict()}))
    assert d["evidence"]["model"]["probability"] == 0.3 and d["evidence"]["threat_intel"][0]["status"] == "no_match"
    assert set(d["assessment"]) == {"risk_score", "safety_score", "category", "confidence", "decision_basis", "notes"}
