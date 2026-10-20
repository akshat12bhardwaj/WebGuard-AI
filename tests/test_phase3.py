"""Phase 3: controlled fusion scenarios, threshold-rounding regression, EXP-03 data policy and integrity."""
import numpy as np
import pandas as pd
import pytest

from backend.evidence import Evidence, ModelEvidence, RuleFinding, TIResult
from backend.fusion import fuse
from ml.calibrate import pick_thresholds
from ml.exp03_evaluate import domain_weighted, rate_ci
from ml.external_data import EXTERNAL
from ml.subdomain_data import select
from ml.utils import PROCESSED

TH = {"alert": 0.366171, "high": 0.5671}
SUB = ["host has a subdomain"]


def ev(p, ti=("no_match",), rules=(), available=True):
    return Evidence("https://a.b.example.com/", "a.b.example.com", "example.com", "t",
                    ModelEvidence(available, p if available else None, "isotonic", TH, "v"),
                    [TIResult(f"S{i}", s) for i, s in enumerate(ti)], [RuleFinding(r, "fired", sev, r) for r, sev in rules])


@pytest.mark.parametrize("case,args,caveats,category", [
    ("confirmed listing beats everything", (0.01, ("match",), [("TI_PHISHTANK_VERIFIED", "critical")]), SUB, "dangerous"),
    ("legitimate popular domain", (0.05,), [], "low_risk"),
    ("legitimate subdomain, model alarmed", (0.99,), SUB, "caution"),
    ("phishing-like host, no TI match", (0.90,), [], "high_risk"),
    ("IP host: model capped + medium rule", (0.99, ("no_match",), [("IP_ADDRESS_HOST", "medium")]), ["IP-address host"], "caution"),
    ("punycode alone", (0.05, ("no_match",), [("PUNYCODE_HOST", "low")]), [], "low_risk"),
    ("shared hosting alone", (0.05, ("no_match",), [("SHARED_HOSTING_PLATFORM", "info")]), [], "low_risk"),
    ("conflict: model low, high rule", (0.05, ("no_match",), [("BRAND_IN_HOST_MISMATCH", "high")]), [], "high_risk"),
    ("TI timeout", (0.05, ("error",)), [], "low_risk"),
    ("rate-limited API", (0.05, ("rate_limited",)), [], "low_risk"),
    ("service unavailable / not configured", (0.05, ("not_configured",)), [], "low_risk"),
])
def test_controlled_scenarios(case, args, caveats, category):
    r = fuse(ev(*args), caveats)
    assert r.category == category, case
    assert r.category != "safe" and (r.safety_score is None or r.safety_score == 100 - r.risk_score)
    if args[1:] and args[1][0] in ("error", "rate_limited", "not_configured"):
        assert r.confidence == "low" and any("not checked" in n for n in r.notes)  # never a clean bill of health


def test_risk_score_lies_in_its_category_band():
    for p in np.linspace(0, 1, 101):
        r = fuse(ev(float(p)), [])
        band = {"low_risk": (0, 36), "caution": (37, 56), "high_risk": (57, 94)}[r.category]
        assert band[0] <= r.risk_score <= band[1]


def test_exact_threshold_comparison_regression():
    # rounding p or the threshold used to move tied isotonic scores across the alert boundary
    assert fuse(ev(TH["alert"]), []).category == "caution"
    assert fuse(ev(TH["alert"] - 1e-6), []).category == "low_risk"


def test_guard_variants():
    assert fuse(ev(0.99), SUB, "below_alert").category == "low_risk"
    assert fuse(ev(0.99, ("no_match",), [("BRAND_IN_HOST_MISMATCH", "high")]), SUB, "below_alert").category == "high_risk"
    assert fuse(ev(0.99, ("match",), [("TI_URLHAUS_LISTED", "critical")]), SUB, "below_alert").category == "dangerous"


def test_pick_thresholds_rounding_option():
    y = np.array([0] * 50 + [1] * 50)
    p = np.r_[np.linspace(0, 0.6, 50), np.linspace(0.3, 1, 50)] + 1e-7
    r4, exact = pick_thresholds(y, p), pick_thresholds(y, p, ndigits=None)
    assert r4["alert"] == round(exact["alert"], 4) and r4["high"] == round(exact["high"], 4)


def test_rate_ci_and_domain_weighting():
    hits = np.array([True] * 30 + [False] * 70)
    lo, hi = rate_ci(hits)
    assert lo < 0.3 < hi
    assert domain_weighted(np.array([1, 1, 1, 0]), pd.Series(["a", "a", "a", "b"])) == 0.5


def test_subdomain_selection_policy():
    cand = pd.DataFrame({"host": ["x.good.com", "y.good.com", "z.good.com", "w.good.com", "good.com", "1.2.3.4",
                                  "a.site.web.app", "a.bad.com", "a.val.com"],
                         "reg_domain": ["good.com"] * 5 + ["1.2.3.4", "web.app", "bad.com", "val.com"]})
    ex = {k: set() for k in ("external_test", "kaggle", "openphish", "phiusiil_hosts")}
    ex |= {"phiusiil_val_test": {"val.com"}, "phiusiil_train_phishing": {"bad.com"}}
    out, rep = select(cand, ex)
    assert list(out["host"]) == ["x.good.com", "y.good.com", "z.good.com"]  # max 3 per domain, no apex/IP/shared
    assert rep["dropped_over_3_per_domain"] == 1 and rep["dropped_domain_in_phiusiil_val_test"] == 1


NEW = [PROCESSED / f"exp03_new_{s}.csv" for s in ("train", "val", "test")]


@pytest.mark.skipif(not all(p.exists() for p in NEW), reason="run python -m ml.subdomain_data")
def test_exp03_data_integrity():
    tr, va, te = (pd.read_csv(p, keep_default_na=False) for p in NEW)
    rd = lambda f: set(pd.read_csv(f, keep_default_na=False, usecols=["reg_domain"])["reg_domain"])
    phi_train, phi_eval = rd(PROCESSED / "train.csv"), rd(PROCESSED / "val.csv") | rd(PROCESSED / "test.csv")
    forbidden = phi_eval | rd(EXTERNAL) | rd(PROCESSED / "kaggle_binary_hosts.csv")
    for d in (tr, va, te):
        assert (d["is_phishing"] == 0).all() and (d["subdomain_count"] > 0).all()
        assert not set(d["reg_domain"]) & forbidden
    for d in (va, te):
        assert not set(d["reg_domain"]) & (phi_train | set(tr["reg_domain"]))
    assert not set(va["reg_domain"]) & set(te["reg_domain"])
    assert (pd.concat([tr, va, te]).groupby("reg_domain").size() <= 3).all()
