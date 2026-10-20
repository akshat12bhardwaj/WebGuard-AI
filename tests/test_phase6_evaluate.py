"""Phase 6 runner: fail-closed freeze checks, reproducibility, privacy of outputs, full-URL mode (synthetic data only).
Uses the real production bundle to score a handful of synthetic hosts; no network, no real feed data."""
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from ml import phase6_collect as pc
from ml import phase6_evaluate as pe
from ml import phase6_platforms as pp
from ml.utils import MODELS

T0 = datetime(2026, 10, 20, tzinfo=UTC)
END = T0 + timedelta(days=pc.WINDOW_DAYS, hours=1)
FEED1 = b"https://a1.phish-new.example/login?email=victim@example.com\nhttps://x.typedream.app/p\nhttps://old.seen.example/\n"
FEED2 = b"https://b2.other-phish.example/verify#t\nhttps://user:pw@c3.third-phish.example/x\n"
needs_bundle = pytest.mark.skipif(not (MODELS / "model_bundle.joblib").exists(), reason="needs the production bundle")


@pytest.fixture
def project(tmp_path, monkeypatch):
    (tmp_path / "code.py").write_text("frozen code", encoding="utf-8")
    (tmp_path / "PROTO.md").write_text("protocol", encoding="utf-8")
    prior = tmp_path / "prior.csv"
    prior.write_text("host,reg_domain\nold.seen.example,seen.example\nx.typedream.app,typedream.app\n"
                     "q.typedream.app,typedream.app\n", encoding="utf-8")
    (tmp_path / "pre.txt").write_text("https://pre-freeze.example/\n", encoding="utf-8")
    for name, value in {"ROOT": tmp_path, "FRESH": tmp_path / "fresh", "MANIFEST": tmp_path / "fresh" / "manifest.jsonl",
                        "FROZEN": tmp_path / "frozen.json", "PROTOCOL": tmp_path / "PROTO.md",
                        "FROZEN_FILES": ["code.py"], "PRIOR_SETS": ["prior.csv"], "PRE_FREEZE_OPENPHISH": ["pre.txt"]}.items():
        monkeypatch.setattr(pc, name, value)
    feeds = {"c1": FEED1, "c2": FEED2}
    state = {"commit": "c1"}

    def fake_get(url):
        if url == pc.OPENPHISH_FEED:
            return feeds[state["commit"]]
        if url == pc.OPENPHISH_COMMITS:
            return json.dumps([{"sha": state["commit"]}]).encode()
        if url.startswith(pc.TRANCO_API):
            sub = "subdomains" in url
            return json.dumps({"list_id": "LSUB" if sub else "LAPX", "created_on": END.isoformat(),
                               "download": "sub" if sub else "apx"}).encode()
        if url == "sub":
            return b"1,docs.legit-one.example\n2,www.legit-two.example\n3,a.legit-one.example\n"
        if url == "apx":
            return b"1,legit-apex.example\n2,seen.example\n3,another-apex.example\n"
        for c, raw in feeds.items():  # GitHub raw by commit (full-URL mode)
            if url == pe.GITHUB_RAW.format(commit=c):
                return state.get("tamper", raw)
        raise OSError(url)
    monkeypatch.setattr(pc, "_get", fake_get)
    monkeypatch.setattr(pe, "_get", fake_get)
    pc.freeze(T0)
    pc.collect_openphish(T0)
    state["commit"] = "c2"
    pc.collect_openphish(T0 + timedelta(hours=12))
    pc.collect_tranco(END)
    return tmp_path, state


def test_freeze_fails_closed_on_missing_entry_and_mismatch(project):
    _ = project
    rec = json.loads(pc.FROZEN.read_text(encoding="utf-8"))
    del rec["sha256"]["code.py"]
    pc.FROZEN.write_text(json.dumps(rec), encoding="utf-8")
    with pytest.raises(SystemExit, match=r"Missing from the freeze record: \['code.py'\]"):
        pe.ready(END)
    rec["sha256"]["code.py"] = "0" * 64
    pc.FROZEN.write_text(json.dumps(rec), encoding="utf-8")
    with pytest.raises(SystemExit, match=r"changed since the freeze: \['code.py'\]"):
        pe.ready(END)


def test_real_freeze_set_covers_runner_and_platform_list():
    for f in ("ml/phase6_evaluate.py", "ml/phase6_collect.py", "ml/phase6_platforms.json", "models/model_bundle.joblib",
              "backend/rules.py", "backend/fusion.py"):
        assert f in pc.FROZEN_FILES


def test_runner_refuses_while_window_open(project):
    with pytest.raises(SystemExit, match="still open"):
        pe.ready(T0 + timedelta(days=2))


def test_groups_and_negatives(project):
    pos = pe.positives()
    assert dict(zip(pos["host"], pos["group"])) == {
        "a1.phish-new.example": "primary", "x.typedream.app": "seen_before", "old.seen.example": "seen_before",
        "b2.other-phish.example": "primary", "c3.third-phish.example": "primary"}
    neg, counts = pe.negatives(pe.ready(END), pos)
    assert set(neg.loc[neg.group == "legit_apex", "host"]) == {"legit-apex.example", "another-apex.example"}  # seen.example excluded
    assert set(neg.loc[neg.group == "legit_subdomain", "host"]) == {"docs.legit-one.example", "a.legit-one.example"}
    assert counts["legit_apex"]["excluded"] == 1


@needs_bundle
def test_e1_is_reproducible_and_writes_no_urls(project):
    a, b = pe.run_e1(END), pe.run_e1(END)
    a.pop("run_at_utc"), b.pop("run_at_utc")
    assert a == b
    text = json.dumps(a)
    assert "victim" not in text and "http" not in text and "a1.phish-new" not in text  # aggregates only
    assert "raw_model" in a["groups"]["primary"] and "final_api" in a["groups"]["primary"]
    assert a["criteria"]["E1-a recall@alert>=0.75 & lower>=0.70 on >=500 primary"].startswith("not established (n = 3")
    assert a["criteria"]["E2"].startswith("not run")


@needs_bundle
def test_full_url_mode_verifies_hash_and_keeps_urls_in_memory(project):
    _, state = project
    res = pe.run_e1(END, full_urls=True)["full_url_analysis"]
    assert res["status"] == "ok" and "victim" not in json.dumps(res) and "http" not in json.dumps(res)
    state["tamper"] = b"https://tampered.example/\n"
    bad = pe.run_e1(END, full_urls=True)["full_url_analysis"]
    assert bad == {"status": "unavailable", "reason": "hash mismatch for commit c1"}


def test_bootstrap_is_deterministic():
    hits = [True] * 30 + [False] * 70
    assert pe.ci(hits) == pe.ci(hits) and pe.ci(hits)[0] < 0.3 < pe.ci(hits)[1]
    assert pe.rate([]) == {"n": 0, "rate": None, "ci95": None}


def test_criteria_thresholds_unchanged():
    import pandas as pd
    legit = pd.DataFrame({"category": ["low_risk"] * 99 + ["high_risk"], "brand_high": [False] * 100})
    groups = {"primary": {"raw_model": {"at_alert": {"n": 600, "rate": 0.76, "ci95": [0.71, 0.80]}}},
              "legit_apex": {"raw_model": {"at_high": {"rate": 0.061}}}}
    c = pe.criteria(groups, legit, {})
    assert c["E1-a recall@alert>=0.75 & lower>=0.70 on >=500 primary"] == "pass"
    assert c["E1-b apex FPR@high<=0.06"] == "fail"
    assert c["E1-c final high risk on legit (apex+subdomain)<=0.02"]["result"] == "pass"
    assert c["E4 brand high on legit<=0.01 & upper<=0.02"]["result"] == "pass"


def test_platform_list_is_versioned_and_reproducible():
    data = json.loads(pp.LIST_PATH.read_text(encoding="utf-8"))
    assert data["version"] == "1" and data == json.loads(json.dumps(pp.build()))  # regenerates identically
    assert data["sources"]["psl_private"]["sha256"] == hashlib.sha256(pp.PSL_SNAPSHOT.read_bytes()).hexdigest()
    assert pp.is_platform("a.typedream.app") and not pp.is_platform("typedream.app") and not pp.is_platform("x.example.com")


def test_unicode_platform_suffixes_match_punycode_hosts():
    from tldextract.suffix_list import extract_tlds_from_suffix_list

    from ml.feature_extraction import get_host
    _, private = extract_tlds_from_suffix_list(pp.PSL_SNAPSHOT.read_text(encoding="utf-8"))
    idn = sorted(s.removeprefix("*.") for s in private if not s.isascii() and not s.startswith("!"))
    assert len(idn) == 13 and all(s.isascii() for s in pp.suffixes())  # regression: these 13 were stored as Unicode
    for s in idn:
        host = get_host(f"https://login.{s}/")                  # pipeline form: punycode
        assert host.startswith("login.xn--") or ".xn--" in host
        assert pp.is_platform(host) and not pp.is_platform(get_host(f"https://{s}/"))  # the platform's own apex
    assert pp.is_platform("login.xn--41a.xn--p1acf")             # я.рус given directly as punycode
    assert pp.is_platform("x.pages.dev") and pp.is_platform("x.weebly.com")  # ASCII: PSL private and production list
    assert not pp.is_platform("login.xn--unknown-platform.xn--p1acf") and not pp.is_platform("a.bank.example")


def test_criteria_without_legit_data_are_not_established():
    import pandas as pd
    c = pe.criteria({}, pd.DataFrame({"category": [], "brand_high": []}), {})
    assert c["E1-c final high risk on legit (apex+subdomain)<=0.02"]["result"].startswith("not established")
    assert c["E4 brand high on legit<=0.01 & upper<=0.02"]["result"].startswith("not established")
    assert c["E1-b apex FPR@high<=0.06"].startswith("not established")  # regression: used to be a bare null
    assert c["E1-d subdomain caution-or-worse (reported, no bar)"] == {"n": 0, "rate": None, "ci95": None}


def test_freeze_fails_closed_on_dropped_entry_deleted_file_and_tampered_collection(project, monkeypatch):
    tmp, _ = project
    monkeypatch.setattr(pc, "FROZEN_FILES", [])  # an edit that silently drops an entry from the freeze set
    with pytest.raises(SystemExit, match=r"no longer checked: \['code.py'\]"):
        pe.ready(END)
    monkeypatch.setattr(pc, "FROZEN_FILES", ["code.py"])
    snap = tmp / pc.manifest()[0]["file"]
    snap.write_text(snap.read_text(encoding="utf-8") + "https://added-later.example/\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="changed since collection"):
        pe.ready(END)
    (tmp / "code.py").unlink()
    with pytest.raises(FileNotFoundError):
        pe.ready(END)


def test_real_freeze_set_covers_prior_sets_and_packages():
    assert set(pc.PRIOR_SETS + pc.PRE_FREEZE_OPENPHISH) <= set(pc.FROZEN_FILES)
    assert {"xgboost", "scikit-learn", "tldextract", "numpy", "pandas"} <= set(pc.FROZEN_PACKAGES)


def test_criteria_compare_unrounded_rates():
    import pandas as pd
    legit = pd.DataFrame({"category": ["high_risk"] * 63 + ["low_risk"] * 3086, "brand_high": [False] * 3149})
    c = pe.criteria({}, legit, {})  # 63 / 3149 = 0.020006 > 0.02, which rounds to 0.0200
    assert c["E1-c final high risk on legit (apex+subdomain)<=0.02"]["result"] == "fail"


def test_model_failure_is_counted_not_scored_as_negative():
    import pandas as pd
    items = pd.DataFrame({"group": ["legit_apex"] * 3, "prob": [0.9, None, 0.1], "reg": ["a", "b", "c"],
                          "category": ["low_risk"] * 3, "brand_high": [False] * 3, **{r: [False] * 3 for r in pe.QUERY_RULES}})
    raw = pe.summarise(items, {"alert": 0.5, "high": 0.8})["legit_apex"]["raw_model"]
    assert raw["model_unavailable"] == 1 and raw["at_high"]["n"] == 2 and raw["at_high"]["rate"] == 0.5


@needs_bundle
def test_e3_reports_source_failures(project, monkeypatch):
    from backend.evidence import TIResult
    monkeypatch.setattr(pe.time, "sleep", lambda s: None)
    for name in ("check_phishtank", "check_openphish_local"):
        monkeypatch.setattr(pe.threat_intel, name, lambda u, **_: TIResult("PhishTank", "error", "timeout", "t"))
    res = pe.run_e3(END, n=2)
    assert res["source_status_counts"] == {"PhishTank: error": 4} and res["timings"]["pipeline_available_sources"]["n"] == 2
