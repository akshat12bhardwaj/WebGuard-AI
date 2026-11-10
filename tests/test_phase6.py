"""Phase 6 collector: freeze guard, privacy, no-overwrite, cadence, window and Tranco rules (synthetic data, no network)."""
import json
from datetime import UTC, datetime, timedelta

import pytest

from ml import phase6_collect as pc

T0 = datetime(2026, 10, 20, 0, 0, tzinfo=UTC)


@pytest.fixture
def env(tmp_path, monkeypatch):
    for name in ("model.bin", "code.py"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    proto = tmp_path / "PROTO.md"
    proto.write_text("protocol v1", encoding="utf-8")
    monkeypatch.setattr(pc, "ROOT", tmp_path)
    monkeypatch.setattr(pc, "FRESH", tmp_path / "fresh")
    monkeypatch.setattr(pc, "MANIFEST", tmp_path / "fresh" / "manifest.jsonl")
    monkeypatch.setattr(pc, "FROZEN", tmp_path / "frozen.json")
    monkeypatch.setattr(pc, "PROTOCOL", proto)
    monkeypatch.setattr(pc, "FROZEN_FILES", ["model.bin", "code.py"])
    state = {"commit": "c1", "feed": b"https://a.phish.example/login?email=victim@example.com#x\nhttps://u:p@b.phish.example/x\nbad url\n"}

    def fake_get(url):
        if url == pc.OPENPHISH_FEED:
            return state["feed"]
        if url == pc.OPENPHISH_COMMITS:
            return json.dumps([{"sha": state["commit"]}]).encode()
        if url.startswith(pc.TRANCO_API):
            lid = "NEWSUB" if "subdomains" in url else "NEWAPX"
            return json.dumps({"list_id": state.get("tranco_id", lid), "created_on": state["tranco_created"],
                               "download": f"https://tranco.example/{lid}"}).encode()
        return b"1,example.com\n2,docs.example.org\n"
    monkeypatch.setattr(pc, "_get", fake_get)
    return tmp_path, state


def test_sanitize_drops_query_fragment_userinfo():
    assert pc.sanitize("https://u:p@A.Example.com:8443/x/y?email=a@b.c#frag") == "https://a.example.com:8443/x/y"
    assert pc.sanitize("example.com") == "http://example.com/"
    assert pc.sanitize("javascript:alert(1)") is None
    assert pc.sanitize("http://bad url/x") is None  # regression: spaces in the host used to be stored


def test_collection_requires_freeze_and_stops_on_changes(env):
    tmp, _ = env
    with pytest.raises(SystemExit, match="not frozen"):
        pc.collect_openphish(T0)
    pc.freeze(T0)
    with pytest.raises(SystemExit, match="already exists"):
        pc.freeze(T0)
    (tmp / "code.py").write_text("changed", encoding="utf-8")  # e.g. a rule tweak after the freeze
    with pytest.raises(SystemExit, match="changed since the freeze"):
        pc.collect_openphish(T0)


def test_snapshot_privacy_provenance_and_no_overwrite(env):
    tmp, state = env
    pc.freeze(T0)
    rec = pc.collect_openphish(T0)
    stored = (tmp / rec["file"]).read_text(encoding="utf-8")
    assert "victim" not in stored and "?" not in stored and "u:p@" not in stored
    assert stored.split() == ["https://a.phish.example/login", "https://b.phish.example/x"]
    assert rec["raw_urls"] == 3 and rec["invalid"] == 1 and rec["query_or_fragment_dropped"] == 1
    assert len(rec["raw_sha256"]) == 64 and rec["commit"] == "c1"
    with pytest.raises(SystemExit, match="12 h"):           # cadence
        pc.collect_openphish(T0 + timedelta(hours=11))
    assert pc.collect_openphish(T0 + timedelta(hours=13)) is None  # same commit -> nothing stored
    state["commit"] = "c2"
    (tmp / "fresh" / "openphish" / (T0 + timedelta(hours=25)).strftime(pc.STAMP)).with_suffix(".txt").write_text("x")
    with pytest.raises(FileExistsError):                     # never overwrite an existing file
        pc.collect_openphish(T0 + timedelta(hours=25))


def test_window_closes_and_tranco_must_be_later(env):
    _, state = env
    pc.freeze(T0)
    pc.collect_openphish(T0)
    state["tranco_created"] = (T0 + timedelta(days=11)).isoformat()
    with pytest.raises(SystemExit, match="only after"):
        pc.collect_tranco(T0 + timedelta(days=3))
    end = T0 + timedelta(days=pc.WINDOW_DAYS)
    state["commit"] = "c9"
    with pytest.raises(SystemExit, match="window is closed"):
        pc.collect_openphish(end)
    state["tranco_id"] = "Q2Y54"                             # pre-freeze list: refused
    with pytest.raises(SystemExit, match="already used"):
        pc.collect_tranco(end + timedelta(days=1))
    del state["tranco_id"]
    state["tranco_created"] = (T0 + timedelta(days=5)).isoformat()  # created inside the window: refused
    with pytest.raises(SystemExit, match="not later"):
        pc.collect_tranco(end + timedelta(days=1))
    state["tranco_created"] = (end + timedelta(hours=1)).isoformat()
    recs = pc.collect_tranco(end + timedelta(days=1))
    assert [r["list_id"] for r in recs] == ["NEWAPX", "NEWSUB"] and all(len(r["file_sha256"]) == 64 for r in recs)


def test_fresh_hosts_dedup_first_sighting(env):
    _, state = env
    pc.freeze(T0)
    pc.collect_openphish(T0)
    state["commit"], state["feed"] = "c2", b"https://WWW.a.phish.example/other\nhttps://c.phish.example/\n"
    pc.collect_openphish(T0 + timedelta(hours=12))
    first = pc.fresh_hosts()
    assert first == {"a.phish.example": T0.strftime(pc.STAMP), "b.phish.example": T0.strftime(pc.STAMP),
                     "c.phish.example": (T0 + timedelta(hours=12)).strftime(pc.STAMP)}


def test_f1_host_groups():
    regs, seen = {"pages.dev", "old-attacker.com", "compromised.org", "typedream.app"}, {"x.pages.dev"}
    assert pc.classify("x.pages.dev", regs, seen) == "seen_before"
    assert pc.classify("brand-new-phish.com", regs, seen) == "primary"
    assert pc.classify("y.pages.dev", regs, seen) == "supplementary"           # PSL private suffix
    assert pc.classify("a.typedream.app", regs, seen) == "supplementary"       # missing from production list, in PSL private
    assert pc.classify("x.weebly.com", regs | {"weebly.com"}, seen) == "supplementary"  # production list
    assert pc.classify("login.compromised.org", regs, seen) == "excluded_other"     # never assumed to be a platform


def test_window_constants_match_protocol():
    assert (pc.WINDOW_DAYS, pc.MAX_SNAPSHOTS, pc.MIN_HOURS) == (10, 20, 12)
