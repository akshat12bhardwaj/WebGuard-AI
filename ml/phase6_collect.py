"""Phase 6 fresh held-out collection (docs/PHASE6_PROTOCOL.md). Collects data only; never scores anything.

Usage (repository root):
  python -m ml.phase6_collect freeze      # once, after the protocol is approved: records system + protocol hashes
  python -m ml.phase6_collect openphish   # at most every 12 h, within the 10-day window
  python -m ml.phase6_collect tranco      # once, after the window has closed
  python -m ml.phase6_collect status      # counts only (no model output)
Stores data/fresh/ (gitignored; OpenPhish forbids redistribution) and data/fresh/manifest.jsonl.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from urllib.parse import urlsplit

from ml.external_data import (
    OPENPHISH_COMMITS,
    OPENPHISH_FEED,
    TRANCO_API,
    _get,
    parse_openphish,
)
from ml.feature_extraction import (
    InvalidURLError,
    get_host,
    normalize_url,
    registered_domain,
)
from ml.phase6_platforms import PSL_SNAPSHOT, is_platform
from ml.utils import ROOT, sha256

FRESH = ROOT / "data" / "fresh"
MANIFEST = FRESH / "manifest.jsonl"
FROZEN = ROOT / "reports" / "phase6" / "frozen_system.json"
PROTOCOL = ROOT / "docs" / "PHASE6_PROTOCOL.md"
WINDOW_DAYS, MAX_SNAPSHOTS, MIN_HOURS = 10, 20, 12
PRE_FREEZE_TRANCO = {"N26XW", "Q2Y54"}
PRIOR_SETS = ["data/processed/dataset.csv", "data/processed/kaggle_binary_hosts.csv", "data/external/external_test.csv",
              *[f"data/processed/exp03_new_{s}.csv" for s in ("train", "val", "test")]]
PRE_FREEZE_OPENPHISH = ["data/raw/openphish/feed_20261015T035838Z.txt", "data/feeds/openphish/feed_20261016T031604Z.txt"]
# Everything that can change an E1-E4 number: production system, collector, runner, evaluation-only platform list, the
# helpers they import and the prior sets that define the exclusions/F1 groups. The bundled PSL snapshot (outside the
# repo), the protocol and the versions of the packages that score and sample are added in system_hashes().
FROZEN_FILES = ["models/model_bundle.joblib", "ml/feature_extraction.py", "ml/predict.py", "ml/utils.py",
                "ml/external_data.py", "ml/kaggle_data.py",
                *[f"backend/{m}.py" for m in ("rules", "fusion", "service", "threat_intel", "evidence", "api")],
                "ml/phase6_collect.py", "ml/phase6_evaluate.py", "ml/phase6_platforms.py", "ml/phase6_platforms.json",
                *PRIOR_SETS, *PRE_FREEZE_OPENPHISH]
FROZEN_PACKAGES = ("python", "xgboost", "scikit-learn", "numpy", "pandas", "scipy", "shap", "joblib", "tldextract")
STAMP = "%Y%m%dT%H%M%SZ"
PSL_KEY = "tldextract/.tld_set_snapshot (outside repo)"


def sanitize(url: str) -> str | None:
    """scheme://host[:port]/path - drops userinfo, query and fragment (may hold e-mail addresses or tokens)."""
    try:
        p = urlsplit(normalize_url(url))
        get_host(url)  # same host validation as the pipeline (rejects spaces and other invalid characters)
        port = f":{p.port}" if p.port else ""
        return f"{p.scheme.lower()}://{p.hostname}{port}{p.path or '/'}"
    except InvalidURLError:
        return None


def system_hashes() -> dict[str, str]:
    hashes = {f: sha256(ROOT / f) for f in [*FROZEN_FILES, str(PROTOCOL.relative_to(ROOT)).replace("\\", "/")]}
    hashes[PSL_KEY] = sha256(PSL_SNAPSHOT)
    hashes |= {f"package {p}": platform.python_version() if p == "python" else version(p) for p in FROZEN_PACKAGES}
    return hashes


def freeze(now: datetime) -> dict:
    if FROZEN.exists():
        raise SystemExit(f"{FROZEN} already exists: the protocol is frozen. A new version needs a new record.")
    rec = {"frozen_at_utc": now.strftime(STAMP), "sha256": system_hashes()}
    FROZEN.parent.mkdir(parents=True, exist_ok=True)
    with open(FROZEN, "x", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    return rec


def check_frozen() -> None:
    if not FROZEN.exists():
        raise SystemExit("Protocol not frozen: review docs/PHASE6_PROTOCOL.md, then run `python -m ml.phase6_collect freeze`.")
    frozen = json.loads(FROZEN.read_text(encoding="utf-8")).get("sha256", {})
    current = system_hashes()
    missing = sorted(set(current) - set(frozen))
    dropped = sorted(set(frozen) - set(current))  # e.g. an edit that removes an entry from FROZEN_FILES
    changed = sorted(f for f in set(current) & set(frozen) if frozen[f] != current[f])
    if missing or dropped or changed:  # fail closed: an unrecorded or unchecked file is as bad as a changed one
        raise SystemExit(f"Freeze check failed (protocol section 8). Missing from the freeze record: {missing}; "
                         f"recorded but no longer checked: {dropped}; changed since the freeze: {changed}.")


def manifest() -> list[dict]:
    return [json.loads(line) for line in MANIFEST.read_text(encoding="utf-8").splitlines()] if MANIFEST.exists() else []


def _append(rec: dict) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")


def _snapshots() -> list[dict]:
    return [m for m in manifest() if m["source"] == "openphish"]


def window(now: datetime) -> tuple[datetime | None, bool]:
    """(window start, closed?) - the window opens at the first fresh snapshot."""
    snaps = _snapshots()
    if not snaps:
        return None, False
    start = datetime.strptime(snaps[0]["fetched_at_utc"], STAMP).replace(tzinfo=UTC)
    return start, now >= start + timedelta(days=WINDOW_DAYS) or len(snaps) >= MAX_SNAPSHOTS


def collect_openphish(now: datetime) -> dict | None:
    check_frozen()
    snaps = _snapshots()
    _, closed = window(now)
    if closed:
        raise SystemExit("The 10-day OpenPhish window is closed; no further snapshots (protocol section 7).")
    if snaps and now - datetime.strptime(snaps[-1]["fetched_at_utc"], STAMP).replace(tzinfo=UTC) < timedelta(hours=MIN_HOURS):
        raise SystemExit(f"Last snapshot is less than {MIN_HOURS} h old; the feed updates every 12 h.")
    raw = _get(OPENPHISH_FEED)
    commit = json.loads(_get(OPENPHISH_COMMITS))[0]["sha"]
    if commit in {s["commit"] for s in snaps}:
        print(f"Feed commit {commit[:7]} already collected; nothing stored.")
        return None
    urls = parse_openphish(raw.decode("utf-8"))
    clean = [c for c in map(sanitize, urls) if c]
    stored = list(dict.fromkeys(clean))
    stamp = now.strftime(STAMP)
    path = FRESH / "openphish" / f"{stamp}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x", encoding="utf-8") as f:  # never overwrite
        f.write("\n".join(stored) + "\n")
    rec = {"source": "openphish", "fetched_at_utc": stamp, "feed_url": OPENPHISH_FEED, "commit": commit,
           "raw_sha256": hashlib.sha256(raw).hexdigest(), "raw_urls": len(urls),
           "query_or_fragment_dropped": sum(("?" in u) or ("#" in u) for u in urls), "invalid": len(urls) - len(clean),
           "stored_urls": len(stored), "file": str(path.relative_to(ROOT)).replace("\\", "/"), "file_sha256": sha256(path)}
    _append(rec)
    return rec


def collect_tranco(now: datetime) -> list[dict]:
    check_frozen()
    start, closed = window(now)
    if not closed:
        raise SystemExit("Collect Tranco only after the OpenPhish window has closed (protocol section 4).")
    end = start + timedelta(days=WINDOW_DAYS)
    used = PRE_FREEZE_TRANCO | {m["list_id"] for m in manifest() if m["source"].startswith("tranco")}
    out = []
    for subdomains in (False, True):
        meta = json.loads(_get(TRANCO_API + ("?subdomains=true" if subdomains else "")))
        created = datetime.fromisoformat(meta["created_on"]).replace(tzinfo=UTC)
        if meta["list_id"] in used or created < end:
            raise SystemExit(f"Tranco list {meta['list_id']} ({meta['created_on']}) is not later than the window end "
                             f"{end:%Y-%m-%d} or was already used; try again on a later day.")
        path = FRESH / "tranco" / f"{meta['list_id']}.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "xb") as f:
            f.write(_get(meta["download"]))
        rec = {"source": "tranco_subdomains" if subdomains else "tranco", "fetched_at_utc": now.strftime(STAMP),
               "list_id": meta["list_id"], "created_on": meta["created_on"], "download": meta["download"],
               "file": str(path.relative_to(ROOT)).replace("\\", "/"), "file_sha256": sha256(path)}
        _append(rec)
        out.append(rec)
    return out


def prior_sets() -> tuple[set[str], set[str]]:
    """(prior registered domains, prior hosts) from every pre-freeze data set and OpenPhish snapshot (protocol section 5)."""
    import pandas as pd
    regs, hosts = set(), set()
    for f in PRIOR_SETS:
        d = pd.read_csv(ROOT / f, keep_default_na=False, usecols=["host", "reg_domain"])
        regs |= set(d["reg_domain"])
        hosts |= set(d["host"])
    for f in PRE_FREEZE_OPENPHISH:
        for u in parse_openphish((ROOT / f).read_text(encoding="utf-8")):
            try:
                h = get_host(u)
            except InvalidURLError:
                continue
            hosts.add(h)
            regs.add(registered_domain(h))
    return regs, hosts


def classify(host: str, prior_regs: set[str], prior_hosts: set[str]) -> str:
    """F1 groups: seen_before | primary | supplementary (evaluation-only platform list) | excluded_other."""
    if host in prior_hosts:
        return "seen_before"
    if registered_domain(host) not in prior_regs:
        return "primary"
    return "supplementary" if is_platform(host) else "excluded_other"


def fresh_hosts() -> dict[str, str]:
    """Unique fresh phishing hosts -> first snapshot they appeared in (protocol section 5)."""
    first = {}
    for s in _snapshots():
        for u in (ROOT / s["file"]).read_text(encoding="utf-8").splitlines():
            if not u:
                continue
            first.setdefault(get_host(u), s["fetched_at_utc"])
    return first


def status(now: datetime) -> dict:
    start, closed = window(now)
    hosts = fresh_hosts()
    regs, seen = prior_sets() if hosts else (set(), set())
    groups = {g: 0 for g in ("primary", "supplementary", "excluded_other", "seen_before")}
    for h in hosts:
        groups[classify(h, regs, seen)] += 1
    return {"frozen": FROZEN.exists(), "snapshots": len(_snapshots()), "window_start": start and start.strftime(STAMP),
            "window_closed": closed, "unique_hosts": len(hosts), "host_groups_counts_only": groups,
            "tranco_lists": [m["list_id"] for m in manifest() if m["source"].startswith("tranco")]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["freeze", "openphish", "tranco", "status"])
    cmd, now = ap.parse_args().command, datetime.now(UTC)
    result = {"freeze": freeze, "openphish": collect_openphish, "tranco": collect_tranco, "status": status}[cmd](now)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
