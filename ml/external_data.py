"""Collect OpenPhish + Tranco snapshots and build the independent external test set.

Only the lists are downloaded; no listed website is ever visited.
Usage: python -m ml.external_data [--n-neg 3000] [--top 100000]
Writes: data/raw/openphish/feed_<UTC>.txt, data/raw/tranco/<list_id>.csv, data/external/external_test.csv,
        reports/metrics/external_test_provenance.json
OpenPhish terms: research use allowed, redistribution forbidden -> snapshots stay local (gitignored).
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import urllib.request
from datetime import UTC, datetime

import pandas as pd

from ml.feature_extraction import (
    SHARED_HOSTING_SUFFIXES,
    InvalidURLError,
    get_host,
    is_ip,
    registered_domain,
)
from ml.utils import METRICS, PROCESSED, RAW, ROOT, SEED, get_logger, save_json, sha256

OPENPHISH_FEED = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
OPENPHISH_COMMITS = "https://api.github.com/repos/openphish/public_feed/commits?per_page=1"
TRANCO_API = "https://tranco-list.eu/api/lists/date/latest"
EXTERNAL = ROOT / "data" / "external" / "external_test.csv"
log = get_logger("external_data")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "website-risk-analyzer-student/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def parse_openphish(text: str) -> list[str]:
    """One URL per line; blank lines and comments ignored; order-preserving de-duplication."""
    return list(dict.fromkeys(u.strip() for u in text.splitlines() if u.strip() and not u.startswith("#")))


def parse_tranco(text: str) -> pd.DataFrame:
    """Tranco CSV: 'rank,domain' rows without a header."""
    rows = [(int(r[0]), r[1].strip().lower()) for r in csv.reader(io.StringIO(text)) if len(r) == 2 and r[0].isdigit()]
    if not rows:
        raise ValueError("no rank,domain rows found")
    return pd.DataFrame(rows, columns=["rank", "domain"])


def host_rows(urls, label: int, subset: str) -> pd.DataFrame:
    rows = []
    for u in urls:
        try:
            h = get_host(u)
        except InvalidURLError:
            continue
        rows.append({"url": u, "host": h, "reg_domain": registered_domain(h), "is_phishing": label, "subset": subset})
    return pd.DataFrame(rows).drop_duplicates("host")


def fetch_tranco(subdomains: bool) -> tuple[pd.DataFrame, dict]:
    meta = json.loads(_get(TRANCO_API + ("?subdomains=true" if subdomains else "")))
    path = RAW / "tranco" / f"{meta['list_id']}.csv"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_get(meta["download"]))
    meta.update(local_path=str(path.relative_to(ROOT)), sha256=sha256(path))
    return parse_tranco(path.read_text(encoding="utf-8")), meta


def build(n_neg: int, top: int) -> dict:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    feed_path = RAW / "openphish" / f"feed_{stamp}.txt"
    feed_path.parent.mkdir(parents=True, exist_ok=True)
    feed_path.write_bytes(_get(OPENPHISH_FEED))
    commit = json.loads(_get(OPENPHISH_COMMITS))[0]
    phish_urls = parse_openphish(feed_path.read_text(encoding="utf-8"))
    pos = host_rows(phish_urls, 1, "openphish")

    apex, meta_apex = fetch_tranco(subdomains=False)
    subs, meta_sub = fetch_tranco(subdomains=True)
    shared = lambda h: any(h == s or h.endswith("." + s) for s in SHARED_HOSTING_SUFFIXES)
    apex_top = apex[apex["rank"] <= top].sample(frac=1, random_state=SEED)
    neg_apex = host_rows((f"https://{d}/" for d in apex_top["domain"]), 0, "tranco_apex")
    sub_top = subs[subs["rank"] <= top]
    sub_hosts = host_rows((f"https://{d}/" for d in sub_top["domain"]), 0, "tranco_subdomain")
    sub_hosts = sub_hosts[(sub_hosts["host"] != sub_hosts["reg_domain"]) & ~sub_hosts["host"].map(is_ip)]
    sub_hosts = sub_hosts.sample(frac=1, random_state=SEED)

    report = {"built_at_utc": stamp, "openphish": {
        "feed_url": OPENPHISH_FEED, "github_commit": commit["sha"], "commit_time_utc": commit["commit"]["committer"]["date"],
        "local_path": str(feed_path.relative_to(ROOT)), "sha256": sha256(feed_path),
        "urls": len(phish_urls), "valid_unique_hosts": len(pos)},
        "tranco_apex": {k: meta_apex[k] for k in ("list_id", "created_on", "download", "local_path", "sha256")},
        "tranco_subdomain": {k: meta_sub[k] for k in ("list_id", "created_on", "download", "local_path", "sha256")},
        "negative_rank_cutoff": top}

    # Exclusions: shared/user-content platforms (anyone can publish there), domains also seen among
    # OpenPhish positives (ambiguous), and any registered domain used to train either model.
    train_regs = set(pd.read_csv(PROCESSED / "train.csv", keep_default_na=False, usecols=["reg_domain"])["reg_domain"])
    kaggle = PROCESSED / "kaggle_binary_hosts.csv"
    kaggle_regs = set(pd.read_csv(kaggle, keep_default_na=False, usecols=["reg_domain"])["reg_domain"]) if kaggle.exists() else set()
    phish_regs = set(pos["reg_domain"])
    ex = {}
    for name, df in (("tranco_apex", neg_apex), ("tranco_subdomain", sub_hosts)):
        keep = ~df["host"].map(shared) & ~df["reg_domain"].isin(phish_regs)
        ex[name] = {"candidates": len(df), "dropped_shared_or_ambiguous": int((~keep).sum())}
        df = df[keep]
        in_train = df["reg_domain"].isin(train_regs | kaggle_regs)
        ex[name]["dropped_training_domain_overlap"] = int(in_train.sum())
        ex[name]["kept"] = min(n_neg, int((~in_train).sum()))
        if name == "tranco_apex":
            neg_apex = df[~in_train].head(n_neg)
        else:
            sub_hosts = df[~in_train].head(n_neg)
    in_train = pos["reg_domain"].isin(train_regs | kaggle_regs)
    ex["openphish"] = {"candidates": len(pos), "dropped_training_domain_overlap": int(in_train.sum()),
                       "kept": int((~in_train).sum())}
    pos = pos[~in_train]
    out = pd.concat([pos, neg_apex, sub_hosts], ignore_index=True)
    out = out[~out["host"].duplicated(keep=False)]  # any host in two subsets is ambiguous
    assert not set(out["reg_domain"]) & train_regs, "training-domain overlap left in external set"
    EXTERNAL.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(EXTERNAL, index=False)
    report.update(exclusions=ex, final_counts=out["subset"].value_counts().to_dict(),
                  overlap_policy="registered domains in PhiUSIIL train or any Kaggle binary host removed")
    save_json(report, METRICS / "external_test_provenance.json")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n-neg", type=int, default=3000, help="max legitimate hosts per Tranco subset")
    ap.add_argument("--top", type=int, default=100_000, help="only use Tranco ranks <= top")
    args = ap.parse_args()
    rep = build(args.n_neg, args.top)
    log.info("External test set: %s (exclusions %s)", rep["final_counts"], rep["exclusions"])


if __name__ == "__main__":
    main()
