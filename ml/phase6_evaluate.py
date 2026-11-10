"""Phase 6 evaluation runner (docs/PHASE6_PROTOCOL.md). Scores the FROZEN system on fresh held-out data.

Fails closed unless the freeze record matches every evaluation-critical file (including this one), the 10-day OpenPhish
window is closed and the later Tranco lists were collected. Changes nothing in production; writes only aggregate
results to reports/phase6/ (exclusive create, never overwrites). No URL is written to any output.
Usage:
  python -m ml.phase6_evaluate e1 [--with-phishtank] [--full-urls]
  python -m ml.phase6_evaluate e3
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from datetime import UTC, datetime

import numpy as np
import pandas as pd

from backend import threat_intel
from backend.fusion import fuse
from backend.service import Analyzer
from ml import phase6_collect as pc
from ml.external_data import _get, parse_openphish, parse_tranco
from ml.feature_extraction import (
    SHARED_HOSTING_SUFFIXES,
    InvalidURLError,
    get_host,
    is_ip,
    is_public_suffix,
    registered_domain,
)
from ml.predict import predict
from ml.utils import sha256

SEED, N_BOOT, N_NEG, APEX_MAX_RANK, PER_DOMAIN, MIN_POSITIVES = 42, 2000, 2000, 100_000, 3, 500
QUERY_RULES = ("BRAND_IN_PATH", "HTTP_WITH_CREDENTIAL_WORDS", "NO_HTTPS", "URL_CREDENTIALS_IN_AUTHORITY", "VERY_LONG_URL")
GITHUB_RAW = "https://raw.githubusercontent.com/openphish/public_feed/{commit}/feed.txt"
PROTOCOL_VERSION = "1.0"


def ci(hits) -> list[float] | None:
    """95% percentile bootstrap of a rate (2,000 resamples, seed 42; protocol section 6)."""
    hits = np.asarray(hits, dtype=float)
    if not len(hits):
        return None
    b = np.random.default_rng(SEED).choice(hits, (N_BOOT, len(hits))).mean(1)
    # unrounded: criteria compare these values, and rounding could turn e.g. 63/3149 = 0.020006 into a pass at <= 0.02
    return [float(np.percentile(b, 2.5)), float(np.percentile(b, 97.5))]


def rate(hits) -> dict:
    hits = np.asarray(hits, dtype=bool)
    return {"n": len(hits), "rate": float(hits.mean()) if len(hits) else None, "ci95": ci(hits)}


def ready(now: datetime) -> dict:
    pc.check_frozen()
    _, closed = pc.window(now)
    if not closed:
        raise SystemExit("The OpenPhish window is still open: no scoring before it closes (protocol section 8).")
    tranco = {m["source"]: m for m in pc.manifest() if m["source"].startswith("tranco")}
    if set(tranco) != {"tranco", "tranco_subdomains"}:
        raise SystemExit("Both later Tranco lists must be collected first: python -m ml.phase6_collect tranco")
    bad = [m["file"] for m in pc.manifest() if not (pc.ROOT / m["file"]).is_file() or sha256(pc.ROOT / m["file"]) != m["file_sha256"]]
    if bad:
        raise SystemExit(f"Collected files missing or changed since collection (manifest hash): {bad}")
    return tranco


def positives() -> pd.DataFrame:
    """One row per fresh phishing host: first stored (sanitised) URL, first snapshot, F1 group."""
    rows, seen = [], set()
    for s in pc.manifest():
        if s["source"] != "openphish":
            continue
        for u in (pc.ROOT / s["file"]).read_text(encoding="utf-8").splitlines():
            if u and (h := get_host(u)) not in seen:
                seen.add(h)
                rows.append({"host": h, "url": u, "reg": registered_domain(h), "snapshot": s["fetched_at_utc"]})
    df = pd.DataFrame(rows, columns=["host", "url", "reg", "snapshot"])
    regs, prior_hosts = pc.prior_sets()
    df["group"] = [pc.classify(h, regs, prior_hosts) for h in df["host"]]
    return df


def negatives(tranco: dict, pos: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    regs, _ = pc.prior_sets()
    banned = regs | set(pos["reg"])
    shared = lambda h: any(h == s or h.endswith("." + s) for s in SHARED_HOSTING_SUFFIXES)
    counts, parts = {}, []
    for source, group in (("tranco", "legit_apex"), ("tranco_subdomains", "legit_subdomain")):
        t = parse_tranco((pc.ROOT / tranco[source]["file"]).read_text(encoding="utf-8")).sort_values("rank")
        if group == "legit_apex":
            t = t[t["rank"] <= APEX_MAX_RANK]
        rows = []
        for rank, d in zip(t["rank"], t["domain"]):
            try:
                h = get_host(f"https://{d}/")
            except InvalidURLError:
                continue
            rows.append({"host": h, "reg": registered_domain(h), "rank": rank})
        df = pd.DataFrame(rows, columns=["host", "reg", "rank"]).drop_duplicates("host")
        c = {"candidates": len(df)}
        df = df[(df["host"] == df["reg"]) if group == "legit_apex" else (df["host"] != df["reg"])]
        keep = ~(df["reg"].isin(banned) | df["host"].map(is_ip) | df["host"].map(is_public_suffix) | df["host"].map(shared))
        c["excluded"] = int((~keep).sum())
        df = df[keep]
        if group == "legit_subdomain":
            df = df.groupby("reg", sort=False).head(PER_DOMAIN)
        df = df.sample(min(N_NEG, len(df)), random_state=SEED).sort_values("rank")
        c["sampled"] = len(df)
        counts[group] = c
        parts.append(df.assign(group=group, url=[f"https://{h}/" for h in df["host"]]))
    neg = pd.concat(parts, ignore_index=True)
    both = set(neg["host"]) & set(pos["host"])
    counts["dropped_in_both_classes"] = len(both)
    return neg[~neg["host"].isin(both)], counts


def score(urls, analyzer: Analyzer) -> pd.DataFrame:
    rows = []
    for u in urls:
        ev, caveats = analyzer.collect(u)
        fired = {r.rule_id for r in ev.rules if r.status == "fired"}
        rows.append({"prob": ev.model.probability, "category": fuse(ev, caveats).category,
                     "brand_high": "BRAND_IN_HOST_MISMATCH" in fired, **{r: r in fired for r in QUERY_RULES},
                     "ti": {t.source: t.status for t in ev.threat_intel}})
    return pd.DataFrame(rows)


def summarise(items: pd.DataFrame, th: dict) -> dict:
    out = {}
    for g, d in items.groupby("group", sort=True):
        hi_final = d["category"].isin(["high_risk", "dangerous"])
        m = d[d["prob"].notna()]  # a model failure is counted, never scored as "below threshold"
        out[g] = {
            "raw_model": {"model_unavailable": len(d) - len(m),
                          "at_alert": rate(m["prob"] >= th["alert"]), "at_high": rate(m["prob"] >= th["high"]),
                          # each registered domain counts once; point estimates only (protocol section 6)
                          **{f"domain_weighted_at_{k}": round(float((m["prob"] >= th[k]).groupby(m["reg"]).mean().mean()), 4)
                             if len(m) else None for k in ("alert", "high")}},
            "final_api": {"category_share": d["category"].value_counts(normalize=True).round(4).to_dict(),
                          "high_risk_or_dangerous": rate(hi_final),
                          "caution_or_worse": rate(d["category"].isin(["caution", "high_risk", "dangerous"]))},
            "brand_rule_high": rate(d["brand_high"]),
            "query_dependent_rule_fires": {r: int(d[r].sum()) for r in QUERY_RULES},
            "n_registered_domains": int(d["reg"].nunique())}
    return out


def _verdict(ok: bool, r: dict) -> str:
    return "not established (no legitimate hosts)" if not r["n"] else ("pass" if ok else "fail")


def criteria(groups: dict, legit: pd.DataFrame, th: dict) -> dict:
    p = groups.get("primary", {}).get("raw_model", {}).get("at_alert", {"n": 0, "rate": None, "ci95": None})
    if p["n"] < MIN_POSITIVES:
        e1a = f"not established (n = {p['n']} < {MIN_POSITIVES})"
    else:
        e1a = "pass" if p["rate"] >= 0.75 and p["ci95"][0] >= 0.70 else "fail"
    apex = groups.get("legit_apex", {}).get("raw_model", {}).get("at_high", {}).get("rate")
    legit_final = rate(legit["category"].isin(["high_risk", "dangerous"]))
    legit_brand = rate(legit["brand_high"])
    return {
        "E1-a recall@alert>=0.75 & lower>=0.70 on >=500 primary": e1a,
        "E1-b apex FPR@high<=0.06": ("not established (no scored legitimate apex hosts)" if apex is None
                                     else "pass" if apex <= 0.06 else "fail"),
        "E1-c final high risk on legit (apex+subdomain)<=0.02":
            {**legit_final, "result": _verdict(legit_final["rate"] is not None and legit_final["rate"] <= 0.02, legit_final)},
        "E1-d subdomain caution-or-worse (reported, no bar)":
            groups.get("legit_subdomain", {}).get("final_api", {}).get("caution_or_worse") or rate([]),
        "E4 brand high on legit<=0.01 & upper<=0.02":
            {**legit_brand, "result": _verdict(legit_brand["rate"] is not None and legit_brand["rate"] <= 0.01
                                               and legit_brand["ci95"][1] <= 0.02, legit_brand)},
        "E2": "not run (F4: Google Safe Browsing and URLhaus credentials unavailable)"}


def full_url_analysis(pos: pd.DataFrame, analyzer: Analyzer, th: dict) -> dict:
    """Query-dependent rules on FULL feed URLs, re-fetched by commit and checked against the recorded hash, scored in
    memory only. Fails closed (no partial result) if any snapshot cannot be re-fetched or verified."""
    full = {}
    for s in (m for m in pc.manifest() if m["source"] == "openphish"):
        try:
            raw = _get(GITHUB_RAW.format(commit=s["commit"]))
        except OSError as exc:
            return {"status": "unavailable", "reason": f"re-fetch failed for {s['commit'][:7]}: {type(exc).__name__}"}
        if hashlib.sha256(raw).hexdigest() != s["raw_sha256"]:
            return {"status": "unavailable", "reason": f"hash mismatch for commit {s['commit'][:7]}"}
        for u in parse_openphish(raw.decode("utf-8")):
            try:
                full.setdefault(get_host(u), u)
            except InvalidURLError:
                continue
    keep = pos[pos["group"].isin(["primary", "supplementary"]) & pos["host"].isin(full)]
    scored = score([full[h] for h in keep["host"]], analyzer).assign(group=keep["group"].to_numpy(), reg=keep["reg"].to_numpy())
    full.clear()  # full URLs never leave this function
    res = summarise(scored, th)
    return {"status": "ok", "note": "phishing groups only; aggregates only; full URLs were held in memory and discarded",
            "groups": {g: {k: v[k] for k in ("final_api", "brand_rule_high", "query_dependent_rule_fires")}
                       for g, v in res.items()}}


def _throttled(fn, min_interval: float = 1.25):
    """PhishTank allows ~250 requests / 300 s without a key: keep below it."""
    last = [0.0]

    def call(url):
        time.sleep(max(0.0, last[0] + min_interval - time.monotonic()))
        last[0] = time.monotonic()
        return fn(url)
    return call


def _write(name: str, result: dict) -> str:
    out = pc.ROOT / "reports" / "phase6" / name
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "x", encoding="utf-8") as f:  # never overwrite an earlier run
        json.dump(result, f, indent=2, default=str)
    return str(out)


def run_e1(now: datetime, with_phishtank: bool = False, full_urls: bool = False) -> dict:
    tranco = ready(now)
    pos = positives()
    neg, neg_counts = negatives(tranco, pos)
    a = Analyzer(lookups={})  # configuration (a): model + rules, no TI; local OpenPhish lookup is never used
    th = a.bundle["thresholds"]
    scored_pos = pos[pos["group"].isin(["primary", "supplementary"])]
    items = pd.concat([scored_pos[["host", "url", "reg", "group"]], neg[["host", "url", "reg", "group"]]], ignore_index=True)
    s = score(items["url"], a)
    items = pd.concat([items.reset_index(drop=True), s.drop(columns="ti")], axis=1)
    groups = summarise(items, th)
    legit = items[items["group"].isin(["legit_apex", "legit_subdomain"])]
    result = {"protocol_version": PROTOCOL_VERSION, "run_at_utc": now.strftime(pc.STAMP),
              "freeze_record_sha256": hashlib.sha256(pc.FROZEN.read_bytes()).hexdigest(),
              "configuration": "E1(a): model + rules, no threat intelligence", "thresholds": th,
              "positive_group_counts": pos["group"].value_counts().to_dict(), "negative_counts": neg_counts,
              "groups": groups, "criteria": criteria(groups, legit, th),
              "limitations": [("E1 scores sanitised URLs (no userinfo/query/fragment): query-dependent rules are not "
                               "fully measured in the primary run"),
                              "primary positives exclude previously seen registered domains (F1)"]}
    if with_phishtank:
        b = Analyzer(lookups={"PhishTank": _throttled(threat_intel.check_phishtank)})
        sb = score(items["url"], b)
        items_b = items.drop(columns=["category", "brand_high", *QUERY_RULES]).assign(
            category=sb["category"].to_numpy(), brand_high=sb["brand_high"].to_numpy(), **{r: sb[r].to_numpy() for r in QUERY_RULES})
        result["configuration_b_phishtank"] = {
            "final_api": {g: v["final_api"] for g, v in summarise(items_b, th).items()},
            "phishtank_status_counts": pd.Series([t.get("PhishTank") for t in sb["ti"]]).value_counts().to_dict()}
    if full_urls:
        result["full_url_analysis"] = full_url_analysis(pos, a, th)
    return result


def run_e3(now: datetime, n: int = 200) -> dict:
    tranco = ready(now)
    neg, _ = negatives(tranco, positives())
    urls = neg[neg["group"] == "legit_apex"].sample(min(n, (neg["group"] == "legit_apex").sum()), random_state=SEED)["url"].tolist()
    lookups = {"PhishTank": threat_intel.check_phishtank, threat_intel.OPENPHISH_SOURCE: threat_intel.check_openphish_local}
    if os.getenv("GOOGLE_SAFE_BROWSING_KEY"):
        lookups["Google Safe Browsing"] = threat_intel.check_safe_browsing
    if os.getenv("URLHAUS_AUTH_KEY"):
        lookups["URLhaus"] = threat_intel.check_urlhaus
    timings, statuses = {}, []
    a_none, a_all = Analyzer(lookups={}), Analyzer(lookups=lookups)

    def all_sources(u):  # records each lookup's status so fast failures cannot pass as real latency
        ev, caveats = a_all.collect(u)
        statuses.extend(f"{t.source}: {t.status}" for t in ev.threat_intel)
        return fuse(ev, caveats)
    for name, fn, pause in (("model_only", lambda u: predict(a_none.bundle, u), 0.0),
                            ("pipeline_no_sources", lambda u: fuse(*a_none.collect(u)), 0.0),
                            ("pipeline_available_sources", all_sources, 1.25)):
        t = []
        for u in urls:
            time.sleep(pause)  # PhishTank rate limit (~250 / 300 s); the pause is outside the timed call
            t0 = time.perf_counter()
            fn(u)
            t.append((time.perf_counter() - t0) * 1000)
        timings[name] = {"n": len(t), "p50_ms": round(float(np.percentile(t, 50)), 2), "p95_ms": round(float(np.percentile(t, 95)), 2)}
    return {"protocol_version": PROTOCOL_VERSION, "run_at_utc": now.strftime(pc.STAMP),
            "enabled_sources": sorted(lookups), "timings": timings,
            "source_status_counts": dict(sorted(Counter(statuses).items())),
            "note": "rate-limit pauses are excluded from the timed calls; TI responses are cached for 15 min (D24), "
                    "so each URL is looked up once per source",
            "criteria": {"E3 model-only p95<=10ms": "pass" if timings["model_only"]["p95_ms"] <= 10 else "fail",
                         "E3 available-sources p95<=6s": "pass" if timings["pipeline_available_sources"]["p95_ms"] <= 6000 else "fail"}}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("experiment", choices=["e1", "e3"])
    ap.add_argument("--with-phishtank", action="store_true")
    ap.add_argument("--full-urls", action="store_true")
    args, now = ap.parse_args(), datetime.now(UTC)
    if args.experiment == "e1":
        res = run_e1(now, args.with_phishtank, args.full_urls)
    else:
        res = run_e3(now)
    print(_write(f"{args.experiment}_{now.strftime(pc.STAMP)}.json", res))


if __name__ == "__main__":
    main()
