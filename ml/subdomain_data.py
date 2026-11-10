"""EXP-03 data: observed legitimate subdomain hosts from Tranco Q2Y54 ranks 100,001-1,000,000 (D26, D27).

Uses the raw list already downloaded by ml.external_data (no new download, no generated hostnames).
Usage: python -m ml.subdomain_data
Writes: data/processed/exp03_new_{train,val,test}.csv, reports/exp03/data_provenance.json
"""
from __future__ import annotations

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from ml.external_data import EXTERNAL, host_rows, parse_tranco
from ml.feature_extraction import (
    FEATURE_NAMES,
    SHARED_HOSTING_SUFFIXES,
    extract_features,
    is_ip,
    is_public_suffix,
)
from ml.utils import PROCESSED, RAW, ROOT, SEED, get_logger, save_json, sha256

LIST_ID, LO, HI, PER_DOMAIN = "Q2Y54", 100_001, 1_000_000, 3
OUT = ROOT / "reports" / "exp03"
log = get_logger("subdomain_data")


def exclusion_sets() -> dict[str, set]:
    rd = lambda f: set(pd.read_csv(f, keep_default_na=False, usecols=["reg_domain"])["reg_domain"])
    tr = pd.read_csv(PROCESSED / "train.csv", keep_default_na=False, usecols=["host", "reg_domain", "is_phishing"])
    phish_feed = next((RAW / "openphish").glob("feed_*.txt"))
    return {"phiusiil_val_test": rd(PROCESSED / "val.csv") | rd(PROCESSED / "test.csv"),
            "external_test": rd(EXTERNAL), "kaggle": rd(PROCESSED / "kaggle_binary_hosts.csv"),
            "openphish": set(host_rows(phish_feed.read_text(encoding="utf-8").splitlines(), 1, "op")["reg_domain"]),
            "phiusiil_train_phishing": set(tr.loc[tr.is_phishing == 1, "reg_domain"]),
            "phiusiil_hosts": set(pd.read_csv(PROCESSED / "dataset.csv", keep_default_na=False, usecols=["host"])["host"])}


def select(candidates: pd.DataFrame, ex: dict[str, set]) -> tuple[pd.DataFrame, dict]:
    """Apply D27 exclusions in a fixed order and record how many rows each removed."""
    rep, df = {"candidates": len(candidates)}, candidates
    steps = [("ip_host", lambda d: d["host"].map(is_ip)),
             ("host_is_public_suffix", lambda d: d["host"].map(is_public_suffix)),  # found by integrity test (D31)
             ("no_subdomain", lambda d: d["host"] == d["reg_domain"]),
             ("shared_hosting", lambda d: d["host"].map(lambda h: any(h == s or h.endswith("." + s) for s in SHARED_HOSTING_SUFFIXES))),
             *[(f"domain_in_{k}", lambda d, k=k: d["reg_domain"].isin(ex[k]))
               for k in ("phiusiil_val_test", "external_test", "kaggle", "openphish", "phiusiil_train_phishing")],
             ("host_in_phiusiil", lambda d: d["host"].isin(ex["phiusiil_hosts"]))]
    for name, drop in steps:
        mask = drop(df)
        rep[f"dropped_{name}"] = int(mask.sum())
        df = df[~mask]
    before = len(df)
    df = df.groupby("reg_domain", sort=False).head(PER_DOMAIN)  # keeps the most popular hosts per domain
    rep["dropped_over_3_per_domain"] = before - len(df)
    rep["selected"] = len(df)
    return df, rep


def main() -> None:
    path = RAW / "tranco" / f"{LIST_ID}.csv"
    tranco = parse_tranco(path.read_text(encoding="utf-8"))
    band = tranco[(tranco["rank"] >= LO) & (tranco["rank"] <= HI)]
    cand = host_rows((f"https://{d}/" for d in band["domain"]), 0, "tranco_rank_100k_1m")
    cand = cand.merge(band.assign(host=band["domain"].str.removeprefix("www."))[["host", "rank"]].drop_duplicates("host"),
                      on="host", how="left")
    sel, rep = select(cand, exclusion_sets())
    feats = pd.DataFrame([extract_features(u) for u in sel["url"]], index=sel.index)[FEATURE_NAMES]
    data = pd.concat([sel.rename(columns={"url": "URL"})[["URL", "host", "reg_domain", "is_phishing", "rank"]], feats], axis=1)

    # Domains already in PhiUSIIL train (legitimate) may only go to new_train, never to new_val/new_test.
    train_regs = set(pd.read_csv(PROCESSED / "train.csv", keep_default_na=False, usecols=["reg_domain"])["reg_domain"])
    pinned = data["reg_domain"].isin(train_regs)
    rep["pinned_to_train_domain_in_phiusiil_train"] = int(pinned.sum())
    free = data[~pinned]
    a, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED).split(free, groups=free["reg_domain"]))
    rest_df = free.iloc[rest]
    b, c = next(GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED).split(rest_df, groups=rest_df["reg_domain"]))
    parts = {"train": pd.concat([data[pinned], free.iloc[a]]), "val": rest_df.iloc[b], "test": rest_df.iloc[c]}
    for name in ("val", "test"):
        assert not set(parts[name]["reg_domain"]) & train_regs
    names = list(parts)
    for i, x in enumerate(names):
        for y in names[i + 1:]:
            assert not set(parts[x]["reg_domain"]) & set(parts[y]["reg_domain"])
    for name, part in parts.items():
        part.to_csv(PROCESSED / f"exp03_new_{name}.csv", index=False)
        rep[name] = {"rows": len(part), "registered_domains": int(part["reg_domain"].nunique())}
    rep.update(source=f"Tranco list {LIST_ID} (subdomains on), created 2026-10-14T22:00 UTC", raw_file=str(path.relative_to(ROOT)),
               raw_sha256=sha256(path), ranks=[LO, HI], band_rows=len(band), label_policy="legitimate (0) by popularity "
               "assumption after exclusions; not verified site by site", max_hosts_per_domain=PER_DOMAIN, seed=SEED)
    OUT.mkdir(parents=True, exist_ok=True)
    save_json(rep, OUT / "data_provenance.json")
    log.info("EXP-03 data: %s", {k: v for k, v in rep.items() if k.startswith(("dropped", "selected", "train", "val", "test"))})


if __name__ == "__main__":
    main()
