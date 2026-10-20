"""Domain-grouped 70/15/15 split: every registered domain lives in exactly one split.

Usage: python -m ml.split_dataset
Needs: data/processed/dataset.csv (python -m ml.preprocessing)
Writes: data/processed/{train,val,test}.csv, reports/metrics/split_report.json,
        reports/metrics/feature_univariate_train.csv (train split only; test is never inspected)
"""
from __future__ import annotations

import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from ml.feature_extraction import FEATURE_NAMES
from ml.utils import METRICS, PROCESSED, SEED, get_logger, save_json, sha256

log = get_logger("split_dataset")


def grouped_split(df: pd.DataFrame, seed: int = SEED) -> dict[str, pd.DataFrame]:
    first = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
    tr, rest = next(first.split(df, groups=df["reg_domain"]))
    rest_df = df.iloc[rest]
    second = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed)
    va, te = next(second.split(rest_df, groups=rest_df["reg_domain"]))
    parts = {"train": df.iloc[tr], "val": rest_df.iloc[va], "test": rest_df.iloc[te]}
    names = list(parts)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            overlap = set(parts[a]["reg_domain"]) & set(parts[b]["reg_domain"])
            assert not overlap, f"registered-domain overlap between {a} and {b}: {list(overlap)[:5]}"
    assert sum(map(len, parts.values())) == len(df)
    return parts


def main() -> None:
    src = PROCESSED / "dataset.csv"
    if not src.exists():
        raise SystemExit(f"{src} not found; run: python -m ml.preprocessing")
    df = pd.read_csv(src, keep_default_na=False)
    parts = grouped_split(df)
    rep = {"seed": SEED, "group_key": "registered domain (tldextract eTLD+1, offline PSL)",
           "input_sha256": sha256(src), "domain_overlap": "none (asserted)"}
    for name, part in parts.items():
        part.to_csv(PROCESSED / f"{name}.csv", index=False)
        rep[name] = {"rows": len(part), "share": round(len(part) / len(df), 4),
                     "unique_domains": int(part["reg_domain"].nunique()),
                     "phishing": int(part["is_phishing"].sum()),
                     "legitimate": int((part["is_phishing"] == 0).sum()),
                     "phishing_share": round(float(part["is_phishing"].mean()), 4)}
    save_json(rep, METRICS / "split_report.json")

    tr = parts["train"]
    uni = pd.DataFrame([{"feature": f, "auc": round(max(a := roc_auc_score(tr["is_phishing"], tr[f]), 1 - a), 4),
                         "direction": "higher = phishing" if a >= 0.5 else "higher = legitimate",
                         "legit_mean": round(tr.loc[tr["is_phishing"] == 0, f].mean(), 4),
                         "phish_mean": round(tr.loc[tr["is_phishing"] == 1, f].mean(), 4)}
                        for f in FEATURE_NAMES]).sort_values("auc", ascending=False)
    uni.to_csv(METRICS / "feature_univariate_train.csv", index=False)
    log.info("Split: %s", {k: (rep[k]["rows"], rep[k]["unique_domains"]) for k in parts})


if __name__ == "__main__":
    main()
