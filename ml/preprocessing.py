"""Clean PhiUSIIL and compute hostname features. Only the URL and label columns are read.

Usage: python -m ml.preprocessing [--input CSV] [--output CSV]
Writes: data/processed/dataset.csv, reports/metrics/preprocessing_report.json
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from ml.feature_extraction import (
    FEATURE_NAMES,
    InvalidURLError,
    extract_features,
    get_host,
    registered_domain,
)
from ml.utils import METRICS, PROCESSED, RAW_CSV, get_logger, save_json, sha256

log = get_logger("preprocessing")


def preprocess(raw: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """raw needs columns URL, label (1 = legitimate). Returns one row per host with features."""
    if not {"URL", "label"} <= set(raw.columns):
        raise ValueError("input must contain URL and label columns")
    if not set(raw["label"].unique()) <= {0, 1}:
        raise ValueError(f"unexpected labels: {sorted(raw['label'].unique())}")
    df = raw[["URL", "label"]].dropna().copy()
    rep = {"rows_in": len(raw), "rows_missing_url_or_label": len(raw) - len(df)}
    df["is_phishing"] = 1 - df["label"].astype(int)

    hosts, regs = [], []
    for u in df["URL"]:
        try:
            h = get_host(u); hosts.append(h); regs.append(registered_domain(h))
        except InvalidURLError:
            hosts.append(None); regs.append(None)
    df["host"], df["reg_domain"] = hosts, regs
    rep["rows_invalid_url"] = int(df["host"].isna().sum())
    df = df[df["host"].notna()]

    # The model sees only the host: drop hosts carrying both labels, then keep one row per host.
    n_labels = df.groupby("host")["is_phishing"].transform("nunique")
    rep["hosts_with_conflicting_labels"] = int(df.loc[n_labels > 1, "host"].nunique())
    rep["rows_dropped_conflicting"] = int((n_labels > 1).sum())
    df = df[n_labels == 1]
    before = len(df)
    df = df.drop_duplicates("host")
    rep["rows_dropped_duplicate_host"] = before - len(df)

    feats = pd.DataFrame([extract_features(u) for u in df["URL"]], index=df.index)[FEATURE_NAMES]
    out = pd.concat([df[["URL", "host", "reg_domain", "is_phishing"]], feats], axis=1).reset_index(drop=True)
    rep["rows_out"] = len(out)
    rep["class_counts_out"] = out["is_phishing"].value_counts().to_dict()
    return out, rep


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, default=RAW_CSV)
    ap.add_argument("--output", type=Path, default=PROCESSED / "dataset.csv")
    args = ap.parse_args()
    if not args.input.exists():
        raise SystemExit(f"{args.input} not found; run: python -m ml.data_download")
    out, rep = preprocess(pd.read_csv(args.input, usecols=["URL", "label"]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output, index=False)
    rep.update(input_sha256=sha256(args.input), output=args.output.name, features=FEATURE_NAMES)
    save_json(rep, METRICS / "preprocessing_report.json")
    log.info("Preprocessed %d -> %d hosts (%s)", rep["rows_in"], rep["rows_out"], rep["class_counts_out"])


if __name__ == "__main__":
    main()
