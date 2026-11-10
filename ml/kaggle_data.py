"""Kaggle 'Malicious URLs dataset' (sid321axn): download, audit, binary normalisation, PhiUSIIL overlap.

Usage: python -m ml.kaggle_data
Writes: data/raw/kaggle_malicious_urls/{malicious_urls_dataset.zip, malicious_phish.csv, metadata.json},
        data/processed/kaggle_binary_hosts.csv, reports/metrics/kaggle_provenance.json, kaggle_audit.json,
        reports/figures/kaggle_url_formats.png
"""
from __future__ import annotations

import urllib.request
import zipfile
from urllib.parse import urlsplit

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from ml.data_download import safe_extract
from ml.feature_extraction import InvalidURLError, get_host, normalize_url
from ml.preprocessing import preprocess
from ml.utils import (
    FIGURES,
    METRICS,
    PROCESSED,
    RAW,
    get_logger,
    now_utc,
    save_json,
    sha256,
)

REF = "sid321axn/malicious-urls-dataset"
PAGE = f"https://www.kaggle.com/datasets/{REF}"
DOWNLOAD = f"https://www.kaggle.com/api/v1/datasets/download/{REF}"
META = f"https://www.kaggle.com/api/v1/datasets/view/{REF}"
DIR = RAW / "kaggle_malicious_urls"
ZIP, CSV = DIR / "malicious_urls_dataset.zip", DIR / "malicious_phish.csv"
BINARY = {"phishing": 1, "benign": 0}  # 'defacement' and 'malware' are other threats -> excluded
log = get_logger("kaggle_data")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "website-risk-analyzer-student/1.0"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def ensure_downloaded() -> dict:
    DIR.mkdir(parents=True, exist_ok=True)
    downloaded = None
    if not (ZIP.exists() and zipfile.is_zipfile(ZIP)):
        data = _get(DOWNLOAD)
        if not data.startswith(b"PK"):
            raise RuntimeError("Kaggle download is not a ZIP (login wall or error page?)")
        ZIP.write_bytes(data)
        downloaded = now_utc()
    if not (DIR / "metadata.json").exists():
        (DIR / "metadata.json").write_bytes(_get(META))
    members = safe_extract(ZIP, DIR)
    old = METRICS / "kaggle_provenance.json"
    first = pd.read_json(old, typ="series").get("downloaded_at_utc") if old.exists() else None
    meta = pd.read_json(DIR / "metadata.json", typ="series")
    prov = {"page": PAGE, "download_url": DOWNLOAD, "metadata_url": META,
            "downloaded_at_utc": downloaded or first, "validated_at_utc": now_utc(),
            "licence": meta.get("licenseName"), "version": int(meta.get("currentVersionNumber")),
            "last_updated": meta.get("lastUpdated"), "creator": meta.get("creatorName"),
            "zip_bytes": ZIP.stat().st_size, "zip_sha256": sha256(ZIP), "members": members,
            "csv_bytes": CSV.stat().st_size, "csv_sha256": sha256(CSV)}
    save_json(prov, old)
    return prov


def to_binary(raw: pd.DataFrame) -> pd.DataFrame:
    """Keep phishing/benign rows; return columns URL, is_phishing (phishing = 1)."""
    if not {"url", "type"} <= set(raw.columns):
        raise ValueError(f"expected columns url,type; got {list(raw.columns)}")
    df = raw[raw["type"].isin(BINARY)].dropna(subset=["url"])
    return pd.DataFrame({"URL": df["url"].astype(str), "is_phishing": df["type"].map(BINARY).astype(int)})


def binary_hosts(raw: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Same cleaning and features as PhiUSIIL (preprocess expects label 1 = legitimate)."""
    b = to_binary(raw)
    return preprocess(pd.DataFrame({"URL": b["URL"], "label": 1 - b["is_phishing"]}))


def url_key(u: str) -> str | None:
    """Comparable URL form: scheme-less, lower-case host, no 'www.', no trailing slash."""
    try:
        p = urlsplit(normalize_url(u))
        return (get_host(u) + p.path.rstrip("/") + (f"?{p.query}" if p.query else "")).lower()
    except InvalidURLError:
        return None


def overlap(a: pd.DataFrame, b: pd.DataFrame, col: str) -> int:
    return len(set(a[col].dropna()) & set(b[col].dropna()))


def main() -> None:
    prov = ensure_downloaded()
    raw = pd.read_csv(CSV)
    a = {"rows": len(raw), "columns": list(raw.columns), "type_counts": raw["type"].value_counts().to_dict(),
         "missing": raw.isna().sum().to_dict(), "duplicate_urls": int(raw["url"].duplicated().sum()),
         "urls_with_conflicting_types": int((raw.groupby("url")["type"].nunique() > 1).sum()),
         "timestamps": "none in the file; sources per description: ISCX-URL-2016, malwaredomains, "
                       "faizan-ahmad repo, PhishTank, PhishStorm; Kaggle version 1, last updated "
                       + str(prov["last_updated"])}
    lower = raw["url"].astype(str).str.lower()
    fmt = pd.DataFrame({"has_scheme": lower.str.contains(r"^[a-z][a-z0-9+.-]*://", regex=True),
                        "https": lower.str.startswith("https://"),
                        "www_prefix": lower.str.contains(r"^(?:https?://)?www\.", regex=True),
                        "has_path": lower.str.replace(r"^[a-z]+://", "", regex=True).str.contains(r"/.", regex=True),
                        "type": raw["type"]})
    a["url_format_share_by_type"] = fmt.groupby("type").mean().round(4).to_dict()

    hosts, rep = binary_hosts(raw)
    hosts.to_csv(PROCESSED / "kaggle_binary_hosts.csv", index=False)
    a["binary_cleaning"] = rep

    phi = pd.read_csv(PROCESSED / "dataset.csv", keep_default_na=False, usecols=["URL", "host", "reg_domain", "is_phishing"])
    kb = to_binary(raw)
    kb["key"] = kb["URL"].map(url_key)
    phi["key"] = phi["URL"].map(url_key)
    splits = {s: pd.read_csv(PROCESSED / f"{s}.csv", keep_default_na=False, usecols=["reg_domain"]) for s in ("train", "val", "test")}
    merged = hosts.merge(phi[["host", "is_phishing"]], on="host", suffixes=("_kaggle", "_phiusiil"))
    a["overlap_with_phiusiil"] = {
        "exact_url_keys": overlap(kb, phi, "key"),
        "hosts": overlap(hosts, phi, "host"),
        "hosts_with_disagreeing_labels": int((merged["is_phishing_kaggle"] != merged["is_phishing_phiusiil"]).sum()),
        "registered_domains": overlap(hosts, phi, "reg_domain"),
        **{f"registered_domains_in_phiusiil_{s}": overlap(hosts, d, "reg_domain") for s, d in splits.items()}}
    save_json(a, METRICS / "kaggle_audit.json")

    fmt.groupby("type").mean().T.plot.bar(title="Kaggle URL formats by type (share of rows)")
    plt.tight_layout(); plt.savefig(FIGURES / "kaggle_url_formats.png", dpi=150); plt.close()
    log.info("Kaggle: %d rows -> %d binary hosts; overlap with PhiUSIIL: %s", len(raw), len(hosts), a["overlap_with_phiusiil"])


if __name__ == "__main__":
    main()

