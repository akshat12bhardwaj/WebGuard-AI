"""Audit the raw PhiUSIIL CSV: schema, labels, duplicates, invalid URLs, domain structure,
URL-format artifacts and single-column leakage. Read-only on data/raw.

Usage: python -m ml.data_audit
Writes: reports/metrics/data_audit.json, reports/metrics/leakage_single_feature.csv,
        reports/figures/class_balance.png, leakage_single_feature.png, url_format_artifacts.png
"""
from __future__ import annotations

from urllib.parse import urlsplit

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import roc_auc_score

from ml.feature_extraction import InvalidURLError, get_host, registered_domain
from ml.utils import FIGURES, METRICS, RAW_CSV, get_logger, save_json, sha256

log = get_logger("data_audit")

URL_COLUMNS = ["URLLength", "DomainLength", "IsDomainIP", "CharContinuationRate", "TLDLength", "NoOfSubDomain",
               "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio", "NoOfLettersInURL", "LetterRatioInURL",
               "NoOfDegitsInURL", "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
               "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS"]
REFERENCE_COLUMNS = ["URLSimilarityIndex", "TLDLegitimateProb", "URLCharProb"]  # depend on authors' reference lists


def source_of(col: str) -> str:
    if col in URL_COLUMNS:
        return "url"
    if col in REFERENCE_COLUMNS:
        return "derived_reference"
    return "html_page"


def main() -> None:
    df = pd.read_csv(RAW_CSV)
    y = 1 - df["label"]  # PhiUSIIL: 1 = legitimate, 0 = phishing -> is_phishing
    a = {"file": RAW_CSV.name, "sha256": sha256(RAW_CSV), "rows": len(df), "columns": len(df.columns),
         "dtypes": df.dtypes.astype(str).to_dict(),
         "label_counts_raw": df["label"].value_counts().to_dict(),
         "label_meaning": "1 = legitimate, 0 = phishing (UCI page); mapped to is_phishing = 1 - label",
         "missing_values_total": int(df.isna().sum().sum()),
         "missing_by_column": {k: int(v) for k, v in df.isna().sum().items() if v},
         "duplicate_rows_excluding_filename": int(df.drop(columns="FILENAME").duplicated().sum()),
         "duplicate_urls": int(df["URL"].duplicated().sum())}

    hosts, regs, invalid = [], [], 0
    for u in df["URL"]:
        try:
            h = get_host(u); hosts.append(h); regs.append(registered_domain(h))
        except InvalidURLError:
            hosts.append(None); regs.append(None); invalid += 1
    df["host"], df["reg"], df["is_phishing"] = hosts, regs, y
    ok = df["host"].notna()
    a["invalid_urls"] = invalid
    a["unique_hosts"] = int(df.loc[ok, "host"].nunique())
    a["duplicate_hosts"] = int(df.loc[ok, "host"].duplicated().sum())
    a["unique_registered_domains"] = int(df.loc[ok, "reg"].nunique())
    per_reg = df[ok].groupby("reg").agg(n=("host", "size"), labels=("is_phishing", "nunique"))
    a["registered_domains_with_multiple_rows"] = int((per_reg["n"] > 1).sum())
    a["rows_in_multi_row_domains"] = int(per_reg.loc[per_reg["n"] > 1, "n"].sum())
    a["registered_domains_with_both_labels"] = int((per_reg["labels"] > 1).sum())
    a["hosts_with_both_labels"] = int((df[ok].groupby("host")["is_phishing"].nunique() > 1).sum())
    a["largest_domains"] = per_reg.sort_values("n", ascending=False).head(10)["n"].to_dict()

    # URL-format artifacts by class (shortcut signals created by data collection).
    parts = df["URL"].map(urlsplit)
    fmt = pd.DataFrame({
        "https_scheme": df["URL"].str.lower().str.startswith("https://"),
        "www_prefix": df["URL"].str.lower().str.contains(r"^https?://www\.", regex=True),
        "no_path": parts.map(lambda p: p.path in ("", "/") and not p.query),
        "trailing_slash": df["URL"].str.endswith("/"),
        "is_phishing": y})
    a["url_format_share_by_class"] = fmt.groupby("is_phishing").mean().round(4).to_dict()

    # Single-column leakage: ROC-AUC of each numeric column alone (0.5 = useless, 1.0 = perfect).
    rows = []
    for col in df.select_dtypes("number").columns.drop(["label", "is_phishing"]):
        auc = roc_auc_score(y, df[col])
        rows.append({"column": col, "source": source_of(col), "auc": round(max(auc, 1 - auc), 4),
                     "legit_mean": round(df.loc[y == 0, col].mean(), 4),
                     "phish_mean": round(df.loc[y == 1, col].mean(), 4)})
    leak = pd.DataFrame(rows).sort_values("auc", ascending=False)
    leak.to_csv(METRICS / "leakage_single_feature.csv", index=False)
    a["single_column_auc_top10"] = leak.head(10).set_index("column")["auc"].to_dict()
    a["columns_with_auc_ge_0_95"] = leak.loc[leak["auc"] >= 0.95, "column"].tolist()
    a["url_similarity_index_eq_100_share_by_class"] = (df["URLSimilarityIndex"] == 100).groupby(y).mean().round(4).to_dict()
    save_json(a, METRICS / "data_audit.json")

    FIGURES.mkdir(parents=True, exist_ok=True)
    ax = y.map({0: "legitimate", 1: "phishing"}).value_counts().plot.bar(title="PhiUSIIL class balance (raw rows)")
    ax.set_ylabel("rows"); plt.tight_layout(); plt.savefig(FIGURES / "class_balance.png", dpi=150); plt.close()
    top = leak.head(20).iloc[::-1]
    colors = top["source"].map({"url": "tab:blue", "derived_reference": "tab:red", "html_page": "tab:gray"})
    plt.figure(figsize=(7, 6)); plt.barh(top["column"], top["auc"], color=colors)
    plt.axvline(0.95, ls="--", c="k"); plt.xlabel("single-column ROC-AUC (red=reference-derived, gray=HTML, blue=URL)")
    plt.title("Precomputed columns that alone separate the classes"); plt.tight_layout()
    plt.savefig(FIGURES / "leakage_single_feature.png", dpi=150); plt.close()
    fmt.groupby("is_phishing").mean().T.rename(columns={0: "legitimate", 1: "phishing"}).plot.bar(
        title="URL-format artifacts by class (share of rows)")
    plt.tight_layout(); plt.savefig(FIGURES / "url_format_artifacts.png", dpi=150); plt.close()

    log.info("Audit: %d rows, %d invalid URLs, %d duplicate URLs, %d hosts with both labels, %d columns with AUC>=0.95",
             a["rows"], invalid, a["duplicate_urls"], a["hosts_with_both_labels"], len(a["columns_with_auc_ge_0_95"]))


if __name__ == "__main__":
    main()
