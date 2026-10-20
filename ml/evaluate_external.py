"""Evaluate the UNCHANGED baseline bundle on external data (no tuning, thresholds from validation).

Sets: OpenPhish + Tranco external test (by subset) and Kaggle phishing/benign hosts whose registered
domain never appears in PhiUSIIL train.
Usage: python -m ml.evaluate_external [--bootstrap 1000]
Writes: reports/metrics/external_results.{json,md}, reports/figures/external_pr_curves.png,
        external_fpr_by_subset.png, external_confusion_<set>.png
"""
from __future__ import annotations

import argparse

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay, PrecisionRecallDisplay

from ml.external_data import EXTERNAL
from ml.feature_extraction import MODEL_FEATURES, extract_features
from ml.utils import (
    FIGURES,
    METRICS,
    MODELS,
    PROCESSED,
    SEED,
    binary_metrics,
    get_logger,
    rounded,
    save_json,
)

log = get_logger("evaluate_external")


def features(urls) -> pd.DataFrame:
    return pd.DataFrame([extract_features(u) for u in urls])[MODEL_FEATURES].astype(float)


def bootstrap_ci(y, p, t: float, n: int, keys=("precision", "recall", "fpr", "pr_auc")) -> dict:
    """95% percentile CI, resampling each class separately (keeps the class ratio)."""
    rng = np.random.default_rng(SEED)
    y, p = np.asarray(y), np.asarray(p)
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    draws = {k: [] for k in keys}
    for _ in range(n):
        idx = np.concatenate([rng.choice(pos, len(pos)), rng.choice(neg, len(neg))]) if len(pos) else rng.choice(neg, len(neg))
        m = binary_metrics(y[idx], p[idx], t)
        for k in keys:
            draws[k].append(m[k])
    return {k: [round(float(np.nanpercentile(v, 2.5)), 4), round(float(np.nanpercentile(v, 97.5)), 4)] for k, v in draws.items()}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bootstrap", type=int, default=1000)
    args = ap.parse_args()
    bundle = joblib.load(MODELS / "model_bundle.joblib")  # read-only: the baseline is not modified
    th = bundle["thresholds"]

    ext = pd.read_csv(EXTERNAL, keep_default_na=False)
    ext["prob"] = bundle["model"].predict_proba(features(ext["url"]))[:, 1]
    train_regs = set(pd.read_csv(PROCESSED / "train.csv", keep_default_na=False, usecols=["reg_domain"])["reg_domain"])
    kag = pd.read_csv(PROCESSED / "kaggle_binary_hosts.csv", keep_default_na=False)
    kag = kag[~kag["reg_domain"].isin(train_regs)].copy()
    kag["prob"] = bundle["model"].predict_proba(kag[MODEL_FEATURES].astype(float))[:, 1]

    sets = {"external_all": ext,
            "openphish_vs_tranco_apex": ext[ext["subset"] != "tranco_subdomain"],
            "openphish_vs_tranco_subdomain": ext[ext["subset"] != "tranco_apex"],
            "kaggle_unseen_domains": kag}
    res = {"model": f"{bundle['model_name']}+{bundle['calibration']} ({bundle['version']})", "thresholds": th, "sets": {}}
    fig, ax = plt.subplots(figsize=(6, 5))
    for name, d in sets.items():
        y, p = d["is_phishing"].to_numpy(), d["prob"].to_numpy()
        r = {"rows": len(d), "phishing": int(y.sum()), "legitimate": int((y == 0).sum())}
        for key in ("alert", "high"):
            r[key] = rounded(binary_metrics(y, p, th[key]))
            if name in ("external_all", "kaggle_unseen_domains"):
                r[key]["ci95"] = bootstrap_ci(y, p, th[key], args.bootstrap)
        res["sets"][name] = r
        PrecisionRecallDisplay.from_predictions(y, p, name=name, ax=ax)
        if name in ("external_all", "kaggle_unseen_domains"):
            ConfusionMatrixDisplay.from_predictions(y, (p >= th["alert"]).astype(int), display_labels=["legitimate", "phishing"])
            plt.title(f"{name}, alert threshold {th['alert']}"); plt.tight_layout()
            plt.savefig(FIGURES / f"external_confusion_{name}.png", dpi=150); plt.close()
    ax.set_title("External PR curves (baseline, unchanged)"); fig.tight_layout()
    fig.savefig(FIGURES / "external_pr_curves.png", dpi=150); plt.close("all")

    # False-positive rate per legitimate subset: the key check for the subdomain bias.
    fpr = {}
    for subset in ("tranco_apex", "tranco_subdomain"):
        neg = ext[ext["subset"] == subset]
        fpr[subset] = {k: {"fpr": round(float((neg["prob"] >= th[k]).mean()), 4),
                           "ci95": bootstrap_ci(np.zeros(len(neg), int), neg["prob"].to_numpy(), th[k], args.bootstrap, ("fpr",))["fpr"]}
                       for k in ("alert", "high")}
    res["fpr_by_legitimate_subset"] = fpr
    res["openphish_recall"] = {k: res["sets"]["external_all"][k]["recall"] for k in ("alert", "high")}
    save_json(res, METRICS / "external_results.json")

    pd.DataFrame({s: {k: v["fpr"] for k, v in fpr[s].items()} for s in fpr}).T.plot.bar(
        title="Baseline false-positive rate on legitimate Tranco hosts")
    plt.ylabel("FPR"); plt.tight_layout(); plt.savefig(FIGURES / "external_fpr_by_subset.png", dpi=150); plt.close()

    cols = ["threshold", "precision", "recall", "f1", "pr_auc", "roc_auc", "fpr", "fnr", "tp", "fp", "fn", "tn"]
    rows = [{"set": n, "level": k, **{c: v[k][c] for c in cols}} for n, v in res["sets"].items() for k in ("alert", "high")]
    (METRICS / "external_results.md").write_text(pd.DataFrame(rows).to_markdown(index=False))
    log.info("External: OpenPhish recall %s; FPR by subset %s", res["openphish_recall"],
             {s: {k: v["fpr"] for k, v in fpr[s].items()} for s in fpr})


if __name__ == "__main__":
    main()
