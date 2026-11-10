"""Final, one-time evaluation on the untouched test split (no tuning happens after this).

Usage: python -m ml.evaluate
Writes: reports/metrics/test_results.{json,md}, test_classification_report.txt, test_error_samples.csv,
        reports/figures/test_roc_curves.png, test_pr_curves.png, test_confusion_{alert,high}.png
"""
from __future__ import annotations

import time

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    PrecisionRecallDisplay,
    RocCurveDisplay,
    classification_report,
)

from ml.feature_extraction import MODEL_FEATURES, extract_features
from ml.train import domain_only
from ml.utils import (
    FIGURES,
    METRICS,
    MODELS,
    PROCESSED,
    binary_metrics,
    get_logger,
    rounded,
    save_json,
)

log = get_logger("evaluate")
CANDIDATES = ["LogisticRegression", "RandomForest", "LightGBM", "XGBoost"]


def latency_ms(bundle: dict, urls: list[str]) -> dict:
    """Wall-clock time of extract_features + predict_proba for one URL at a time (single thread)."""
    times = []
    for u in urls:
        t0 = time.perf_counter()
        bundle["model"].predict_proba(pd.DataFrame([extract_features(u)])[MODEL_FEATURES].astype(float))
        times.append((time.perf_counter() - t0) * 1000)
    t = np.array(times[20:])  # first calls include warm-up
    return {"n": len(t), "mean": round(t.mean(), 3), "p50": round(np.percentile(t, 50), 3),
            "p95": round(np.percentile(t, 95), 3), "method": "per-URL feature extraction + predict_proba, "
            "single process, after 20 warm-up calls, time.perf_counter"}


def main() -> None:
    te = pd.read_csv(PROCESSED / "test.csv", keep_default_na=False)
    X, y = te[MODEL_FEATURES].astype(float), te["is_phishing"]
    bundle = joblib.load(MODELS / "model_bundle.joblib")
    th = bundle["thresholds"]
    res = {"test_rows": len(te), "test_phishing": int(y.sum()), "positive_class": "phishing (is_phishing=1)"}

    # 1) every candidate, uncalibrated, threshold 0.5 (comparison only; selection already done on val)
    fig_roc, ax_roc = plt.subplots(figsize=(6, 5)); fig_pr, ax_pr = plt.subplots(figsize=(6, 5))
    res["candidates_at_0.5"] = {}
    for name in CANDIDATES:
        m = joblib.load(MODELS / "candidates" / f"{name}.joblib")
        p = m.predict_proba(X)[:, 1]
        res["candidates_at_0.5"][name] = rounded(binary_metrics(y, p))
        RocCurveDisplay.from_predictions(y, p, name=name, ax=ax_roc)
        PrecisionRecallDisplay.from_predictions(y, p, name=name, ax=ax_pr)
    abl = joblib.load(MODELS / "candidates" / f"{bundle['model_name']}_domain_only.joblib")
    res["ablation_domain_only_at_0.5"] = rounded(binary_metrics(y, abl.predict_proba(domain_only(te))[:, 1]))
    ax_roc.set_title("Test ROC curves (uncalibrated candidates)"); fig_roc.tight_layout()
    fig_roc.savefig(FIGURES / "test_roc_curves.png", dpi=150)
    ax_pr.set_title("Test precision-recall curves"); fig_pr.tight_layout()
    fig_pr.savefig(FIGURES / "test_pr_curves.png", dpi=150); plt.close("all")

    # 2) the selected, calibrated bundle at the validation-chosen thresholds
    p = bundle["model"].predict_proba(X)[:, 1]
    res["selected"] = {"model": bundle["model_name"], "calibration": bundle["calibration"], "thresholds": th}
    for key, t in [("alert", th["alert"]), ("high", th["high"]), ("reference_0.5", 0.5)]:
        res["selected"][key] = rounded(binary_metrics(y, p, t))
        if key != "reference_0.5":
            ConfusionMatrixDisplay.from_predictions(y, (p >= t).astype(int), display_labels=["legitimate", "phishing"])
            plt.title(f"Test confusion matrix, {key} threshold {t}"); plt.tight_layout()
            plt.savefig(FIGURES / f"test_confusion_{key}.png", dpi=150); plt.close()
    (METRICS / "test_classification_report.txt").write_text(
        f"Selected model {bundle['model_name']} ({bundle['calibration']}), alert threshold {th['alert']}\n\n"
        + classification_report(y, (p >= th["alert"]).astype(int), target_names=["legitimate", "phishing"], digits=4))
    res["latency_ms"] = latency_ms(bundle, te["URL"].sample(520, random_state=42).tolist())
    save_json(res, METRICS / "test_results.json")

    rows = [{"model": k, **v} for k, v in res["candidates_at_0.5"].items()]
    rows.append({"model": "domain-only ablation", **res["ablation_domain_only_at_0.5"]})
    rows += [{"model": f"{bundle['model_name']}+{bundle['calibration']} @{k}", **res["selected"][k]}
             for k in ("alert", "high", "reference_0.5")]
    cols = ["model", "threshold", "accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "brier", "fpr", "fnr"]
    (METRICS / "test_results.md").write_text(pd.DataFrame(rows)[cols].to_markdown(index=False))
    err = te.assign(prob=p)[(p >= th["alert"]).astype(int) != y]
    err[["host", "is_phishing", "prob"]].sample(min(300, len(err)), random_state=42).to_csv(
        METRICS / "test_error_samples.csv", index=False)
    log.info("Test (alert %.4f): %s", th["alert"], {k: res["selected"]["alert"][k] for k in ("precision", "recall", "pr_auc", "fpr")})
    print(pd.DataFrame(rows)[cols].to_string(index=False))


if __name__ == "__main__":
    main()
