"""Calibration and threshold analysis for the selected model, using validation data only.

The validation split is divided by registered domain into val_cal (fits calibrators) and
val_thr (compares calibrators and chooses thresholds), so neither step sees its own fit data.
Usage: python -m ml.calibrate
Writes: models/model_bundle.joblib, reports/metrics/calibration.json, threshold_sweep_val.csv,
        reports/figures/reliability_val.png
"""
from __future__ import annotations

import joblib
import matplotlib

matplotlib.use("Agg")
import json

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import (
    brier_score_loss,
    log_loss,
    precision_recall_curve,
    roc_curve,
)
from sklearn.model_selection import GroupShuffleSplit

from ml.feature_extraction import MODEL_FEATURES
from ml.utils import (
    FIGURES,
    METRICS,
    MODELS,
    PROCESSED,
    SEED,
    binary_metrics,
    get_logger,
    now_utc,
    rounded,
    save_json,
)

log = get_logger("calibrate")
HIGH_PRECISION, ALERT_MAX_FPR = 0.95, 0.10


def ece(y, p, bins: int = 10) -> float:
    """Expected calibration error with equal-width bins."""
    idx = np.minimum((p * bins).astype(int), bins - 1)
    return float(sum(abs(y[idx == b].mean() - p[idx == b].mean()) * (idx == b).mean()
                     for b in range(bins) if (idx == b).any()))


def pick_thresholds(y, p, ndigits: int | None = 4) -> dict:
    """high: smallest threshold with precision >= 0.95; alert: smallest threshold with FPR <= 0.10.
    ndigits=4 reproduces the baseline; rounding can cross tied isotonic scores, so EXP-03 passes None."""
    r = (lambda v: round(v, ndigits)) if ndigits is not None else (lambda v: v)
    prec, _, thr_pr = precision_recall_curve(y, p)
    hi = thr_pr[prec[:-1] >= HIGH_PRECISION]
    fpr, _, thr_roc = roc_curve(y, p)
    lo = thr_roc[(fpr <= ALERT_MAX_FPR) & np.isfinite(thr_roc)]
    return {"alert": r(float(lo.min())) if len(lo) else None,
            "high": r(float(hi.min())) if len(hi) else None,
            "rule": f"alert: lowest threshold with FPR <= {ALERT_MAX_FPR}; "
                    f"high: lowest threshold with precision >= {HIGH_PRECISION} (on val_thr)"}


def main() -> None:
    sel = json.loads((MODELS / "selected_model.json").read_text())["selected_model"]
    model = joblib.load(MODELS / "candidates" / f"{sel}.joblib")
    va = pd.read_csv(PROCESSED / "val.csv", keep_default_na=False)
    tr = pd.read_csv(PROCESSED / "train.csv", keep_default_na=False, usecols=MODEL_FEATURES)
    cal_idx, thr_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=SEED)
                            .split(va, groups=va["reg_domain"]))
    cal, thr = va.iloc[cal_idx], va.iloc[thr_idx]
    Xc, yc = cal[MODEL_FEATURES].astype(float), cal["is_phishing"].to_numpy()
    Xt, yt = thr[MODEL_FEATURES].astype(float), thr["is_phishing"].to_numpy()

    variants = {"uncalibrated": model}
    for method in ("sigmoid", "isotonic"):
        variants[method] = CalibratedClassifierCV(FrozenEstimator(model), method=method).fit(Xc, yc)
    probs = {k: v.predict_proba(Xt)[:, 1] for k, v in variants.items()}
    scores = {k: {"brier": round(brier_score_loss(yt, p), 5), "log_loss": round(log_loss(yt, p), 5),
                  "ece": round(ece(yt, p), 5)} for k, p in probs.items()}
    best = min(scores, key=lambda k: scores[k]["brier"])
    if best != "uncalibrated" and scores["uncalibrated"]["brier"] - scores[best]["brier"] < 1e-4:
        best = "uncalibrated"  # keep the simpler model unless calibration measurably helps
    p = probs[best]
    th = pick_thresholds(yt, p)

    sweep = pd.DataFrame([rounded(binary_metrics(yt, p, t)) for t in np.round(np.arange(0.05, 1.0, 0.05), 2)])
    sweep.to_csv(METRICS / "threshold_sweep_val.csv", index=False)

    plt.figure(figsize=(5.5, 5)); plt.plot([0, 1], [0, 1], "k--", lw=1, label="perfect")
    for k, pk in probs.items():
        fp_, mp_ = calibration_curve(yt, pk, n_bins=10, strategy="quantile")
        plt.plot(mp_, fp_, marker="o", ms=3, label=f"{k} (Brier {scores[k]['brier']:.4f})")
    plt.xlabel("mean predicted P(phishing)"); plt.ylabel("observed phishing share")
    plt.title(f"Reliability on val_thr ({sel})"); plt.legend(); plt.tight_layout()
    plt.savefig(FIGURES / "reliability_val.png", dpi=150); plt.close()

    report = {"selected_model": sel, "val_cal_rows": len(cal), "val_thr_rows": len(thr),
              "scores_on_val_thr": scores, "chosen_calibration": best, "thresholds": th,
              "val_thr_metrics_at_alert": rounded(binary_metrics(yt, p, th["alert"])),
              "val_thr_metrics_at_high": rounded(binary_metrics(yt, p, th["high"]))}
    save_json(report, METRICS / "calibration.json")
    joblib.dump({"model": variants[best], "raw_model": model, "model_name": sel, "calibration": best,
                 "features": MODEL_FEATURES, "thresholds": th,
                 "train_min": tr.min().to_dict(), "train_max": tr.max().to_dict(),
                 "created_at_utc": now_utc(), "dataset": "UCI PhiUSIIL (CC BY 4.0), domain-grouped split seed 42",
                 "version": "host-v1"}, MODELS / "model_bundle.joblib")
    log.info("Calibration=%s %s; thresholds alert=%s high=%s", best, scores[best], th["alert"], th["high"])


if __name__ == "__main__":
    main()
