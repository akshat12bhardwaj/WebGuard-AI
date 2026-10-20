"""EXP-03: retrain with observed legitimate subdomain hosts (design pre-registered in docs/DECISIONS.md D26-D30).

B = PhiUSIIL train + all new_train; C = PhiUSIIL train + 5,000 random new_train hosts.
Baseline hyperparameters (no re-tuning); isotonic calibration and thresholds exactly as ml.calibrate,
but on PhiUSIIL val + new_val. The baseline bundle is never touched.
Usage: python -m ml.exp03_train
Writes: models/experiments/exp03_{B,C}/model_bundle.joblib, reports/exp03/training.json
"""
from __future__ import annotations

import json
import time

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import brier_score_loss
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

from ml.calibrate import ece, pick_thresholds
from ml.feature_extraction import MODEL_FEATURES
from ml.utils import (
    METRICS,
    MODELS,
    PROCESSED,
    ROOT,
    SEED,
    binary_metrics,
    get_logger,
    now_utc,
    rounded,
    save_json,
)

OUT = ROOT / "reports" / "exp03"
log = get_logger("exp03_train")


def load(name: str) -> pd.DataFrame:
    return pd.read_csv(PROCESSED / name, keep_default_na=False)


def train_bundle(name: str, train: pd.DataFrame, val: pd.DataFrame) -> tuple[dict, dict]:
    X, y = train[MODEL_FEATURES].astype(float), train["is_phishing"]
    params = json.loads((METRICS / "experiment_config.json").read_text())["best_params"]["XGBoost"]
    t0 = time.perf_counter()
    model = XGBClassifier(**params, tree_method="hist", eval_metric="aucpr", random_state=SEED, n_jobs=-1,
                          scale_pos_weight=float((y == 0).sum() / (y == 1).sum())).fit(X, y)
    fit_s = time.perf_counter() - t0
    cal_idx, thr_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=SEED).split(val, groups=val["reg_domain"]))
    cal, thr = val.iloc[cal_idx], val.iloc[thr_idx]
    Xt, yt = thr[MODEL_FEATURES].astype(float), thr["is_phishing"].to_numpy()
    iso = CalibratedClassifierCV(FrozenEstimator(model), method="isotonic").fit(cal[MODEL_FEATURES].astype(float), cal["is_phishing"])
    p_raw, p = model.predict_proba(Xt)[:, 1], iso.predict_proba(Xt)[:, 1]
    th = pick_thresholds(yt, p, ndigits=None)
    sub_legit = (thr["is_phishing"] == 0) & (thr["subdomain_count"] > 0)
    info = {"model": name, "train_rows": len(train), "train_phishing_share": round(float(y.mean()), 4),
            "train_legit_with_subdomain_share": round(float((train.loc[y == 0, "subdomain_count"] > 0).mean()), 4),
            "fit_seconds": round(fit_s, 1), "val_cal_rows": len(cal), "val_thr_rows": len(thr),
            "val_thr_brier": {"uncalibrated": round(brier_score_loss(yt, p_raw), 5), "isotonic": round(brier_score_loss(yt, p), 5)},
            "val_thr_ece": {"uncalibrated": round(ece(yt, p_raw), 5), "isotonic": round(ece(yt, p), 5)},
            "thresholds": th, "val_thr_at_alert": rounded(binary_metrics(yt, p, th["alert"])),
            "val_thr_at_high": rounded(binary_metrics(yt, p, th["high"])),
            "val_thr_legit_subdomain_fpr_alert": round(float((p[sub_legit.to_numpy()] >= th["alert"]).mean()), 4)}
    tr_feats = train[MODEL_FEATURES].astype(float)
    bundle = {"model": iso, "raw_model": model, "model_name": f"XGBoost-{name}", "calibration": "isotonic",
              "features": MODEL_FEATURES, "thresholds": th, "train_min": tr_feats.min().to_dict(),
              "train_max": tr_feats.max().to_dict(), "created_at_utc": now_utc(), "version": f"host-v2-{name}",
              "dataset": "PhiUSIIL train + Tranco Q2Y54 ranks 100k-1M legitimate subdomain hosts (EXP-03)"}
    return bundle, info


def main() -> None:
    tr, va = load("train.csv"), load("val.csv")
    new_tr, new_va = load("exp03_new_train.csv"), load("exp03_new_val.csv")
    cols = ["host", "reg_domain", "is_phishing", *MODEL_FEATURES]
    val = pd.concat([va[cols], new_va[cols]], ignore_index=True)
    variants = {"B": new_tr, "C": new_tr.sample(5000, random_state=SEED)}
    report = {"seed": SEED, "val_rows_phiusiil_plus_new": len(val)}
    for name, extra in variants.items():
        train = pd.concat([tr[cols], extra[cols]], ignore_index=True).drop_duplicates("host")
        bundle, info = train_bundle(name, train, val)
        path = MODELS / "experiments" / f"exp03_{name}" / "model_bundle.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(bundle, path, compress=3)
        report[name] = info | {"bundle": str(path.relative_to(ROOT))}
        log.info("EXP-03 %s: thresholds %s, val legit-subdomain FPR@alert %s", name, info["thresholds"],
                 info["val_thr_legit_subdomain_fpr_alert"])
    OUT.mkdir(parents=True, exist_ok=True)
    save_json(report, OUT / "training.json")


if __name__ == "__main__":
    main()
