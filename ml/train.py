"""Train LR, RF, LightGBM and XGBoost on the train split; compare on validation; select by PR-AUC.

Usage: python -m ml.train [--n-iter 8]
Needs: data/processed/{train,val}.csv (python -m ml.split_dataset)
Writes: models/candidates/*.joblib, models/selected_model.json,
        reports/metrics/validation_comparison.{csv,md}, reports/metrics/val_predictions.csv,
        reports/metrics/experiment_config.json
"""
from __future__ import annotations

import argparse
import platform
import time

import joblib
import lightgbm
import pandas as pd
import sklearn
import xgboost
from lightgbm import LGBMClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold, RandomizedSearchCV
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ml.feature_extraction import MODEL_FEATURES, extract_features
from ml.utils import (
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

log = get_logger("train")


def load(name: str) -> pd.DataFrame:
    path = PROCESSED / f"{name}.csv"
    if not path.exists():
        raise SystemExit(f"{path} not found; run: python -m ml.split_dataset")
    return pd.read_csv(path, keep_default_na=False)


def domain_only(df: pd.DataFrame) -> pd.DataFrame:
    """Ablation: the same features computed from the registered domain, hiding subdomains."""
    return pd.DataFrame([extract_features(d) for d in df["reg_domain"]])[MODEL_FEATURES].astype(float)


def candidates(pos_weight: float, n_iter: int) -> dict:
    cv = GroupKFold(n_splits=3)
    search = {"n_iter": n_iter, "scoring": "average_precision", "cv": cv, "random_state": SEED, "n_jobs": 1}
    return {
        "LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(
            max_iter=2000, class_weight="balanced", random_state=SEED)),
        "RandomForest": RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced",
                                               n_jobs=-1, random_state=SEED),
        "LightGBM": RandomizedSearchCV(LGBMClassifier(scale_pos_weight=pos_weight, random_state=SEED, verbose=-1),
                                       {"n_estimators": [200, 400, 600], "learning_rate": [0.05, 0.1],
                                        "num_leaves": [31, 63, 127], "min_child_samples": [20, 50],
                                        "subsample": [0.8, 1.0], "subsample_freq": [1],
                                        "colsample_bytree": [0.8, 1.0]}, **search),
        "XGBoost": RandomizedSearchCV(XGBClassifier(tree_method="hist", eval_metric="aucpr",
                                                    scale_pos_weight=pos_weight, random_state=SEED, n_jobs=-1),
                                      {"n_estimators": [200, 400, 600], "max_depth": [4, 6, 8],
                                       "learning_rate": [0.05, 0.1], "subsample": [0.8, 1.0],
                                       "colsample_bytree": [0.8, 1.0], "min_child_weight": [1, 5]}, **search),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--n-iter", type=int, default=8, help="random-search candidates for LightGBM/XGBoost")
    args = ap.parse_args()
    tr, va = load("train"), load("val")
    X_tr, y_tr, g_tr = tr[MODEL_FEATURES].astype(float), tr["is_phishing"], tr["reg_domain"]
    X_va, y_va = va[MODEL_FEATURES].astype(float), va["is_phishing"]
    pos_weight = float((y_tr == 0).sum() / (y_tr == 1).sum())  # imbalance: ~41% phishing in train
    (MODELS / "candidates").mkdir(parents=True, exist_ok=True)

    rows, preds, params = [], va[["host", "reg_domain", "is_phishing"]].copy(), {}
    for name, est in candidates(pos_weight, args.n_iter).items():
        t0 = time.perf_counter()
        est.fit(X_tr, y_tr, **({"groups": g_tr} if isinstance(est, RandomizedSearchCV) else {}))
        fit_s = time.perf_counter() - t0
        model = est.best_estimator_ if isinstance(est, RandomizedSearchCV) else est
        params[name] = est.best_params_ if isinstance(est, RandomizedSearchCV) else model.get_params()
        joblib.dump(model, MODELS / "candidates" / f"{name}.joblib", compress=3)
        preds[name] = model.predict_proba(X_va)[:, 1]
        rows.append({"model": name, "fit_seconds": round(fit_s, 1), **rounded(binary_metrics(y_va, preds[name]))})
        log.info("%s: val PR-AUC %.4f ROC-AUC %.4f (%.1fs)", name, rows[-1]["pr_auc"], rows[-1]["roc_auc"], fit_s)

    table = pd.DataFrame(rows).sort_values("pr_auc", ascending=False)
    selected = table.iloc[0]["model"]

    # Ablation (diagnostic only, not a candidate): selected model's settings on domain-only features.
    abl = joblib.load(MODELS / "candidates" / f"{selected}.joblib")
    abl = sklearn.base.clone(abl).fit(domain_only(tr), y_tr)
    joblib.dump(abl, MODELS / "candidates" / f"{selected}_domain_only.joblib")
    preds[f"{selected}_domain_only"] = abl.predict_proba(domain_only(va))[:, 1]
    abl_row = {"model": f"{selected}_domain_only (ablation)", "fit_seconds": None,
               **rounded(binary_metrics(y_va, preds[f"{selected}_domain_only"]))}
    table = pd.concat([table, pd.DataFrame([abl_row])], ignore_index=True)

    table.to_csv(METRICS / "validation_comparison.csv", index=False)
    (METRICS / "validation_comparison.md").write_text(
        "Validation split, threshold 0.5, uncalibrated probabilities. Selection metric: PR-AUC.\n\n"
        + table.to_markdown(index=False))
    preds.to_csv(METRICS / "val_predictions.csv", index=False)
    save_json({"selected_model": selected, "criterion": "highest validation PR-AUC (average precision)",
               "selected_at_utc": now_utc(), "features": MODEL_FEATURES,
               "validation_pr_auc": table.iloc[0]["pr_auc"]}, MODELS / "selected_model.json")
    save_json({"seed": SEED, "python": platform.python_version(), "sklearn": sklearn.__version__,
               "xgboost": xgboost.__version__, "lightgbm": lightgbm.__version__, "n_iter": args.n_iter,
               "cv": "GroupKFold(3) by registered domain on train only", "scale_pos_weight": pos_weight,
               "class_weight": "balanced (LR, RF)", "features": MODEL_FEATURES, "best_params": params},
              METRICS / "experiment_config.json")
    log.info("Selected %s by validation PR-AUC", selected)
    print(table.to_string(index=False))


if __name__ == "__main__":
    main()
