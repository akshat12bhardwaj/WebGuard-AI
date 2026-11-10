"""EXP-02: does adding Kaggle phishing/benign hosts help? The baseline bundle is NOT modified.

Models (same XGBoost hyperparameters as the baseline, no re-tuning):
  B  baseline raw XGBoost (loaded from models/candidates/XGBoost.joblib)
  C  PhiUSIIL train + Kaggle train
  D  Kaggle train only (shows how dataset-specific each source is)
Kaggle hosts whose registered domain is in PhiUSIIL val/test are removed first; Kaggle is then split by
registered domain (70/30, seed 42) and Kaggle-test also drops PhiUSIIL-train domains.
Common operating point: per model, the lowest threshold with FPR <= 10% on PhiUSIIL validation.

Decision rule fixed before the first run: Kaggle data counts as useful for training only if C beats B by
>= 0.02 PR-AUC on external_all AND >= 0.02 ROC-AUC on openphish_vs_tranco_subdomain, while losing
<= 0.02 PR-AUC on the PhiUSIIL test split. Even then the baseline stays deployed in this phase; C would
need its own calibration on a fresh validation split before replacing it.
Usage: python -m ml.additional_data_experiment
Writes: models/experiments/exp02_{C,D}.joblib, reports/metrics/exp02_additional_data.{json,md}
"""
from __future__ import annotations

import json

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

from ml.evaluate_external import features
from ml.external_data import EXTERNAL
from ml.feature_extraction import MODEL_FEATURES
from ml.utils import (
    METRICS,
    MODELS,
    PROCESSED,
    SEED,
    binary_metrics,
    get_logger,
    rounded,
    save_json,
)

log = get_logger("exp02")


def load(name: str) -> pd.DataFrame:
    return pd.read_csv(PROCESSED / name, keep_default_na=False)


def xgb(X, y) -> XGBClassifier:
    params = json.loads((METRICS / "experiment_config.json").read_text())["best_params"]["XGBoost"]
    return XGBClassifier(**params, tree_method="hist", eval_metric="aucpr", random_state=SEED, n_jobs=-1,
                         scale_pos_weight=float((y == 0).sum() / (y == 1).sum())).fit(X, y)


def alert_threshold(y, p) -> float:
    fpr, _, thr = roc_curve(y, p)
    return float(thr[(fpr <= 0.10) & np.isfinite(thr)].min())


def main() -> None:
    tr, va, te = load("train.csv"), load("val.csv"), load("test.csv")
    kag = load("kaggle_binary_hosts.csv")
    kag = kag[~kag["reg_domain"].isin(set(va["reg_domain"]) | set(te["reg_domain"]))]
    k_tr_idx, k_te_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
                              .split(kag, groups=kag["reg_domain"]))
    k_tr, k_te = kag.iloc[k_tr_idx], kag.iloc[k_te_idx]
    k_te = k_te[~k_te["reg_domain"].isin(set(tr["reg_domain"]))]
    assert not set(k_tr["reg_domain"]) & set(k_te["reg_domain"])

    combo = pd.concat([tr, k_tr], ignore_index=True)
    combo = combo[combo.groupby("host")["is_phishing"].transform("nunique") == 1].drop_duplicates("host")
    X = lambda d: d[MODEL_FEATURES].astype(float)
    models = {"B_baseline": joblib.load(MODELS / "candidates" / "XGBoost.joblib"),
              "C_phiusiil+kaggle": xgb(X(combo), combo["is_phishing"]),
              "D_kaggle_only": xgb(X(k_tr), k_tr["is_phishing"])}
    (MODELS / "experiments").mkdir(parents=True, exist_ok=True)
    joblib.dump(models["C_phiusiil+kaggle"], MODELS / "experiments" / "exp02_C.joblib", compress=3)
    joblib.dump(models["D_kaggle_only"], MODELS / "experiments" / "exp02_D.joblib", compress=3)

    ext = pd.read_csv(EXTERNAL, keep_default_na=False)
    ext_X = features(ext["url"])
    evals = {"phiusiil_test": (X(te), te["is_phishing"].to_numpy()),
             "kaggle_test": (X(k_te), k_te["is_phishing"].to_numpy()),
             "external_all": (ext_X, ext["is_phishing"].to_numpy())}
    for sub in ("tranco_apex", "tranco_subdomain"):
        m = (ext["subset"] != ("tranco_subdomain" if sub == "tranco_apex" else "tranco_apex")).to_numpy()
        evals[f"openphish_vs_{sub}"] = (ext_X[m], ext["is_phishing"].to_numpy()[m])

    res = {"kaggle_train_hosts": len(k_tr), "kaggle_test_hosts": len(k_te), "combined_train_hosts": len(combo),
           "kaggle_share_with_subdomain": {"benign": round(float((k_tr.loc[k_tr.is_phishing == 0, "subdomain_count"] > 0).mean()), 4),
                                           "phishing": round(float((k_tr.loc[k_tr.is_phishing == 1, "subdomain_count"] > 0).mean()), 4)},
           "models": {}}
    for name, m in models.items():
        t = alert_threshold(va["is_phishing"], m.predict_proba(X(va))[:, 1])
        r = {"alert_threshold_from_phiusiil_val": round(t, 4)}
        for ev, (Xe, ye) in evals.items():
            met = binary_metrics(ye, m.predict_proba(Xe)[:, 1], t)
            r[ev] = rounded({k: met[k] for k in ("pr_auc", "roc_auc", "precision", "recall", "fpr")})
        res["models"][name] = r

    b, c = res["models"]["B_baseline"], res["models"]["C_phiusiil+kaggle"]
    gains = {"external_all_pr_auc": c["external_all"]["pr_auc"] - b["external_all"]["pr_auc"],
             "subdomain_roc_auc": c["openphish_vs_tranco_subdomain"]["roc_auc"] - b["openphish_vs_tranco_subdomain"]["roc_auc"],
             "phiusiil_test_pr_auc": c["phiusiil_test"]["pr_auc"] - b["phiusiil_test"]["pr_auc"]}
    res["decision"] = {"gains_C_minus_B": {k: round(v, 4) for k, v in gains.items()},
                       "kaggle_useful_for_training": bool(gains["external_all_pr_auc"] >= 0.02
                                                          and gains["subdomain_roc_auc"] >= 0.02
                                                          and gains["phiusiil_test_pr_auc"] >= -0.02)}
    save_json(res, METRICS / "exp02_additional_data.json")
    rows = [{"model": n, "eval": e, **v} for n, r in res["models"].items() for e, v in r.items() if isinstance(v, dict)]
    (METRICS / "exp02_additional_data.md").write_text(pd.DataFrame(rows).to_markdown(index=False))
    log.info("EXP-02 decision: %s", res["decision"])


if __name__ == "__main__":
    main()
