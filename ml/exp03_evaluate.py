"""EXP-03 comparison of A (baseline), B and C on identical evaluation sets + D29 promotion check.

Each model uses its own validation-chosen thresholds; nothing here tunes anything.
Usage: python -m ml.exp03_evaluate
Writes: reports/exp03/comparison.{json,md}, reports/exp03/*.png
"""
from __future__ import annotations

import time

import joblib
import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay

from ml.evaluate_external import features
from ml.external_data import EXTERNAL
from ml.feature_extraction import MODEL_FEATURES, extract_features
from ml.utils import (
    MODELS,
    PROCESSED,
    ROOT,
    SEED,
    binary_metrics,
    get_logger,
    rounded,
    save_json,
)

OUT = ROOT / "reports" / "exp03"
BUNDLES = {"A_baseline": MODELS / "model_bundle.joblib",
           "B_all_new": MODELS / "experiments" / "exp03_B" / "model_bundle.joblib",
           "C_5k_new": MODELS / "experiments" / "exp03_C" / "model_bundle.joblib"}
log = get_logger("exp03_evaluate")


def rate_ci(hits: np.ndarray, n_boot: int = 2000) -> list[float]:
    rng = np.random.default_rng(SEED)
    b = rng.choice(hits, (n_boot, len(hits))).mean(1)
    return [round(float(np.percentile(b, 2.5)), 4), round(float(np.percentile(b, 97.5)), 4)]


def domain_weighted(hits: np.ndarray, domains: pd.Series) -> float:
    """Each registered domain counts once (mean of per-domain rates)."""
    return round(float(pd.Series(hits).groupby(domains.to_numpy()).mean().mean()), 4)


def main() -> None:
    te = pd.read_csv(PROCESSED / "test.csv", keep_default_na=False)
    new_te = pd.read_csv(PROCESSED / "exp03_new_test.csv", keep_default_na=False)
    ext = pd.read_csv(EXTERNAL, keep_default_na=False)
    train_regs = set(pd.read_csv(PROCESSED / "train.csv", keep_default_na=False, usecols=["reg_domain"])["reg_domain"])
    kag = pd.read_csv(PROCESSED / "kaggle_binary_hosts.csv", keep_default_na=False)
    kag = kag[~kag["reg_domain"].isin(train_regs)]
    Xe = features(ext["url"])
    groups = {"tranco_apex": ext["subset"] == "tranco_apex", "tranco_subdomain": ext["subset"] == "tranco_subdomain",
              "openphish": ext["subset"] == "openphish"}
    res, fig_rows = {"sample_counts": {"phiusiil_test": len(te), "new_legit_subdomain_test": len(new_te),
                                       **{k: int(m.sum()) for k, m in groups.items()}, "kaggle_unseen": len(kag)}}, []

    for name, path in BUNDLES.items():
        b = joblib.load(path)
        th, pred = b["thresholds"], (lambda X, b=b: b["model"].predict_proba(X)[:, 1])
        r = {"thresholds": {k: round(th[k], 4) for k in ("alert", "high")}}
        p_te = pred(te[MODEL_FEATURES].astype(float))
        r["phiusiil_test"] = {k: rounded(binary_metrics(te["is_phishing"], p_te, th[k])) for k in ("alert", "high")}
        ConfusionMatrixDisplay.from_predictions(te["is_phishing"], (p_te >= th["alert"]).astype(int),
                                                display_labels=["legitimate", "phishing"])
        plt.title(f"{name}: PhiUSIIL test, alert {th['alert']:.4f}"); plt.tight_layout()
        plt.savefig(OUT / f"confusion_phiusiil_test_{name}.png", dpi=150); plt.close()

        p_new = pred(new_te[MODEL_FEATURES].astype(float))
        p_ext = pred(Xe)
        for k in ("alert", "high"):
            hit_new = p_new >= th[k]
            r[f"new_legit_subdomain_test_fpr_{k}"] = {"fpr": round(float(hit_new.mean()), 4), "ci95": rate_ci(hit_new),
                                                      "domain_weighted": domain_weighted(hit_new, new_te["reg_domain"])}
            for g, m in groups.items():
                hit = p_ext[m.to_numpy()] >= th[k]
                key = "recall" if g == "openphish" else "fpr"
                r[f"{g}_{key}_{k}"] = {key: round(float(hit.mean()), 4), "ci95": rate_ci(hit)}
                if g == "tranco_subdomain":
                    r[f"{g}_{key}_{k}"]["domain_weighted"] = domain_weighted(hit, ext.loc[m, "reg_domain"])
        y_ext = ext["is_phishing"].to_numpy()
        r["external_all"] = rounded({k: v for k, v in binary_metrics(y_ext, p_ext, th["alert"]).items()
                                     if k in ("pr_auc", "roc_auc", "precision", "recall", "fpr")})
        p_k = pred(kag[MODEL_FEATURES].astype(float))
        r["kaggle_unseen"] = rounded({k: v for k, v in binary_metrics(kag["is_phishing"], p_k, th["alert"]).items()
                                      if k in ("pr_auc", "roc_auc", "precision", "recall", "fpr", "brier")})
        urls, times = te["URL"].sample(520, random_state=SEED).tolist(), []
        for u in urls:
            t0 = time.perf_counter()
            b["model"].predict_proba(pd.DataFrame([extract_features(u)])[MODEL_FEATURES].astype(float))
            times.append((time.perf_counter() - t0) * 1000)
        r["latency_ms_p50_p95"] = [round(float(np.percentile(times[20:], q)), 3) for q in (50, 95)]
        res[name] = r
        fig_rows.append({"model": name, "subdomain FPR@alert": r["tranco_subdomain_fpr_alert"]["fpr"],
                         "subdomain FPR@high": r["tranco_subdomain_fpr_high"]["fpr"],
                         "apex FPR@high": r["tranco_apex_fpr_high"]["fpr"],
                         "OpenPhish recall@alert": r["openphish_recall_alert"]["recall"],
                         "OpenPhish recall@high": r["openphish_recall_high"]["recall"]})

    A = res["A_baseline"]
    res["promotion_check_D29"] = {}
    for name in ("B_all_new", "C_5k_new"):
        c = res[name]
        checks = {
            "1_subdomain_fpr_alert_halved": c["tranco_subdomain_fpr_alert"]["fpr"] <= 0.5 * A["tranco_subdomain_fpr_alert"]["fpr"],
            "1_subdomain_fpr_high_halved": c["tranco_subdomain_fpr_high"]["fpr"] <= 0.5 * A["tranco_subdomain_fpr_high"]["fpr"],
            "2_openphish_recall_alert": c["openphish_recall_alert"]["recall"] >= A["openphish_recall_alert"]["recall"] - 0.10,
            "2_openphish_recall_high": c["openphish_recall_high"]["recall"] >= A["openphish_recall_high"]["recall"] - 0.10,
            "3_apex_fpr_high": c["tranco_apex_fpr_high"]["fpr"] <= A["tranco_apex_fpr_high"]["fpr"] + 0.02,
            "4_phiusiil_test_pr_auc": c["phiusiil_test"]["alert"]["pr_auc"] >= A["phiusiil_test"]["alert"]["pr_auc"] - 0.03,
            "5_phiusiil_test_brier": c["phiusiil_test"]["alert"]["brier"] <= A["phiusiil_test"]["alert"]["brier"] + 0.01}
        res["promotion_check_D29"][name] = {**checks, "passes_all": all(checks.values())}
    save_json(res, OUT / "comparison.json")

    tab = pd.DataFrame(fig_rows).set_index("model")
    tab.T.plot.bar(figsize=(9, 4.5), title="EXP-03: external false-alarm rates and phishing recall")
    plt.ylabel("rate"); plt.xticks(rotation=20, ha="right"); plt.tight_layout()
    plt.savefig(OUT / "exp03_external_rates.png", dpi=150); plt.close()
    rows = []
    for name in BUNDLES:
        r = res[name]
        rows.append({"model": name, "alert": r["thresholds"]["alert"], "high": r["thresholds"]["high"],
                     "PhiUSIIL PR-AUC": r["phiusiil_test"]["alert"]["pr_auc"], "PhiUSIIL Brier": r["phiusiil_test"]["alert"]["brier"],
                     "PhiUSIIL P/R @alert": f"{r['phiusiil_test']['alert']['precision']:.3f}/{r['phiusiil_test']['alert']['recall']:.3f}",
                     "PhiUSIIL P/R @high": f"{r['phiusiil_test']['high']['precision']:.3f}/{r['phiusiil_test']['high']['recall']:.3f}",
                     "new-sub FPR @alert/@high": f"{r['new_legit_subdomain_test_fpr_alert']['fpr']:.3f}/{r['new_legit_subdomain_test_fpr_high']['fpr']:.3f}",
                     "Tranco-sub FPR @alert/@high": f"{r['tranco_subdomain_fpr_alert']['fpr']:.3f}/{r['tranco_subdomain_fpr_high']['fpr']:.3f}",
                     "Tranco-apex FPR @alert/@high": f"{r['tranco_apex_fpr_alert']['fpr']:.3f}/{r['tranco_apex_fpr_high']['fpr']:.3f}",
                     "OpenPhish recall @alert/@high": f"{r['openphish_recall_alert']['recall']:.3f}/{r['openphish_recall_high']['recall']:.3f}",
                     "external PR-AUC": r["external_all"]["pr_auc"], "Kaggle ROC-AUC": r["kaggle_unseen"]["roc_auc"],
                     "latency p50 ms": r["latency_ms_p50_p95"][0]})
    (OUT / "comparison.md").write_text(pd.DataFrame(rows).to_markdown(index=False), encoding="utf-8")
    log.info("D29 promotion check: %s", {k: v["passes_all"] for k, v in res["promotion_check_D29"].items()})
    print(pd.DataFrame(rows).T.to_string())


if __name__ == "__main__":
    main()
