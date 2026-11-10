"""Investigate the baseline's false positives on legitimate subdomain hosts (read-only on the baseline).

Usage: python -m ml.subdomain_bias
Writes: reports/subdomain_bias/{analysis.json, false_positive_examples.csv, *.png}
"""
from __future__ import annotations

import joblib
import matplotlib
import numpy as np
import pandas as pd
import shap

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from ml.evaluate_external import features
from ml.external_data import EXTERNAL
from ml.feature_extraction import MODEL_FEATURES, extract_features
from ml.utils import MODELS, PROCESSED, ROOT, save_json

OUT = ROOT / "reports" / "subdomain_bias"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    b = joblib.load(MODELS / "model_bundle.joblib")
    alert = b["thresholds"]["alert"]
    ext = pd.read_csv(EXTERNAL, keep_default_na=False)
    sub = ext[ext["subset"] == "tranco_subdomain"].reset_index(drop=True)
    apex = ext[ext["subset"] == "tranco_apex"].reset_index(drop=True)
    te = pd.read_csv(PROCESSED / "test.csv", keep_default_na=False)
    tr = pd.read_csv(PROCESSED / "train.csv", keep_default_na=False)
    Xs, Xa = features(sub["url"]), features(apex["url"])
    ps, pa = b["model"].predict_proba(Xs)[:, 1], b["model"].predict_proba(Xa)[:, 1]
    fp = ps >= alert
    res = {"n_subdomain_hosts": len(sub), "n_unique_registered_domains": int(sub["reg_domain"].nunique()),
           "fpr_alert_subdomain": round(float(fp.mean()), 4), "fpr_alert_apex": round(float((pa >= alert).mean()), 4)}

    # 1) Which features change when only the subdomain is removed (host -> registered domain)?
    Xr = pd.DataFrame([extract_features(d) for d in sub["reg_domain"]])[MODEL_FEATURES].astype(float)
    res["share_changed_by_subdomain"] = {f: round(float((Xs[f] != Xr[f]).mean()), 4) for f in MODEL_FEATURES}

    # 2) Counterfactual: score the same sites with the subdomain removed.
    pr = b["model"].predict_proba(Xr)[:, 1]
    res["counterfactual_registered_domain_only"] = {
        "fpr_alert": round(float((pr >= alert).mean()), 4),
        "false_positives_that_clear": round(float((pr[fp] < alert).mean()), 4),
        "median_prob_host": round(float(np.median(ps)), 4), "median_prob_reg_domain": round(float(np.median(pr)), 4)}

    # 3) SHAP: mean contribution on false positives vs correctly scored apex domains.
    ex = shap.TreeExplainer(b["raw_model"])
    sv_fp = ex.shap_values(Xs[fp])
    sv_ap = ex.shap_values(Xa[pa < alert])
    shap_tab = pd.DataFrame({"feature": MODEL_FEATURES, "mean_shap_subdomain_FP": sv_fp.mean(0),
                             "mean_shap_apex_TN": sv_ap.mean(0)}).round(4)
    shap_tab["difference"] = (shap_tab["mean_shap_subdomain_FP"] - shap_tab["mean_shap_apex_TN"]).round(4)
    shap_tab = shap_tab.sort_values("difference", ascending=False)
    res["shap_top_differences"] = shap_tab.head(6).set_index("feature")["difference"].to_dict()

    # 4) Distributions: training data vs external legitimate subdomains.
    res["subdomain_count_share_gt0"] = {
        "train_legit": round(float((tr.loc[tr.is_phishing == 0, "subdomain_count"] > 0).mean()), 4),
        "train_phish": round(float((tr.loc[tr.is_phishing == 1, "subdomain_count"] > 0).mean()), 4),
        "tranco_subdomain": 1.0}
    res["train_phish_rate_by_subdomain_count"] = tr.groupby(tr["subdomain_count"].clip(upper=3))["is_phishing"].mean().round(4).to_dict()
    legit_sub_test = te[(te.is_phishing == 0) & (te.subdomain_count > 0)]
    res["phiusiil_test_legit_with_subdomain"] = {
        "n": len(legit_sub_test),
        "fpr_alert": round(float((b["model"].predict_proba(legit_sub_test[MODEL_FEATURES].astype(float))[:, 1] >= alert).mean()), 4)
        if len(legit_sub_test) else None}

    # 5) Where are the errors concentrated?
    first = sub["host"].str.split(".").str[0]
    sub = sub.assign(prob=ps, prob_reg_only=pr, first_label=first, fp=fp)
    by_label = sub.groupby("first_label").agg(n=("fp", "size"), fpr=("fp", "mean")).query("n >= 15").sort_values("n", ascending=False)
    res["fpr_by_common_first_label"] = by_label.head(12).round(3).to_dict("index")
    res["fpr_by_subdomain_count"] = sub.groupby(Xs["subdomain_count"].clip(upper=3).values)["fp"].mean().round(4).to_dict()
    res["hosts_per_registered_domain"] = sub["reg_domain"].value_counts().describe().round(2).to_dict()
    res["top_registered_domains_among_fp"] = sub.loc[sub.fp, "reg_domain"].value_counts().head(8).to_dict()
    sub.loc[sub.fp].sort_values("prob", ascending=False)[["host", "reg_domain", "prob", "prob_reg_only"]].head(40).to_csv(
        OUT / "false_positive_examples.csv", index=False)
    save_json(res, OUT / "analysis.json")
    shap_tab.to_csv(OUT / "shap_fp_vs_apex.csv", index=False)

    _, ax = plt.subplots(1, 2, figsize=(11, 4))
    ax[0].hist([ps, pr, pa], bins=20, label=["subdomain hosts", "same sites, subdomain removed", "apex domains"])
    ax[0].axvline(alert, ls="--", c="k"); ax[0].set_xlabel("baseline calibrated P(phishing)"); ax[0].legend(fontsize=8)
    ax[0].set_title("Legitimate Tranco hosts")
    top = shap_tab.head(8).iloc[::-1]
    ax[1].barh(top["feature"], top["difference"]); ax[1].set_xlabel("mean SHAP (subdomain FP) - mean SHAP (apex TN)")
    ax[1].set_title("Features pushing subdomain hosts toward phishing")
    plt.tight_layout(); plt.savefig(OUT / "subdomain_bias_overview.png", dpi=150); plt.close()
    print(pd.Series({k: v for k, v in res.items() if not isinstance(v, dict)}).to_string())


if __name__ == "__main__":
    main()
