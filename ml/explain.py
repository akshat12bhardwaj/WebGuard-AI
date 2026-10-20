"""Global and local SHAP explanations of the selected tree model (raw, uncalibrated margin).

SHAP values are in log-odds of the raw model; isotonic calibration is monotonic, so the direction
(toward phishing / legitimate) carries over but the magnitudes are not calibrated probabilities.
Usage: python -m ml.explain [--sample 2000]
Writes: reports/metrics/shap_global_importance.csv, reports/shap_local_examples.json,
        reports/figures/shap_summary_beeswarm.png, shap_global_bar.png, shap_local_<case>.png
"""
from __future__ import annotations

import argparse

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

from ml.feature_extraction import MODEL_FEATURES
from ml.utils import FIGURES, METRICS, MODELS, PROCESSED, ROOT, get_logger, save_json

log = get_logger("explain")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sample", type=int, default=2000)
    args = ap.parse_args()
    bundle = joblib.load(MODELS / "model_bundle.joblib")
    te = pd.read_csv(PROCESSED / "test.csv", keep_default_na=False)
    sample = te.sample(min(args.sample, len(te)), random_state=42)
    X = sample[MODEL_FEATURES].astype(float)
    explainer = shap.TreeExplainer(bundle["raw_model"])  # requires a tree model (XGBoost/LightGBM/RF)
    sv = explainer(X)

    imp = pd.DataFrame({"feature": MODEL_FEATURES, "mean_abs_shap": np.abs(sv.values).mean(0),
                        "corr_value_vs_shap": [np.corrcoef(X[f], sv.values[:, i])[0, 1] if X[f].std() else np.nan
                                               for i, f in enumerate(MODEL_FEATURES)]})
    imp["typical_direction"] = np.where(imp["corr_value_vs_shap"] > 0, "higher value -> toward phishing",
                                        "higher value -> toward legitimate")
    imp = imp.sort_values("mean_abs_shap", ascending=False).round(4)
    imp.to_csv(METRICS / "shap_global_importance.csv", index=False)

    shap.plots.beeswarm(sv, max_display=17, show=False); plt.title("SHAP values on 2,000 test hosts (log-odds)")
    plt.tight_layout(); plt.savefig(FIGURES / "shap_summary_beeswarm.png", dpi=150); plt.close()
    shap.plots.bar(sv, max_display=17, show=False); plt.tight_layout()
    plt.savefig(FIGURES / "shap_global_bar.png", dpi=150); plt.close()

    # Local explanations: one true positive, one false positive, one false negative (alert threshold).
    p = bundle["model"].predict_proba(X)[:, 1]
    pred = p >= bundle["thresholds"]["alert"]
    y = sample["is_phishing"].to_numpy().astype(bool)
    cases, out = {"true_positive": pred & y, "false_positive": pred & ~y, "false_negative": ~pred & y}, {}
    for case, mask in cases.items():
        if not mask.any():
            continue
        i = int(np.flatnonzero(mask)[0])
        shap.plots.waterfall(sv[i], max_display=10, show=False)
        plt.title(f"{case}: {sample['host'].iloc[i][:60]}"); plt.tight_layout()
        plt.savefig(FIGURES / f"shap_local_{case}.png", dpi=150); plt.close()
        order = np.argsort(-np.abs(sv.values[i]))[:5]
        out[case] = {"host": sample["host"].iloc[i], "is_phishing": int(y[i]),
                     "calibrated_probability": round(float(p[i]), 4),
                     "base_value_log_odds": round(float(sv.base_values[i]), 4),
                     "top_contributions": [{"feature": MODEL_FEATURES[j], "value": float(X.iloc[i, j]),
                                            "shap_log_odds": round(float(sv.values[i, j]), 4),
                                            "pushes_toward": "phishing" if sv.values[i, j] > 0 else "legitimate"}
                                           for j in order]}
    save_json(out, ROOT / "reports" / "shap_local_examples.json")
    log.info("SHAP top features: %s", imp["feature"].head(5).tolist())


if __name__ == "__main__":
    main()
