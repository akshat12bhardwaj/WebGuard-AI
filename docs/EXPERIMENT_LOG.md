# Experiment log

## EXP-01 — hostname-only baseline comparison (2026-10-15)

| Item | Value |
| --- | --- |
| Data | PhiUSIIL CSV SHA-256 `a236549c…d06d1c6`; `data/processed/dataset.csv` SHA-256 `3b5951ad…48dc9` |
| Split | Domain-grouped, seed 42: train 158,770 rows / 122,810 domains (40.6% phishing); val 30,810 / 26,317 (34.6%); test 29,453 / 26,317 (31.1%); no domain overlap (asserted) |
| Features | 17 hostname features (`MODEL_FEATURES`; `docs/DATA_DICTIONARY.md`) |
| Imbalance | `class_weight="balanced"` (LR, RF); `scale_pos_weight` = 1.464 (LightGBM, XGBoost) |
| Tuning | 8 random candidates, GroupKFold(3) by domain on train, scoring = average precision |
| Environment | Python 3.13.7, scikit-learn 1.9.1, XGBoost 3.4.1, LightGBM 4.7.0, SHAP 0.53.0 (`reports/metrics/pip_freeze.txt`) |
| Config file | `reports/metrics/experiment_config.json` |

**Best parameters.** XGBoost: n_estimators 200, max_depth 6, learning_rate 0.05, subsample 0.8, colsample_bytree 0.8,
min_child_weight 1. LightGBM: n_estimators 200, num_leaves 31, learning_rate 0.05, min_child_samples 50, subsample 1.0,
colsample_bytree 0.8. RF: 300 trees, min_samples_leaf 2. LR: StandardScaler + L2, max_iter 2000.

### Validation (threshold 0.5, uncalibrated) — used for selection

| Model | Fit (s) | Precision | Recall | F1 | ROC-AUC | PR-AUC | Brier | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **XGBoost** | 16.0 | 0.846 | 0.597 | 0.700 | 0.831 | **0.812** | 0.135 | 0.057 |
| LightGBM | 21.0 | 0.843 | 0.599 | 0.700 | 0.830 | 0.812 | 0.135 | 0.059 |
| Random Forest | 2.8 | 0.796 | 0.610 | 0.691 | 0.817 | 0.800 | 0.142 | 0.082 |
| Logistic Regression | 0.3 | 0.861 | 0.553 | 0.674 | 0.801 | 0.786 | 0.145 | 0.047 |
| XGBoost, domain-only features (ablation) | — | 0.646 | 0.457 | 0.535 | 0.730 | 0.623 | 0.190 | 0.132 |

Fit times include the random search for LightGBM and XGBoost. **Selected: XGBoost** (highest validation PR-AUC, 0.8120 vs
LightGBM 0.8116 — a practical tie; either is defensible).

### Calibration and thresholds (validation only; val_cal 14,370 rows fits, val_thr 16,440 rows compares)

| Variant | Brier | Log loss | ECE |
| --- | --- | --- | --- |
| Uncalibrated | 0.1267 | 0.3976 | 0.0483 |
| Sigmoid | 0.1251 | 0.4026 | 0.0290 |
| **Isotonic (kept)** | **0.1239** | **0.3975** | **0.0093** |

Thresholds on val_thr: **alert 0.3662** (rule: FPR ≤ 10%; achieved precision 0.864, recall 0.680, FPR 0.069) and
**high 0.5671** (rule: precision ≥ 95%; achieved precision 0.964, recall 0.595, FPR 0.014).
Figure: `reports/figures/reliability_val.png`; sweep: `reports/metrics/threshold_sweep_val.csv`.

### Final test (run once, after all choices were fixed)

| Model | Threshold | Precision | Recall | F1 | ROC-AUC | PR-AUC | Brier | FPR | FNR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **XGBoost + isotonic** | alert 0.3662 | 0.772 | 0.548 | 0.641 | 0.797 | 0.736 | 0.141 | 0.073 | 0.452 |
| **XGBoost + isotonic** | high 0.5671 | 0.918 | 0.418 | 0.574 | 0.797 | 0.736 | 0.141 | 0.017 | 0.582 |
| XGBoost (raw) | 0.5 | 0.799 | 0.530 | 0.637 | 0.798 | 0.747 | 0.144 | 0.060 | 0.470 |
| LightGBM (raw) | 0.5 | 0.795 | 0.532 | 0.637 | 0.800 | 0.748 | 0.144 | 0.062 | 0.468 |
| Random Forest (raw) | 0.5 | 0.744 | 0.539 | 0.625 | 0.782 | 0.730 | 0.153 | 0.084 | 0.461 |
| Logistic Regression (raw) | 0.5 | 0.786 | 0.477 | 0.594 | 0.764 | 0.709 | 0.157 | 0.059 | 0.523 |
| Domain-only ablation | 0.5 | 0.569 | 0.386 | 0.460 | 0.706 | 0.561 | 0.191 | 0.132 | 0.614 |

Class-wise at the alert threshold: legitimate precision 0.819 / recall 0.927; phishing precision 0.772 / recall 0.548
(`reports/metrics/test_classification_report.txt`). Latency: 2.79 ms p50, 2.91 ms p95 per URL (feature extraction +
calibrated prediction, single process, 500 URLs after 20 warm-up calls).

### Interpretation

- Test performance is below validation (PR-AUC 0.736 vs 0.855 on val_thr). The thresholds did not fully transfer: test
  precision at "high" is 0.918, not 0.95; FPR at "alert" is 7.3%. Different domain groups behave differently. These
  numbers were not used to tune anything.
- Isotonic calibration lowers PR-AUC slightly (0.747 → 0.736) because it merges scores into ties, while improving
  probability quality. This is an accepted trade-off.
- Hiding subdomains costs ~0.19 PR-AUC, so much of the signal is subdomain structure. Part of it is a PhiUSIIL artifact,
  so real-world false positives on legitimate subdomains (e.g. `docs.example.com`) are likely higher than measured.
- About 45% of phishing test hosts look like ordinary domains and are missed. Hostname-only ML cannot replace threat
  intelligence and rules.

### Artifacts

`models/model_bundle.joblib` (selected), `models/candidates/*.joblib`, `models/selected_model.json`,
`reports/metrics/{validation_comparison,test_results}.{csv,md,json}`, `reports/figures/test_*.png`.

## EVAL-EXT-01 — unchanged baseline on external data (2026-10-15)

Script: `python -m ml.evaluate_external` (bundle read-only; thresholds alert 0.3662 / high 0.5671 from validation; 1,000
stratified bootstrap resamples, seed 42). Sets: `data/external/external_test.csv` (221 OpenPhish phishing hosts, 3,000
Tranco apex domains, 3,000 Tranco hosts with a subdomain; no registered-domain overlap with PhiUSIIL train or Kaggle) and
Kaggle phishing/benign hosts whose registered domain is not in PhiUSIIL train (45,566 phishing, 118,924 benign).

| Set | Level | Precision | Recall | FPR | PR-AUC | ROC-AUC |
| --- | --- | --- | --- | --- | --- | --- |
| OpenPhish vs Tranco apex | alert | 0.261 | 0.869 | 0.182 | 0.811 | 0.919 |
| OpenPhish vs Tranco apex | high | 0.589 | 0.851 | 0.044 | 0.811 | 0.919 |
| OpenPhish vs Tranco **subdomain** | alert | 0.064 | 0.869 | **0.935** | 0.122 | 0.640 |
| OpenPhish vs Tranco **subdomain** | high | 0.068 | 0.851 | **0.861** | 0.122 | 0.640 |
| External, all | alert | 0.054 | 0.869 [0.824, 0.910] | 0.558 | 0.118 | 0.780 |
| Kaggle, unseen domains | alert | 0.283 | 0.311 | 0.302 | 0.286 | 0.524 |
| Kaggle, unseen domains | high | 0.265 | 0.225 | 0.239 | 0.286 | 0.524 |

FPR 95% CI: apex alert [0.169, 0.196], high [0.037, 0.051]; subdomain alert [0.926, 0.943], high [0.849, 0.874].
Files: `reports/metrics/external_results.{json,md}`, `reports/figures/external_{pr_curves,fpr_by_subset,confusion_*}.png`.

**Findings.** (1) On apex domains the model generalises reasonably (ROC-AUC 0.92, FPR 4.4% at "high"). (2) On legitimate
hosts with a subdomain it is unusable: it flags 86–93% of them. This confirms the PhiUSIIL subdomain artifact
(DATA_DICTIONARY). (3) On Kaggle it is near chance (ROC-AUC 0.52); Kaggle's per-URL labels on shared hosts make it a weak
benchmark, so this mostly measures label disagreement. (4) Precision on the mixed external set is not meaningful as a
real-world estimate: the class ratio (221 vs 6,000) is arbitrary. Only 221 phishing hosts — wide recall CI.

## EXP-02 — additional Kaggle training data (2026-10-15)

Script: `python -m ml.additional_data_experiment`. Kaggle hosts in PhiUSIIL val/test domains removed; Kaggle split by
registered domain 70/30 (seed 42) → 115,541 train / 45,641 test hosts (test also excludes PhiUSIIL-train domains).
Same XGBoost hyperparameters as the baseline, no re-tuning. Common operating point = threshold with FPR ≤ 10% on PhiUSIIL
validation. Decision rule written into the script before the first run.

| Model | PhiUSIIL test PR-AUC | Kaggle test PR-AUC | External all PR-AUC | Subdomain ROC-AUC | Apex ROC-AUC | Subdomain FPR |
| --- | --- | --- | --- | --- | --- | --- |
| B baseline (raw XGB) | 0.747 | 0.311 | 0.206 | 0.675 | 0.919 | 0.947 |
| C PhiUSIIL + Kaggle | 0.723 | 0.408 | 0.180 | 0.675 | 0.903 | 0.911 |
| D Kaggle only | 0.481 | 0.497 | 0.090 | 0.650 | 0.683 | 0.265 |

Gains C − B: external PR-AUC −0.027, subdomain ROC-AUC +0.000 (0.67473 vs 0.67472), PhiUSIIL test PR-AUC −0.024 →
**rule not met; Kaggle is not used for training** (D17). Kaggle benign hosts do include subdomains (22.9%, phishing
24.5%), but adding them did not separate legitimate from phishing subdomain hosts. Model D's low subdomain FPR comes with
recall 0.54 and near-random apex ranking — a different trade-off, not a better model.
Artifacts: `models/experiments/exp02_{C,D}.joblib`, `reports/metrics/exp02_additional_data.{json,md}`.

## EXP-03 — retraining with legitimate subdomain hosts (2026-10-16)

Design pre-registered in DECISIONS D26–D30 before any result. Full report: `reports/exp03/REPORT.md`; root-cause
analysis: `reports/subdomain_bias_analysis.md`. Scripts: `ml.subdomain_bias`, `ml.subdomain_data`, `ml.exp03_train`,
`ml.exp03_evaluate`, `ml.fusion_report`.

| Metric | A baseline | B (+41,147 legit subdomain hosts) | C (+5,000) |
| --- | --- | --- | --- |
| Tranco-subdomain FPR @alert / @high | 0.935 / 0.861 | 0.271 / 0.079 | 0.442 / 0.100 |
| New legit-subdomain test FPR @alert / @high (n = 8,127) | 0.903 / 0.796 | 0.117 / 0.022 | 0.269 / 0.023 |
| OpenPhish recall @alert / @high (n = 221) | 0.869 / 0.851 | 0.652 / 0.308 | 0.738 / 0.462 |
| PhiUSIIL test PR-AUC / Brier | 0.736 / 0.141 | 0.651 / 0.170 | 0.717 / 0.169 |

D29: B fails criteria 2, 4, 5; C fails 2, 5 → **baseline retained** (D32). Artifacts:
`models/experiments/exp03_{B,C}/model_bundle.joblib`, `reports/exp03/`.

### Raw model vs final API (baseline, offline, TI not checked) — `reports/exp03/fusion_report.md`

| Group (n) | Raw @alert | Final caution or worse (current guard) | Final high_risk | Final caution+ if guard = below_alert |
| --- | --- | --- | --- | --- |
| Tranco apex (3,000) | 0.182 | 0.183 | 0.046 | 0.183 |
| Tranco subdomain (3,000) | 0.935 | 0.935 | 0.051 | 0.051 |
| New legit subdomain test (8,127) | 0.903 | 0.903 | 0.004 | 0.004 |
| OpenPhish (221; detection rate) | 0.869 | 0.873 | 0.063 | 0.095 |

The final 'high_risk' on legitimate subdomain hosts comes entirely from `BRAND_IN_HOST_MISMATCH` (D36).
