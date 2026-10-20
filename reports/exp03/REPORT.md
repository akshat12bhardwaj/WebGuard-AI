# EXP-03 — retraining with legitimate subdomain hosts (2026-10-16)

**Outcome: no candidate met the pre-registered criteria (docs/DECISIONS.md D29). The baseline stays in production.**
Candidate B removes most subdomain false alarms but loses too much phishing recall.

## Data (`reports/exp03/data_provenance.json`)

Observed hostnames from Tranco list Q2Y54 (subdomains on, created 2026-10-14 22:00 UTC), ranks 100,001–1,000,000
(900,000 rows → 871,674 valid unique hosts). Label: legitimate by popularity assumption.

| Step | Rows removed |
| --- | --- |
| No subdomain | 676,530 |
| Host is itself a public suffix (e.g. `rr.gov.br`; added after an integrity test, D31) | 831 |
| Shared-hosting platform | 419 |
| Registered domain in PhiUSIIL val/test | 8,267 |
| … in the external test set | 57,004 |
| … in Kaggle binary hosts | 21,728 |
| … in the OpenPhish snapshot | 0 |
| … in PhiUSIIL train with a phishing row | 3,168 |
| Host already in PhiUSIIL | 62 |
| More than 3 hosts per registered domain | 46,917 |
| **Selected** | **57,523** |

Split by registered domain (seed 42): new_train 41,147 (27,455 domains; includes 3,226 hosts whose domain is already
in PhiUSIIL train), new_val 8,249 (5,467), new_test 8,127 (5,468). Verified by `tests/test_phase3.py`: no domain overlap
with PhiUSIIL val/test, the external set or Kaggle; val/test disjoint from all training domains; ≤ 3 hosts per domain.

## Candidates (same XGBoost hyperparameters, isotonic, thresholds on PhiUSIIL val + new_val)

| Model | Training rows | Legit hosts with subdomain | alert / high | val_thr Brier (iso) |
| --- | --- | --- | --- | --- |
| A baseline | 158,770 | 2.9% | 0.3662 / 0.5671 | 0.1239 |
| B + all new_train | 199,917 | 32.4% | 0.3816 / 0.7143 | 0.1357 (uncal. 0.1504; ECE 0.011) |
| C + 5,000 new_train | 163,770 | 7.8% | 0.2897 / 0.7455 | 0.1455 (uncal. 0.1878; ECE 0.013) |

## Comparison (each model at its own validation thresholds; `comparison.md`, `comparison.json`, `exp03_external_rates.png`)

| Metric (n) | A baseline | B | C |
| --- | --- | --- | --- |
| Tranco-subdomain FPR @alert / @high (3,000) | 0.935 / 0.861 | **0.271 / 0.079** | 0.442 / 0.100 |
| … domain-weighted | 0.907 / 0.820 | 0.156 / 0.037 | 0.313 / 0.046 |
| New legit-subdomain test FPR @alert / @high (8,127) | 0.903 / 0.796 | 0.117 / 0.022 | 0.269 / 0.023 |
| Tranco-apex FPR @alert / @high (3,000) | 0.182 / 0.044 | 0.175 / 0.016 | 0.038 / 0.005 |
| OpenPhish recall @alert / @high (221) | 0.869 / 0.851 | 0.652 / 0.308 | 0.738 / 0.462 |
| PhiUSIIL test PR-AUC / Brier (29,453) | 0.736 / 0.141 | 0.651 / 0.170 | 0.717 / 0.169 |
| PhiUSIIL test P/R @alert | 0.772 / 0.548 | 0.758 / 0.395 | 0.947 / 0.338 |
| External all PR-AUC (6,221) | 0.118 | 0.144 | 0.255 |
| Kaggle unseen ROC-AUC (164,490) | 0.524 | 0.529 | 0.524 |
| Latency p50 (ms) | 3.70 | 4.79 | 3.66 |

OpenPhish recall 95% bootstrap CIs @alert / @high: A [0.82, 0.91] / [0.81, 0.90]; B [0.59, 0.71] / [0.25, 0.37]; C [0.68, 0.79] / [0.39, 0.53]. The recall drops are larger than the sampling noise. Latency was measured on a busier
machine than in phase 1 (baseline then 2.8 ms); compare models within this table only.

## D29 check

| Criterion | B | C |
| --- | --- | --- |
| 1 Tranco-subdomain FPR halved (alert and high) | pass | pass |
| 2 OpenPhish recall ≥ baseline − 0.10 (alert and high) | **fail** (0.652, 0.308) | **fail** (0.738, 0.462) |
| 3 Apex FPR @high ≤ baseline + 0.02 | pass | pass |
| 4 PhiUSIIL test PR-AUC ≥ baseline − 0.03 | **fail** (0.651) | pass (0.717) |
| 5 PhiUSIIL test Brier ≤ baseline + 0.01 | **fail** (0.170) | **fail** (0.169) |

## Interpretation

- Adding legitimate subdomains works as intended on false alarms, which supports the root-cause analysis.
- The recall loss shows that, from the hostname alone, many phishing hosts look like ordinary subdomains once the
  shortcut is gone. Much of the baseline's apparent phishing recall came from the shortcut itself.
- Criteria 4 and 5 use the PhiUSIIL test split, which shares the artifact (only 3.4% of its legitimate hosts, 695 of 20,283, have a
  subdomain). It therefore rewards the shortcut. This was not changed after the fact; it is recorded for future criteria.
- The higher "high" thresholds of B and C (0.71–0.75) come from the 95%-precision rule on a validation set that now
  contains many legitimate subdomains; this explains part of their low recall at "high".
