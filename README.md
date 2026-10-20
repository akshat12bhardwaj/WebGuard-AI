# AI-Based Website Risk Analyzer (WebGuard AI)

Phishing-risk classifier for an explainable website-safety browser extension (university AI course project).
Status: phases 1–5 are done: ML pipeline, external validation, subdomain-bias experiment, hardened rules and
threat intelligence, API contract v1.0 (`docs/API_CONTRACT.md`) and the **Chrome extension** (`extension/`, v0.8;
see `extension/README.md`). **Phase 6 is frozen** (2026-10-20, `docs/PHASE6_PROTOCOL.md`). Fresh-data collection is
in progress, and no Phase 6 results exist yet.

**Quick start:**
1. Run the pipeline below, which creates `models/model_bundle.joblib`. Data and model files are not in the repository.
2. Start the backend: `python -m backend.serve`. This loads `.env`, then serves on 127.0.0.1:8000.
3. Load `extension/` via chrome://extensions → Developer mode → Load unpacked.
4. Open a page and click the WebGuard AI icon. It shows the score, and *View detailed report* opens the full report.

**Optional reputation keys:** put `URLHAUS_AUTH_KEY` and `GOOGLE_SAFE_BROWSING_KEY` in `.env` (read by
`python -m backend.serve`), or set them as environment variables before starting the backend. `.env.example` lists the names and where to get each key. Never commit real keys: `.env` is
gitignored. Without keys, those two sources report "not checked — not configured".

The model scores a URL from its **hostname only** (17 features, no page download). Its output is a calibrated
probability that the host is a phishing host. It is **not** the final 0–100 risk score and never proves a site is safe.

## Results (measured 2026-10-15, untouched domain-grouped test split, 29,453 hosts)

| Model | Threshold | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| XGBoost + isotonic (selected) | alert 0.3662 | 0.772 | 0.548 | 0.641 | 0.736 | 0.797 | 0.073 |
| XGBoost + isotonic (selected) | high 0.5671 | 0.918 | 0.418 | 0.574 | 0.736 | 0.797 | 0.017 |

All candidates and plots: `reports/metrics/test_results.md`, `reports/figures/`. Details: `docs/EXPERIMENT_LOG.md`.

**External check (independent data, 2026-10-15):** on OpenPhish phishing vs popular Tranco apex domains the model reaches
ROC-AUC 0.92 and 4.4% FPR at the high threshold, but it flags **86–93% of legitimate hosts that have a subdomain**
(e.g. `docs.example.com`). Until the model is retrained, the API caps model-only verdicts for such hosts at "caution".
The Kaggle Malicious URLs dataset was evaluated and rejected as training data (EXP-02).

**Phase 3 (2026-10-16):** the bias comes from PhiUSIIL (legitimate training hosts almost never have subdomains;
`reports/subdomain_bias_analysis.md`). Retraining with 41k observed legitimate subdomain hosts cut those false alarms from
93% to 27% but dropped OpenPhish recall from 87% to 65%, so under the pre-registered criteria the baseline was kept
(`reports/exp03/REPORT.md`).

## Setup (Windows PowerShell shown; Python 3.13.7 tested)

```powershell
cd website-risk-analyzer
py -3 -m venv $HOME\.venvs\wra          # kept outside OneDrive on purpose (see docs/DECISIONS.md)
& $HOME\.venvs\wra\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS/Linux: `python3 -m venv ~/.venvs/wra && source ~/.venvs/wra/bin/activate && pip install -r requirements.txt`.

## Run the pipeline (from the repository root)

```bash
python -m ml.data_download     # downloads + validates + safely extracts UCI PhiUSIIL into data/raw/
python -m ml.data_audit        # schema, duplicates, leakage audit -> reports/metrics/data_audit.json
python -m ml.preprocessing     # cleaning + hostname features -> data/processed/dataset.csv
python -m ml.split_dataset     # domain-grouped 70/15/15 split, seed 42 -> data/processed/{train,val,test}.csv
python -m ml.train             # LR, RF, LightGBM, XGBoost; selection by validation PR-AUC (~1 min)
python -m ml.calibrate         # calibration + thresholds on validation only -> models/model_bundle.joblib
python -m ml.evaluate          # ONE final test-set evaluation -> reports/metrics/test_results.*
python -m ml.explain           # SHAP global + local -> reports/figures/shap_*.png
python -m ml.predict https://www.wikipedia.org   # standalone inference with the saved bundle
# phase 2
python -m ml.kaggle_data                 # Kaggle download (public endpoint), audit, overlap with PhiUSIIL
python -m ml.external_data               # OpenPhish + Tranco snapshots -> data/external/external_test.csv
python -m ml.evaluate_external           # unchanged baseline on external + Kaggle data (~3 min, bootstrap)
python -m ml.additional_data_experiment  # EXP-02
# phase 3
python -m ml.subdomain_bias              # root-cause analysis -> reports/subdomain_bias/
python -m ml.subdomain_data              # Tranco ranks 100k-1M legit subdomain hosts -> data/processed/exp03_new_*.csv
python -m ml.exp03_train                 # candidates B, C -> models/experiments/exp03_{B,C}/
python -m ml.exp03_evaluate              # comparison + D29 check -> reports/exp03/
python -m ml.fusion_report               # raw model vs final API (~2 min, offline)
# phase 4
python -m backend.openphish_update       # refresh local OpenPhish snapshot (max every 12 h)
python -m ml.brand_rule_diagnostic       # diagnostic brand-rule counts -> reports/phase4/
python -m backend.serve                  # API on 127.0.0.1:8000 with .env loaded (`uvicorn backend.api:app` also loads it)
# phase 5
cd extension; npm test; cd ..          # 49 mocked extension tests (Node 20+)
# phase 6 (frozen 2026-10-20): see docs/PHASE6_PROTOCOL.md; do not change frozen files
python -m ml.phase6_collect status       # freeze | openphish | tranco | status
pytest -q                                # 175 tests + 3 live tests (skipped unless WRA_LIVE_TESTS=1 and keys are set)
ruff check ml tests backend              # lint
```

Re-running the pipeline reproduces identical splits and metrics (verified; only latency varies).

## Where things are

| What | Path |
| --- | --- |
| Pipeline code | `ml/` (shared extractor: `ml/feature_extraction.py`) |
| Selected model bundle | `models/model_bundle.joblib` (gitignored; regenerate with the commands above) |
| Metrics | `reports/metrics/` |
| Figures | `reports/figures/` |
| Model card | `reports/model_cards/xgb-host-v1.md` |
| Documentation | `docs/` (start with `docs/PROGRESS.md` and `docs/IMPLEMENTATION_STATUS.md`) |
| Log | `logs/implementation.log` |

## Data

UCI PhiUSIIL Phishing URL Dataset, CC BY 4.0 — Prasad & Chandra (2024), *Computers & Security*,
doi:10.1016/j.cose.2023.103545. It is downloaded by `ml.data_download` and never committed. See `docs/DATA_SOURCES.md`.

## Known limitations

- Hostname-only: at the alert threshold the model misses about 45% of test phishing hosts.
- PhiUSIIL artifacts: legitimate rows are https `www.` homepages and rarely have subdomains (2.9% vs 59% of phishing),
  so subdomain features partly encode how the data was collected (`docs/DATA_DICTIONARY.md`).
- Probabilities are calibrated on PhiUSIIL validation data only; real-world calibration is not evaluated.
- External set is small (221 phishing hosts, one snapshot) and uses popularity as a proxy for legitimacy.
- Fusion constants are provisional; URLhaus needs an Auth-Key (untested live).
- `python -m ml.external_data` takes a new OpenPhish snapshot each run, so external results change over time.

## Academic integrity

AI assistance was used; see `docs/AI_USE_DISCLOSURE.md`. Faculty guidance on AI-assisted code is still outstanding.
