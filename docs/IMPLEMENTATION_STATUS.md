# Implementation status (updated 2026-10-16, phase 6 setup)

| Area | Status | Evidence |
| --- | --- | --- |
| Phase-1 ML pipeline (download → audit → features → split → train → calibrate → test → SHAP) | **Verified**, unchanged | baseline bundle, metrics and figures untouched |
| Kaggle dataset download, audit, overlap analysis | **Verified** | `ml/kaggle_data.py`, `kaggle_audit.json`, `kaggle_provenance.json` |
| EXP-02 additional-data experiment | **Verified**; Kaggle rejected for training | `exp02_additional_data.*` |
| OpenPhish + Tranco collection and external test set | **Verified** (221 phishing, 6,000 legitimate) | `external_test_provenance.json`, integrity test |
| External evaluation of the unchanged baseline | **Verified** | `external_results.*`, 4 figures |
| PhishTank client | **Verified**: mocked tests + live smoke test (no key) | `backend/threat_intel.py`, `tests/test_threat_intel.py`, `tests/test_live_ti.py` |
| URLhaus client | Implemented; **mocked tests only** — live test blocked (no Auth-Key) | same files |
| Rule engine (14 rules) | **Verified** by unit tests | `backend/rules.py`, `tests/test_rules_fusion.py` |
| Evidence structure + JSON serialisation | **Verified** | `backend/evidence.py` |
| Fusion (manual policy + reliability guard) | Implemented and unit-tested; **provisional, not validated** on labelled data | `backend/fusion.py` |
| Thin FastAPI (`/api/v1/health`, `/api/v1/analyze`) | **Verified**: TestClient tests + live Uvicorn smoke test with real PhishTank | `backend/api.py`, `backend/service.py`, `tests/test_api.py` |
| Subdomain-bias analysis | **Verified** | `reports/subdomain_bias_analysis.md` |
| EXP-03 retraining (B, C) + comparison | **Verified**; baseline retained (D32) | `reports/exp03/REPORT.md` |
| Fusion: exact threshold comparison, level-based categories, guard option | **Verified** by 11 controlled scenarios + regression tests; constants still provisional | `backend/fusion.py`, `tests/test_phase3.py` |
| Raw model vs final API measurement (offline, no TI) | **Verified** | `reports/exp03/fusion_report.md` |
| Brand rules (D38) | **Verified** by synthetic fixtures; diagnostic on the external set only | `tests/test_phase4.py`, `reports/phase4/` |
| PSL-aware `site_domain` (D39) | **Verified** by tests | `ml/feature_extraction.py` |
| Google Safe Browsing v4 client | Implemented; **mocked tests only** — live blocked (no key) | `backend/threat_intel.py` |
| Local OpenPhish lookup + refresh | **Verified**: tests with synthetic feeds; live refresh and live API match | `backend/threat_intel.py`, `backend/openphish_update.py` |
| API contract v1.0 | **Verified**: contract test + live Uvicorn smoke test | `docs/API_CONTRACT.md` |
| Phase 6 protocol + fresh-data collector | Implemented and unit-tested; flags decided; **not frozen, not started** | `docs/PHASE6_PROTOCOL.md` (v1.0 final text), `ml/phase6_collect.py`, `tests/test_phase6.py` |
| Phase 6 evaluation runner + evaluation-only platform list | Implemented and unit-tested on synthetic data; in the freeze set; E1(b) and E3 not exercised (live network) | `ml/phase6_evaluate.py`, `ml/phase6_platforms.{py,json}`, `tests/test_phase6_evaluate.py` |
| Tests / lint | **Verified**: `pytest -q` 156 passed, 3 skipped (live tests; with WRA_LIVE_TESTS=1 PhishTank passes, URLhaus and Safe Browsing skip — no keys); `ruff check ml tests backend` clean | |
| LLM explanation agent | Not started (optional) | manual Ch. 15 |
| Chrome extension (MV3) | **Verified**: 23 mocked Node tests; live headless Chrome 155 test against the running backend (load, analyze, low/caution/high, errors, backend down, keyboard) | `extension/`, `reports/phase5/` |
| Extension: reading the active tab via toolbar click | **Not verified automatically** (activeTab needs a real click); manual check documented | `extension/README.md` |
| Extension: `dangerous` / `unknown` rendering | Verified with mocked responses only (no real phishing URL used in the browser) | `extension/tests/api.test.js` |
| Git | Local repo, nothing committed or published | |

## Remaining limitations

- **Subdomain bias (critical, unresolved):** the production model flags 86–93% of legitimate subdomain hosts; the API shows
  them as 'caution' with low confidence. Retraining (EXP-03 B) removes most false alarms but costs ~22 points of
  phishing recall at alert, so it was not promoted. Hostname features alone cannot separate legitimate and phishing
  subdomains well.
- Brand rules: 43 legitimate infrastructure hosts whose registered name contains a brand (e.g. `apple-dns.net`) still get
  'high'; 4 OpenPhish hosts moved from high to medium. Diagnostic numbers only.
- Live Safe Browsing and URLhaus are unverified (no keys).
- Only 221 external phishing hosts (one OpenPhish snapshot); recall CI ±4.3 points.
- Tranco popularity is a proxy for legitimacy, not ground truth.
- Fusion constants (95, rule floors, cap) are design choices, not validated values.
- URLhaus untested live; PhishTank without an app key is limited to ~250 requests / 5 min.
- Recall on the PhiUSIIL test split is limited (55% at alert).
- Faculty guidance on AI-assisted code: **outstanding**.
