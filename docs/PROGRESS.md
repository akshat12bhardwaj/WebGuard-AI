# Progress (resume point)

**Project root:** the repository root
**Venv:** `%USERPROFILE%\.venvs\wra` (Python 3.13.7)
**Production model:** baseline `models/model_bundle.joblib` (SHA-256 `dd5c7677…af479bff`, unchanged). No `models/production.json`.
**Current state:** phase 6 preparation complete — protocol v1.0 final text with runner/platform/query-rule section (D54–D57),
evaluation runner and evaluation-only platform list in the freeze set; **not frozen, no fresh data collected**.
Next: final review, then `python -m ml.phase6_collect freeze`. Production model unchanged.

## Phases 1–2 (2026-10-15, done)

ML pipeline (test PR-AUC 0.736, thresholds 0.3662/0.5671), external validation (subdomain FPR 93.5%), Kaggle rejected
for training (EXP-02), PhishTank/URLhaus clients, rule engine, evidence, provisional fusion, thin FastAPI.
See EXPERIMENT_LOG and IMPLEMENTATION_STATUS.

## Phase 3 milestones (2026-10-16)

| M | Milestone | Status | Key result |
| --- | --- | --- | --- |
| M1 | Inspect Ponytail, baseline, Git | Done | Ponytail = hook-loaded style rules, no commands; baseline values and bundle hash verified; no commits |
| M2 | Bias investigation | Done | train: 92–99.9% phishing when a subdomain exists; removing the subdomain clears 84% of false alarms; PhiUSIIL test legit-subdomain FPR 51% |
| M3 | New legit subdomain data | Done | Tranco Q2Y54 ranks 100k–1M → 57,523 hosts (41,147 / 8,249 / 8,127), integrity-tested |
| M4 | Retraining | Done | B (all new), C (5k); D29 written first |
| M5 | Comparison | Done | B: subdomain FPR 0.271/0.079 but OpenPhish recall 0.652/0.308 |
| M6 | Selection | Done | Neither passes D29 → baseline retained |
| M7 | Safeguard + fusion | Done | Exact-threshold fix (D33); guard variants measured (D35); brand-rule FP finding (D36); 11 controlled scenarios tested |
| M8 | Tests + lint | Done | `pytest -q` 85 passed, 2 skipped (live); ruff clean |
| M9 | Docs + handover | Done | |

## Bugs found and fixed in phase 3

- API vs evaluation mismatch from rounding probabilities/thresholds (D33).
- Threshold rounding crossing isotonic ties for new candidates (D34).
- Public-suffix hosts mis-grouped in new data (D31); shared fix deferred to protect the baseline split.
- Phase 2 bugs: see EXPERIMENT_LOG / DECISIONS.
- Windows: Python's default encoding is cp1252 — always pass `encoding="utf-8"` when editing docs.

## Phase 4 (2026-10-16)

| Item | Status | Evidence |
| --- | --- | --- |
| D35 guard kept at below_high | Done, tested | `test_phase4.py::test_safeguard_policy_d35_default` |
| D36 brand rules | Done: 15 synthetic fixtures; diagnostic: high-severity hits on legit subdomain hosts 154 → 43, apex 7 → 2, OpenPhish 4 → 0 | `reports/phase4/brand_rule_diagnostic.md` |
| PSL-aware `site_domain` | Done, 17 tests; frozen `registered_domain` kept | `ml/feature_extraction.py` |
| Google Safe Browsing v4 | Implemented, mocked tests; **live not verified (no key)** | `backend/threat_intel.py` |
| Local OpenPhish | Implemented, tested with synthetic feeds; **live refresh verified** (300 URLs, commit 018c866) | `backend/openphish_update.py` |
| API contract v1.0 | Documented + contract test; live Uvicorn smoke test passed | `docs/API_CONTRACT.md` |
| Tests / lint | `pytest -q` 135 passed, 3 skipped (live); ruff clean | |

## Phase 5 (2026-10-16)

| Item | Status | Evidence |
| --- | --- | --- |
| Extension (MV3: manifest, popup, api.js client/view model) | Done | `extension/` |
| Mocked tests (5 categories, TI statuses, 422/unreachable/timeout/500/malformed) | 23/23 pass | `cd extension && node --test tests/` |
| Real API response vs JS validator | 4/4 pass | `tests/test_extension_contract.py` |
| Live Chrome 155: loads, talks to backend, low/caution/high render, chrome:// + invalid input + backend down handled, Enter submits | Passed | `reports/phase5/` (results JSON + 6 screenshots) |
| Toolbar-click reading of the current tab (activeTab) | **Manual check pending** (cannot be automated) | `extension/README.md` |
| Bug found live and fixed | Old result stayed visible while a new analysis ran | `extension/popup.js` |
| Python tests / ruff | 139 passed, 3 skipped; clean | |

## Phase 6 setup (2026-10-16)

| Item | Status |
| --- | --- |
| Protocol v1.0 DRAFT (E1–E4, criteria unchanged from the plan, flags F1–F6) | Written; awaiting review |
| Collector `ml/phase6_collect.py` (freeze / openphish / tranco / status; F1 host groups) | Implemented; 7 tests; dry run on the real project refused correctly (not frozen) |
| Bug found by the new tests | `sanitize()` accepted hosts with spaces → now validated with `get_host()` |
| Tests / lint (2026-10-20) | `pytest -q` 156 passed, 3 skipped (live); phase-6 tests 17/17; extension `npm test` 23/23; ruff clean |
| Evaluation runner `ml/phase6_evaluate.py` (E1 a/b, `--full-urls`, E3) | Implemented before the freeze and in the freeze set; 15 tests (fail-closed checks incl. dropped entries and tampered collected files, reproducibility, no URLs in outputs, hash-verified full-URL mode, criteria on unrounded values, model-failure accounting, mocked E3 source failures). Pre-freeze audit fixes 2026-10-20 (D56) |
| Evaluation-only platform list v1 (`ml/phase6_platforms.json`) | Generated from PSL private section + production list; reproducibility test |
| Not tested before collection | E1(b) live PhishTank and E3 (need live network) |
| Fresh collection | **Not started** (by instruction) |

To start after approval: `python -m ml.phase6_collect freeze`, then `python -m ml.phase6_collect openphish` every ≥ 12 h
for 10 days, then `python -m ml.phase6_collect tranco` on a later day.

## Next actions (need the user's decisions first)

1. Get API keys (Safe Browsing, URLhaus) and run `WRA_LIVE_TESTS=1 pytest tests/test_live_ti.py`.
2. Validate the brand rules on a fresh sample (not the external set); consider cited ownership data for names like
   `apple-dns.net` (43 remaining high-severity hits on legitimate infrastructure).
3. Schedule `python -m backend.openphish_update` (≤ every 12 h) before demos.
4. Revisit promotion criteria that rely on PhiUSIIL test (it rewards the shortcut), then re-run EXP-03 B as EXP-04.
5. Do the manual toolbar test (open a page, click the icon, confirm the URL is filled in) and record it.
6. Ask faculty about AI-assisted code before submission.
