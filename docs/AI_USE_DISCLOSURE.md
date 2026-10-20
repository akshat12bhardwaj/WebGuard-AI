# AI-use disclosure

- **Tool:** Claude (Anthropic), model Claude Opus 5.5, used through Claude Code in VS Code, 2026-10-14 and 2026-10-15.
  The Ponytail 5.2.0 Claude Code plugin (coding-style rules) was installed.
- **What the AI did:** researched datasets, APIs and literature for the implementation manual; wrote the manual; wrote
  all code in `ml/` and `tests/`; ran the pipeline, tests and lint; fixed the errors it found; wrote the files in `docs/`
  and the README.
- **Phase 2 (2026-10-15):** the AI also identified and audited the Kaggle dataset, collected OpenPhish/Tranco
  snapshots, ran the external evaluation and EXP-02, wrote the PhishTank/URLhaus clients, rule engine, evidence and
  fusion modules and the thin FastAPI app, made one live PhishTank call set, and found/fixed three bugs.
- **Phase 3 (2026-10-16):** the AI analysed the subdomain bias, built the EXP-03 dataset, trained and compared two
  candidates under criteria it wrote before the results, fixed three bugs (threshold rounding, API/evaluation mismatch,
  public-suffix grouping) and updated the fusion logic and documentation.
- **Phase 4 (2026-10-16):** the AI rewrote the brand rules, added the PSL-aware `site_domain`, the Google Safe Browsing
  and local OpenPhish clients, the feed-refresh script, the API contract and tests; it made live PhishTank/OpenPhish calls.
- **Phase 5 (2026-10-16):** the AI built the Chrome extension and its tests, and ran a headless Chrome test that loaded it
  against the local backend.
- **What the student must do before submission:** read and understand every file; be able to explain each design
  decision in the viva; edit or rewrite parts as required by the course; record personal changes below.
- **Verification performed:** every reported number comes from scripts run on 2026-10-15 (`reports/metrics/`);
  139 Python and 23 JavaScript tests passed (phase 5); the full pipeline was re-run and reproduced identical splits and metrics.
- **Course policy:** the handout states that AI-generated code is treated under the Unfair Means policy.
  **Faculty approval has not been obtained.** Ask the course faculty in writing before submitting this work.
- **Student changes:** _to be filled in by the student_.
