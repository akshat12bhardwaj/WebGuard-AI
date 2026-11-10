# WebGuard AI maintainer instructions

Purpose: explain website risk through a local FastAPI backend and Chrome MV3 extension.
Architecture: existing URL hostname ML + URL rules + DOM rules + threat intelligence → hybrid assessment.

**DOM inspection is rule-based only. Do not reintroduce DOM ML unless the project owner explicitly requests it.** No DOM classifier, promotion gates, training tools or model settings belong in active scope.

Start with README.md and docs/{ARCHITECTURE,DEVELOPMENT,TESTING,PROJECT_STATUS}.md. Historical protocols describe earlier revisions, not current product status.

- Entry points: backend/api.py, backend/serve.py; collection: backend/service.py.
- URL inference: ml/predict.py, ml/feature_extraction.py, models/model_bundle.joblib.
- Rules/policy: backend/rules.py, fusion.py, dom_schema.py, dom_rules.py, hybrid.py.
- Browser: extension/background.js, assessor.js, api.js, dom_extractor.js, dom_inspection.js; popup/report/consumer.js present results.
- Tests: tests/, extension/tests/, extension/scripts/*test.mjs. Original URL research: ml/, data/, models/, reports/.

From root: `python -m backend.serve`; `python -m pytest -q`; `npm --prefix extension test`; `python -m ruff check backend ml tests extension/scripts`; `git diff --check`. Existing environment: `$HOME/.venvs/wra`; fresh setup uses requirements.txt. See docs/TESTING.md for Chrome commands. Reload unpacked extension after changes; no npm build required.

Invariants: DOM rules only raise category floors; confirmed reputation retains dangerous precedence. Preserve exact URL thresholds/probabilities and missing-model fallback. Missing inspection/configuration never counts as passed. Automatic checks remain URL-only. Preserve navigation guards, cache separation, notifications, 360 px native popup and reduced-motion animation.

Privacy: never collect input values, passwords, cookies, raw HTML/text or script bodies. Structural destinations contain origins only. Never forward DOM evidence to providers, expose .env values or load untrusted serialized models.

Protect original URL weights/data/splits/reports, Phase 6 protocol/frozen records and docs/baselines archives. Never overwrite evaluations, retrain original weights or bypass frozen hashes. Reproduce historical evaluation in a separate recovered checkout. DOM retirement and recovery manifest: docs/archive/DOM_ML_RETIREMENT.md.

Inspect Git status; preserve unrelated uncommitted work. No automatic commits/pushes/history rewrites. Inspect ownership/references before deletion; archive unique untracked/ignored evidence first. Never delete uncertain data. Keep links current and report honest test results/limitations.
