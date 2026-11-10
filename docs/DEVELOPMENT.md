# Development

Use Python 3.13, Node for tests and Chrome for browser verification. From the repository root in PowerShell:

```powershell
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
python -m backend.serve --host 127.0.0.1 --port 8000
```

No extension build or npm installation is required. The unchanged production `models/model_bundle.joblib` is included; see [provenance](../models/README.md). Without it, rules and reputation still run with explicit model-unavailable evidence. Never load untrusted joblib files.

Open `chrome://extensions`, enable Developer mode and load the repository's `extension` directory unpacked. Reload after browser-source changes; restart the backend after Python changes. If port 8000 is occupied, stop the old server in its owning terminal. `GET http://127.0.0.1:8000/api/v1/health` reports model availability. QA scripts support a separate port; the shipped extension stays on 8000.

## Configuration

`backend.serve` and backend initialization load `.env`; already set environment variables win. `WRA_ENV_FILE` selects a different local file. Never print or commit credentials.

- `PHISHTANK_USERNAME`, `PHISHTANK_APP_KEY`: optional PhishTank credentials.
- `URLHAUS_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_KEY`: optional provider keys.
- `OPENPHISH_STALE_HOURS`, `TI_TIMEOUT_SECONDS`, `TI_CACHE_TTL_SECONDS`: freshness, timeout and cache settings; defaults are in `.env.example`.
- `WRA_LIVE_TESTS=1`: explicitly enable network smoke tests.

There are no DOM model settings, activation pointers or training commands. Obsolete DOM-model environment variables have no effect. `python -m backend.openphish_update` refreshes the local feed with the existing twelve-hour guard and never replaces frozen snapshots.

## Structure and URL research

`backend/` holds API, evidence, rules, reputation and hybrid policy. `extension/` holds the browser product and Node/browser tests. `ml/` holds URL feature extraction/inference and original research. `tests/` holds Python regressions. `docs/` holds current guides and historical research notes. Original source archives, datasets and generated evaluations are retained locally and excluded from publication. The production URL model is included; candidate weights are not.

The original URL workflow is download Ã¢â€ â€™ audit/preprocess Ã¢â€ â€™ grouped split Ã¢â€ â€™ train Ã¢â€ â€™ calibrate Ã¢â€ â€™ evaluate Ã¢â€ â€™ explain. Modules include `ml.data_download`, `ml.data_audit`, `ml.preprocessing`, `ml.split_dataset`, `ml.train`, `ml.calibrate`, `ml.evaluate`, `ml.explain`. Inspect module help and [experiment log](EXPERIMENT_LOG.md) before reproducing in a separate output area with required licensed inputs. Never rerun into historical outputs or original weights. `python -m ml.predict https://www.wikipedia.org` performs local inference only.

The Phase 6 evaluator intentionally rejects this revised checkout as the original frozen system. Recover source into a separate directory using the separately retained local baseline archive, with matching local inputs and dependencies. Never change recorded hashes to bypass its guard.

## Safe modification and troubleshooting

Read root `AGENTS.md`, [architecture](ARCHITECTURE.md) and [testing](TESTING.md). Preserve privacy bounds, URL thresholds, category semantics, navigation safety and model checksums. Changed feature meaning needs a new DOM schema. Preserve native popup width 360 px and content-based height; viewport-width sizing previously caused Chrome popup shrinkage. Render backend strings as text. Consumer screens should not expose diagnostic internals.

Missing keys mean unavailable checks, never benign evidence. Missing model files mean explicit failure, never invented probabilities. Unsupported/permission-denied inspection has explicit URL-only fallback. A fresh checkout needs ignored URL inputs restored for data-dependent tests. Do not commit `.env`, raw datasets, caches or browser profiles.
