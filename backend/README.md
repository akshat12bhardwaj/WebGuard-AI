# Backend (phase 2: thin API, no extension yet)

```bash
uvicorn backend.api:app --host 127.0.0.1 --port 8000      # from the repository root
curl -X POST http://127.0.0.1:8000/api/v1/analyze -H "Content-Type: application/json" -d "{\"url\":\"https://www.wikipedia.org\"}"
```

| File | Role |
| --- | --- |
| `evidence.py` | Dataclasses: `ModelEvidence`, `TIResult`, `RuleFinding`, `Evidence` (JSON via `to_dict`) |
| `threat_intel.py` | PhishTank (no key needed), URLhaus (`URLHAUS_AUTH_KEY`), Google Safe Browsing v4 (`GOOGLE_SAFE_BROWSING_KEY`) and local OpenPhish snapshot lookup; 15-min cache of checked results |
| `openphish_update.py` | Refresh the local OpenPhish snapshot (`python -m backend.openphish_update`, at most every 12 h) |
| `rules.py` | 17 deterministic rules (critical/high/medium/low/info); brand rules per D38 |
| `fusion.py` | PROVISIONAL score: manual Ch. 14 policy + reliability guard for subdomain/IP hosts |
| `service.py` | `Analyzer.collect(url)`: model via `ml.predict` + SHAP, TI in parallel, then rules; private hosts never sent out |
| `api.py` | FastAPI: `GET /api/v1/health`, `POST /api/v1/analyze` → `{assessment, evidence, disclaimer}` |

Feature and inference code is imported from `ml/`, never duplicated. TI statuses: `match`, `no_match`, `unverified`,
`error`, `rate_limited`, `not_configured`, `invalid_input`. Only the first three count as "checked"; `no_match` is never
proof of safety. Response schema: `docs/API_CONTRACT.md` (version 1.0). It differs from the manual's Ch. 16 schema; the extension must follow the contract.
