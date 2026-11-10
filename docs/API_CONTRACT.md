# API contract — version 1.0 (2026-10-16)

Server: `uvicorn backend.api:app --host 127.0.0.1 --port 8000` (local only). CORS allows `chrome-extension://<32 a–p chars>`
origins for GET and POST. Verified by `tests/test_phase4.py::test_api_contract` and `tests/test_api.py`.
Any breaking change must bump `api_version`.

## `GET /api/v1/health`

`{"status": "ok", "model_loaded": bool, "api_version": "1.0"}`

## `POST /api/v1/analyze`

Request: `{"url": string}`, 1–2048 characters. A missing scheme is treated as `http://`.

### 200 response

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | string | `"1.0"` |
| `assessment.category` | string | `dangerous` (confirmed TI listing) · `high_risk` · `caution` · `low_risk` · `unknown`. There is **no "safe" category** |
| `assessment.risk_score` | int 0–95 | Inside the category band: low 0–36, caution 37–56, high 57–94, dangerous 95; `unknown` = 50 |
| `assessment.safety_score` | int or null | `100 − risk_score`; null when `unknown` (show "–") |
| `assessment.confidence` | string | `high` · `medium` · `low`. Low when no TI source was checked, the model is unavailable or out of range, or a model caveat applies (subdomain or IP host) |
| `assessment.decision_basis` | string | What set the category: threat intelligence, rule engine, or ML model |
| `assessment.notes` | list[string] | e.g. `"URLhaus not checked: not_configured"`, model-caveat notes |
| `evidence.url`, `.host` | string | Normalised URL; host without `www.` (IDN as punycode) |
| `evidence.registered_domain` | string | PSL-aware (`site_domain`): eTLD+1, or the host itself for IPs, public-suffix hosts and unknown suffixes |
| `evidence.collected_at` | string | ISO-8601 UTC |
| `evidence.model.available` | bool | |
| `evidence.model.probability` | float or null | Raw calibrated P(phishing host), unrounded — **not** the risk score |
| `evidence.model.calibration`, `.model_version` | string or null | `isotonic`, `host-v1` |
| `evidence.model.thresholds` | object | `alert`, `high`, `rule` |
| `evidence.model.out_of_training_range` | list[string] | Features outside the training range |
| `evidence.model.top_shap` | list[{feature, value, shap_log_odds}] | Five strongest contributions (log-odds of the raw model) |
| `evidence.model.error` | string | Empty unless the model failed |
| `evidence.threat_intel[]` | list | One entry per source: `source`, `status`, `detail`, `checked_at`, `cached`, `reference` |
| `evidence.rules[]` | list | Every rule: `rule_id`, `status` (`fired` / `not_fired` / `not_evaluated`), `severity` (`critical` … `info`), `title`, `explanation` |
| `evidence.errors` | list[string] | e.g. model unavailable |
| `disclaimer` | string | Must be shown to the user |

**Threat-intelligence statuses:**
- `match` — confirmed listing.
- `no_match` — checked and not listed. **This is not proof of safety.**
- `unverified` — reported but not confirmed: a PhishTank unverified entry, an OpenPhish host listed only with a different URL, or a listing in a stale snapshot.
- `error`, `rate_limited`, `not_configured`, `invalid_input` — the source was **not checked**.

Sources: `PhishTank` (live, no key needed), `URLhaus` (live, needs a key), `Google Safe Browsing` (live, needs a key),
`OpenPhish (local snapshot)` (local file, no network call; the detail gives the snapshot time and age).
Private and local hosts are never sent to third parties: every source then reports `not_configured`, "skipped".

### Errors

| Code | When | Body |
| --- | --- | --- |
| 422 | Missing or empty `url`, more than 2048 characters, unsupported scheme (`javascript:`, `ftp:` …), no host, bad port | `{"detail": ...}` (string or a FastAPI validation list) |
| 500 | Unexpected server error (not expected; a model failure instead returns 200 with `model.available = false`) | FastAPI default |

### Example (abridged; offline, TI not configured)

```json
{"api_version": "1.0",
 "assessment": {"risk_score": 56, "safety_score": 44, "category": "caution", "confidence": "low",
                "decision_basis": "ML model (hostname features)",
                "notes": ["URLhaus not checked: not_configured", "Model unreliable here (host has a subdomain; ...)"]},
 "evidence": {"url": "https://docs.python.org/3/", "host": "docs.python.org", "registered_domain": "python.org",
              "model": {"available": true, "probability": 0.98, "...": "..."},
              "threat_intel": [{"source": "PhishTank", "status": "no_match", "...": "..."}], "rules": ["..."], "errors": []},
 "disclaimer": "Automated assessment ... not proof that a site is safe."}
```


## Additive DOM extension — `dom-v1`, hybrid policy `url-dom-r2` (2026-11-10)

API v1.0 clients remain compatible. `POST /api/v1/analyze` still accepts `{url}` and produces the established URL-only response. An optional `dom` object adds bounded structural evidence. No DOM field is required for URL-only assessments; the existing hostname classifier, probability and threat-intelligence semantics remain unchanged.

`dom` contains `schema_version`, `state`, optional `page_origin`, optional `features`, and optional enumerated failure `reason`. States are `inspected`, `partial`, `unavailable`, `not_requested`, `failed`, `incompatible`. The exact bounded schema is `backend/dom_schema.py`; client definitions/extraction are in `extension/dom_extractor.js` and `dom_inspection.js`. See [DOM schema](DOM_FEATURE_SCHEMA.md) for definitions, limits and privacy constraints.

Inspected/partial states require features and a query-free page origin. The origin must match the assessed URL's scheme, hostname and effective port; a mismatch is unavailable. Truncation and inaccessible iframe coverage become partial. An unsupported schema version never contributes risk and is returned as incompatible. Malformed types, unknown fields, excessive arrays or counters, inconsistent counts, and query/userinfo/path-bearing destination origins receive 422. Request bodies larger than 64 KiB receive 413 before JSON parsing, including chunked input.

When `dom` is submitted, the response includes `assessment_version: "url-dom-r2"` and `evidence.dom` with `schema_version`, `state`, separate `rules`, aggregate `summary`, and `features` only for inspected/partial snapshots. DOM inspection is rule-based only. The retired experimental `evidence.dom.model` diagnostics are removed; consumers must not require that field. URL-only `evidence.model` is unchanged. Unavailable snapshots contain no fabricated benign features.

Fusion is monotonic. Confirmed threat-intelligence dangerous/95 results retain precedence. Password forms configured to submit over HTTP (except method=dialog) may raise the assessment to high risk, using the current integer high-band floor. A rapid cross-site refresh with visible password entry, or the documented contextual combination of external credential destination, hidden password entry and rapid cross-site refresh, may raise it to caution. External HTTPS authentication, hidden fields, external scripts/iframes and link ratios alone do not raise risk. DOM findings never lower URL risk or alter model probability; insufficient model evidence plus no meaningful DOM/rule warning remains unknown. Risk raised by DOM uses low confidence and an explicit note.

DOM origins/counters are processed only in the local backend. `Analyzer.collect` receives only the original URL, so DOM features are not forwarded to threat-intelligence providers. Full input values, arbitrary text, HTML, script source, cookies and DOM resource query strings are outside the schema.
