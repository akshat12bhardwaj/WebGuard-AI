# Testing

Run from the repository root with the configured Python environment:

```powershell
python -m pytest -q
npm --prefix extension test
python -m ruff check backend ml tests extension/scripts
Get-ChildItem extension -Recurse -File | Where-Object { $_.Extension -in '.js','.mjs' } | ForEach-Object { node --check $_.FullName; if ($LASTEXITCODE) { throw "Syntax check failed: $($_.FullName)" } }
git diff --check
```

Python covers URL model/feature pipelines, rules, reputation/cache mocks, hybrid floors, API/body validation, missing-model fallback and frozen-source parity. `tests/test_dom.py` covers benign/HTTP/external login, hidden fields, refresh, privacy/schema bounds, partial/unavailable inspection, listing precedence and the rule-only response/startup contract. Data-integrity tests need retained ignored URL inputs and weights. The three default skipped live-provider tests are opt-in: `WRA_LIVE_TESTS=1`, plus keys for URLhaus/Safe Browsing. Never label mocked results as live verification.

Node tests cover response validation, consumer wording, worker/cache/navigation, DOM requests, reports/gauges and notifications. No extension runtime npm packages are required.

## Real Chrome

In a separate terminal start:

```powershell
python -m backend.serve --host 127.0.0.1 --port 8002
```

Then run from the repository root:

```powershell
$chrome = 'C:/Program Files/Google/Chrome/Application/chrome.exe'
node extension/scripts/dom_chrome_test.mjs $chrome "$PWD/extension" "$PWD/reports/cleanup-verification/dom" 8002
node extension/scripts/ui_layout_test.mjs $chrome "$PWD/extension" "$PWD/reports/cleanup-verification/ui" 8002
node extension/scripts/notify_chrome_test.mjs $chrome "$PWD/extension" "$PWD/reports/cleanup-verification/notify" 8002
node extension/scripts/live_chrome_test.mjs $chrome "$PWD/extension" "$PWD/reports/cleanup-verification/live" 8002
```

Stop the QA backend with Ctrl+C afterwards. Scripts use isolated temporary Chrome/extension copies. New outputs above must not replace historical evaluation records.

- DOM suite: controlled loopback extraction/privacy fixtures, actual toolbar grant, permission fallback, navigation/cache/recheck, API hybrid warnings, native popup dimensions/desktop scales, reports and animation lifecycle.
- Layout suite: popup states at 1×/1.5× DPR and reports at 320–1440 px; overflow, clipping, overlap, small type, targets and console errors.
- Notification suite: URL-only automatic checks, permission ownership, deduplication, dismissal, background/unsupported tabs and absence of scripting calls. Optional permissions are pre-granted in its temporary manifest.
- Live suite: URL/report flow, low/caution/high, input errors, stale/offline cache, reduced motion and controlled dangerous/unknown UI fixtures.

No archived phishing HTML is opened and no real credentials are submitted. Seeded warnings test presentation, not detector accuracy. Headless suites cannot inspect native Windows toast appearance or exercise the actual optional-permission accept/decline dialog. Latest measured results are in [project status](PROJECT_STATUS.md).
