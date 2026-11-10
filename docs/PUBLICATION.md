# Publication verification — 2026-11-11

## Scope and Git strategy

Official destination: `https://github.com/akshat12bhardwaj/WebGuard-AI`, branch `main`.
Original remote commit: `34015e6592aeeb46e3aef9923a71df3178f67cf7` (only `.gitattributes`).
Original local branch: `feat/extension-redesign`, commit `6da4c3d61200fba63fbd831301c8d0e4334222c4`, plus substantial uncommitted implementation.

The reviewed working tree is authoritative. Publication uses a new commit whose parent is the original remote main, without merging obsolete implementation. This permits a normal fast-forward push. The previous remote commit is also retained as a local recovery reference. The existing development history and pre-edit backup remain local. Other remote branches are untouched.

Included: current backend, MV3 extension, URL inference/research source, original URL model, deterministic URL/DOM rules, reputation integration, hybrid assessment, monochrome UI, tests, current guides and two genuine product screenshots.
Excluded: `.env`, credentials, raw/processed datasets and feeds, all generated research/browser reports, candidate models, training outputs, recovery archives, browser profiles and retired DOM ML. Excluded local files were not deleted. A byte-identical single-file frozen fusion fixture replaces the parity test's dependency on a private recovery ZIP; no detection behavior changed.

## Verification

Commands run from the repository root with the existing Python 3.13 environment:

| Command | Result |
| --- | --- |
| `python -m pytest -q` | 236 passed, 3 skipped; no failures |
| `npm --prefix extension test` | 82 passed; no failures or skips |
| `python -m ruff check backend ml tests extension/scripts` | Passed |
| `node --check` on every extension `.js` / `.mjs` | All 23 parsed |
| `git diff --check` and `git diff --cached --check` | Passed |

A separate export of exactly the staged publication files, with no local datasets or `.env`, passed **234 Python tests, 5 skipped**, and **82 JavaScript tests**. Two extra skips are data-dependent research integrity tests. The three shared skips are opt-in live-provider smoke tests. The existing Starlette/httpx deprecation warning appeared in both Python runs. Tests used the installed environment; a new dependency installation was not performed.

## Real Chrome

Backend: `python -m backend.serve --host 127.0.0.1 --port 8002`.
Chrome 157.0.8103.50, four suites passed:

```powershell
$chrome = 'C:/Program Files/Google/Chrome/Application/chrome.exe'
node extension/scripts/dom_chrome_test.mjs $chrome extension reports/publication-verification/dom 8002
node extension/scripts/ui_layout_test.mjs $chrome extension reports/publication-verification/ui 8002
node extension/scripts/notify_chrome_test.mjs $chrome extension reports/publication-verification/notify 8002
node extension/scripts/live_chrome_test.mjs $chrome extension reports/publication-verification/live 8002
```

DOM extraction/privacy, native toolbar popup, navigation/recheck/cache, hybrid assessment, notifications, automatic URL-only checks, responsive layouts, reduced motion and browser-error handling passed. The live-flow suite passed 35 scenarios. Layout checks confirmed reports fit one screen at 1920×1080, 1440×900, 1366×768 and 1280×720. Native Windows toast appearance and actual permission-dialog acceptance remain manual checks. Seeded UI scenarios do not establish detector accuracy or provider availability.

## Assets and audit

README screenshots were visually inspected and copied without editing from the DOM suite. [Screenshot provenance](assets/README.md) describes the controlled loopback page. Relative image/document links were checked against the publication tree. A staged-content scan checked known local credential values, common credential/private-key patterns, local user paths, prohibited file types and file sizes. No matching credentials or private user paths were found. The original model SHA-256 is recorded in [model provenance](../models/README.md).
