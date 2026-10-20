# WebGuard AI — Chrome extension (Manifest V3, v0.8.0)

A score-first popup and a detailed report for the phishing risk of the current page's **address**. An optional,
opt-in automatic mode checks every site you visit and shows the result as a toolbar badge plus a short system
notification. The extension never injects anything into web pages, never reads page content and never blocks
navigation. Only the page URL is sent, and only to the local backend.

## Prerequisites

- Google Chrome (tested with Chrome 155).
- The backend on **http://127.0.0.1:8000**; the manifest allows only this origin.
- Node.js only for the extension tests (tested with Node 26).

## 1. Start the backend (with optional reputation keys)

```powershell
cd website-risk-analyzer                                     # the repository root
& $HOME\.venvs\wra\Scripts\Activate.ps1
python -m backend.serve        # loads the repository's .env, then starts the API on 127.0.0.1:8000
```

`python -m backend.serve` reads `.env` from the repository root with the standard library, so no extra package is
needed. Copy `.env.example` to `.env` and fill in only the keys you have.
- Variables already set in the shell win over `.env`.
- Empty values are ignored, so a missing key still shows as "not configured".
- At start-up the launcher prints the *names* it loaded, never the values.

`uvicorn backend.api:app --host 127.0.0.1 --port 8000` loads `.env` the same way (`backend/__init__.py`, only when
served by uvicorn, so tests and the Phase 6 runner never read it). Never put keys in extension files or commit them:
`.env` is gitignored, and `.env.example` lists the variable names only.

| Source | Status without a key | How to get a key | Endpoint used (checked against official docs 2026-10-20) |
| --- | --- | --- | --- |
| URLhaus | `not_configured` ("Not checked — not configured") | Free Auth-Key: register at https://auth.abuse.ch/ | `POST https://urlhaus-api.abuse.ch/v1/url/`, form field `url`, header `Auth-Key` |
| Google Safe Browsing | `not_configured` | Google Cloud project → enable "Safe Browsing API" → create an API key. Non-commercial use only (commercial: Google Web Risk) | v4 Lookup `POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=…`; an empty object means no match |
| PhishTank | works without a key (about 250 requests per 5 min) | optional `PHISHTANK_APP_KEY` | `POST https://checkurl.phishtank.com/checkurl/` |
| OpenPhish | local snapshot, no key | `python -m backend.openphish_update` | none (local file) |

**Status meanings:**
- **Configured:** the key is set. **Checked:** `match`, `no_match` or `unverified` came back.
- **Temporarily unavailable:** `error`, `rate_limited` or `invalid_input`. These are never treated as clean.
- A failed or unconfigured source makes its rule *Unavailable* and lowers confidence. It adds no score penalty.

The clients live in the frozen `backend/threat_intel.py` and were not changed. They already match the current official
request formats, so the only missing piece is the credentials. **No live authenticated request has been made**, because no key exists on this machine.

## 2. Load or reload the extension

1. Open `chrome://extensions` and turn on **Developer mode**.
2. **Load unpacked** → this `extension` folder. After a change, click the reload arrow on the card.
3. Pin WebGuard AI (puzzle-piece menu).

## 3. How it works

**Popup (toolbar icon), 340 px wide, about 410 px tall, no scrolling:**
- The host is on one line. Long hosts shrink to 13 px and are then trimmed from the left, so the registered domain stays visible; the full name is in the tooltip.
- A segmented semicircle gauge. Its bands are the backend's own score bands, computed from the returned model thresholds exactly like `backend/fusion.py`: low 0–36, caution 37–56, high 57–94, dangerous 95. The marker sits on the real risk score.
- The category in its colour, the one-line note, *View detailed report*, and "Assessed just now" or "Saved · 3 min ago".
- *Unknown* shows "–", because the contract's placeholder score of 50 is not a measurement.
- Errors (backend unavailable, timeout, rejected address, unexpected answer) offer *Try again*. Unsupported pages (`chrome://`, the Web Store and similar) say so.
- There is no address input. For development and tests, use `popup.html?url=<address>` (see `scripts/live_chrome_test.mjs`).

**Assessment flow and freshness** (`assessor.js`):
- Results are stored in `chrome.storage.session`. It is memory only, cleared when the browser closes, and needed because an MV3 service worker loses its state after about 30 s idle.
- A result is reused for **10 min**, below the backend's 15-min reputation cache. A failed check is retried after **30 s**. A new URL is always assessed.
- One request per URL at a time. Simultaneous requests from another tab, a redirect or repeated events join it.
- A response updates only tabs that are still on that URL, so a slow old response can't overwrite a newer one.
- Background requests are never delayed. The popup keeps a scan it watched visible for at least 0.7 s, for display only.

**Automatic checks (opt-in switch in the popup footer):**
- Turning the switch on requests the optional permissions `tabs` (to see visited URLs; Chrome warns "Read your browsing history") and `notifications`. Turning it off removes both.
- When it's on, the service worker watches `tabs.onUpdated`. It collapses redirects and rapid changes for 0.5 s, then assesses the URL and sets the toolbar badge to the score ("…" while running, "!" on failure, "?" for unknown) in the category colour.
- **For the active tab only, once per site per tab**, it shows a silent system notification ("Low risk · 17/100", host). The notification closes after 2.5 s, and clicking it opens the report.
- Refreshes, SPA route changes on the same host and cached revisits update the badge silently.
- **Why system notifications instead of an in-page toast:** an in-page toast would need permission to read and change every website, plus script injection into every page. The system notification needs neither and cannot block or alter any page.
- **Privacy:** in automatic mode every visited http(s) address, including its query string, goes to the local backend. The backend forwards it to PhishTank, and to URLhaus and Safe Browsing if keys are set. Private and local hosts are never forwarded.

**Detailed report (`report.html?id=…`)** shows:
- the hero gauge, host, URL, interpretation, backend confidence and decision basis;
- cards for risk score, category, and triggered, passed and unavailable checks, counted from the rule rows;
- **Why this result**, in four groups: model assessment (probability with its zone: below alert, between alert and high, above high), reputation checks (one row per source), rule findings and limitations. Backend notes that only repeat a source status appear once;
- the 17-rule table with Passed, Triggered, Unavailable and Not-evaluated badges and *Evidence* expanders;
- the hostname model card (probability scale and the top-5 SHAP features as returned) and the recommended actions.

## Brand and design system

- **Logo:** `icons/logo.svg` (popup, report) and `icons/icon{16,32,48,128}.png` (toolbar, notifications, extension page).
  - All are generated by `python extension/scripts/make_logo.py` from the supplied artwork `docs/brand/shield_source.png`, which is kept unchanged.
  - The shield silhouette was measured on the source and fitted with Bézier curves (max deviation 1.2 px of 447). The split halves and the 45° long shadow are kept.
  - The red field and the yellow/orange halves are recoloured to navy and teal/cyan, and a thin rim keeps the icon visible on dark toolbars.
- **Tokens:** `theme.css` is the only palette, shared by popup and report: background `#090d14`, surfaces `#141a24` / `#1b2431` / `#222d3b`, teal `#35d6c0` / `#20bfc5`, text `#f4f7fb` / `#a6b4c5`, borders `#2a3746`. The risk colours (low green, caution amber, high orange, dangerous red) are used only for risk indicators and findings.
- **Report layout:**
  - an app bar with the logo, a report tab and a status pill;
  - the host, URL, time, ID and API version;
  - a segmented-gauge hero and five metric cards;
  - **How this result was produced**: five connected stage cards (URL → model → reputation → rules → final), whose statuses come from the response;
  - the rule-by-rule evidence, model evidence, recommended actions and limitations.

## Permissions

| Permission | When | Why |
| --- | --- | --- |
| `activeTab` | always | The current tab's URL, after a toolbar click |
| `storage` | always | `chrome.storage.session` for results (memory only) |
| host `http://127.0.0.1:8000/*` | always | Calls to the local backend; CSP `connect-src` allows only this origin |
| `tabs` (optional) | after opt-in | URLs of visited tabs, for automatic checks |
| `notifications` (optional) | after opt-in | The 2.5 s result notification |

The extension has no `scripting` permission, no content scripts and no site access. The 0.6.0 page overlay was removed.

## Tests

| Test | Command | Result (2026-10-20) |
| --- | --- | --- |
| `tests/*.test.js` (mocked): API client, assessor freshness/pruning, gauge geometry, automatic mode with a fake Chrome API (opt-in, de-duplication, stale responses, notify once per site, 2.5 s dismissal, background tabs, unsupported pages, failures, notification click), report model, permissions, popup readability | `cd extension && npm test` | 48/48 passed |
| `tests/test_extension_contract.py` | `pytest -q tests/test_extension_contract.py` | passed |
| `tests/test_reputation_integration.py` (URLhaus request shape and failures, a listing changes the verdict, unchecked is never clean) | `pytest -q tests/test_reputation_integration.py` | 13 passed |
| `scripts/live_chrome_test.mjs` (live Chrome, real backend plus labelled mocks) | `node scripts/live_chrome_test.mjs "<chrome.exe>" "<abs extension dir>" "<out dir>"` | passed; see the final report |

### Manual checks (cannot be automated: toolbar click, permission prompt, OS notifications)

1. Start the backend (section 1) and reload the extension (section 2).
2. Open `https://www.wikipedia.org/` and click the icon. Expect a brief scan, then about **17, Low risk**, with no scrollbar.
3. Click **View detailed report**: a new tab opens with the same score, and the rules show 15 Passed and 2 Unavailable (no keys).
4. Turn on **Automatic checks** and accept Chrome's prompt.
5. Visit another site. The badge shows "…" and then the score, and a notification appears for about 2.5 s. Reload the page: no new notification.
6. Stop the backend and visit a new site: the badge shows "!", and the popup shows *Backend unavailable* with *Try again*.
7. Without keys, the report shows URLhaus and Safe Browsing as "Not checked — not configured". With keys set, restart the backend and expect "Checked — not listed".
8. Confirm pages look and behave exactly as without the extension.

If notifications don't appear, check Windows Settings → System → Notifications → Google Chrome, and Focus Assist.

## Known limitations

- Rule and feature detail is limited to API v1.0: passed rules have no explanation, and only 5 of 17 features are exposed. The backend is frozen (Phase 6).
- The model over-flags legitimate hosts with a subdomain, and the backend caps them at Caution. Brand-owned infrastructure such as `apple-dns.net` can be High risk.
- URLhaus and Safe Browsing are untested live (no keys).
- In automatic mode, a site's first visit costs one backend call of up to about 5 s (the reputation timeouts); browsing is never blocked.
- Notification appearance is controlled by the operating system.
