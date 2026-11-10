# Screenshot provenance

Captured on 2026-11-11 using the current extension and local FastAPI backend, with `extension/scripts/dom_chrome_test.mjs` in Chrome 157.0.8103.50.

- `extension-popup.png`: unaltered `native_popup.png`, the actual 360 px native Chrome extension popup.
- `security-report.png`: unaltered `report_dom_desktop.png`, full report at 1280 × 900.

Both show the same controlled loopback `/insecure` page. The suite creates a synthetic insecure password form and invokes the real extractor and backend. The high-risk score of 57 is the actual assessment, not a seeded category override. The suite verifies the insecure-form finding. Reputation is unavailable for this private host by design. No personal browser chrome, credentials, raw research URLs or profile identifiers appear.

These images demonstrate product behavior, not detection accuracy on a public website. Other suite screenshots include seeded presentation fixtures and are deliberately excluded.
