# Data sources

All raw files live under `data/raw/` (gitignored, never re-hosted). Machine-readable provenance:
`reports/metrics/download_provenance.json`, `kaggle_provenance.json`, `external_test_provenance.json`.

## 1. Primary training data — UCI PhiUSIIL Phishing URL Dataset

| Field | Value |
| --- | --- |
| Official page | https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset |
| Download URL used | https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip |
| Downloaded | 2026-10-15 02:36 UTC by `python -m ml.data_download` |
| Archive | `data/raw/phiusiil.zip`, 15,376,007 bytes, SHA-256 `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a` |
| CSV | `data/raw/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv`, 56,854,345 bytes, SHA-256 `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` |
| Version / licence | No version number; donated 2024-03-03; CC BY 4.0 (UCI page, checked 2026-10-14) |
| Citation | A. Prasad, S. Chandra, *Computers & Security*, 2024, doi:10.1016/j.cose.2023.103545 |

Limitations: static snapshot; legitimate rows are only https `www.` homepages of established sites (hence the subdomain bias, see
`EXPERIMENT_LOG.md`); never visit its URLs.

## 2. Kaggle Malicious URLs dataset — external evaluation only (D16, D17)

| Field | Value |
| --- | --- |
| Page | https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset |
| Download | `https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset` (public, no login needed on 2026-10-15) |
| Metadata (Kaggle API) | creator Manu Siddhartha; licence **CC0: Public Domain**; version 1; last updated 2021-07-23 |
| Downloaded | 2026-10-15 03:54 UTC (first with curl, then validated by `python -m ml.kaggle_data`) |
| Archive | `data/raw/kaggle_malicious_urls/malicious_urls_dataset.zip`, 17,748,901 bytes, SHA-256 `8d085ce1fb4e462111e233a6a302970f699264ae129e3f6e5ac0496f5b69ca79` |
| CSV | `malicious_phish.csv`, 45,664,439 bytes, SHA-256 `d83ce942075dd63ed4d11560cfdcd9d512caa3d680e292f22cab484e8f074d01` |
| Schema | `url`, `type`; 651,191 rows: benign 428,103, defacement 96,457, phishing 94,111, malware 32,520 |
| Sources (dataset description) | ISCX-URL-2016, malwaredomains blocklist, faizan-ahmad GitHub data, PhishTank, PhishStorm; no timestamps in the file |
| Label mapping | phishing → 1, benign → 0; defacement and malware excluded (different threats) |

Limitations (measured, `reports/metrics/kaggle_audit.json`): labels are per URL, so popular hosts carry both labels
(4,045 hosts, 98,073 rows dropped, e.g. `en.wikipedia.org`, `youtube.com`); 1,069 hosts disagree with PhiUSIIL labels;
scheme present on 8% of benign vs 26% of phishing URLs (format artifact, ignored by hostname features); 2016–2021 era.

## 3. External test sources (D18, D19) — collected 2026-10-15

| Source | Snapshot | Local file | SHA-256 |
| --- | --- | --- | --- |
| OpenPhish Community feed (`https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`, linked from openphish.com/phishing_feeds.html) | GitHub commit `d9c06b3b03dbde41293b4643d290a6dfef83267d` (2026-10-15 00:00:09 UTC); fetched 03:58:38 UTC; 300 URLs | `data/raw/openphish/feed_20261015T035838Z.txt` | `3ae958e9…29305f4` |
| Tranco, registered domains | list **N26XW**, created 2026-10-14 22:00 UTC (30 days to 2026-10-14) | `data/raw/tranco/N26XW.csv` | `2ad19269…b3a484a` |
| Tranco, with subdomains (`?subdomains=true`) | list **Q2Y54**, created 2026-10-14 22:00 UTC | `data/raw/tranco/Q2Y54.csv` | `2c8720e6…1d628a2f` |

Terms: OpenPhish allows academic/personal research, forbids commercial use and redistribution → snapshot kept local only.
Tranco is free; its source rankings have their own licences (cite Tranco, Le Pochat et al., NDSS 2019).
Label assumptions: an OpenPhish entry was phishing when listed (it may be offline now); a popular Tranco host is *probably*
legitimate, but popular sites can host abuse — so shared-hosting hosts and domains that also appear in OpenPhish were removed.

## 4. Threat-intelligence APIs (evidence only — never features or labels)

| Source | Endpoint (checked 2026-10-15) | Access | Status in this project |
| --- | --- | --- | --- |
| PhishTank `checkurl` | `https://checkurl.phishtank.com/checkurl/` POST `url`, `format=json`, optional `app_key`; documented `http://` now 301-redirects to https | No key required; observed limit 250 requests / 300 s (`X-Request-Limit*` headers); HTTP 509 when over; descriptive User-Agent `phishtank/<username>` required; new account registration disabled | **Implemented, mocked tests + 1 live smoke test passed** |
| URLhaus | `https://urlhaus-api.abuse.ch/v1/url/` POST `url`, header `Auth-Key`; `query_status` ok / no_results / invalid_url / http_post_expected | Free Auth-Key from auth.abuse.ch; without it the API returns HTTP 401 `{"error": "Unauthorized"}`; malware URLs only (not phishing) | **Implemented, mocked tests only** (no key available) |
| Google Safe Browsing | (manual Ch. 8, 16) | Free key, non-commercial | Not implemented in this phase |

## 5. EXP-03 legitimate subdomain hosts (phase 3)

Derived from the already-downloaded Tranco list Q2Y54 (`data/raw/tranco/Q2Y54.csv`, SHA-256 `2c8720e6…1d628a2f`, created
2026-10-14 22:00 UTC), ranks 100,001–1,000,000; no new download, no generated hostnames. Label policy: legitimate (0) by
popularity assumption after the D27/D31 exclusions; not verified site by site. Output:
`data/processed/exp03_new_{train,val,test}.csv` (41,147 / 8,249 / 8,127 hosts). Exclusion counts and checksums:
`reports/exp03/data_provenance.json`. Limitation: the list mixes user-visited sites with DNS-observed infrastructure
hosts (CDN, telemetry).

## 6. Phase 4 additions (2026-10-16)

| Source | Use | Access / terms | Verification status |
| --- | --- | --- | --- |
| Google Safe Browsing Lookup API v4 (`https://safebrowsing.googleapis.com/v4/threatMatches:find`, docs checked 2026-10-16) | Live lookup; the URL is sent to Google | Free API key, non-commercial use only | **Mocked tests only**; live test skipped (no key) |
| OpenPhish Community feed, local snapshots | Offline lookup (`OpenPhish (local snapshot)`) | Research/personal use, no redistribution → `data/feeds/openphish/` is gitignored; tests use synthetic feeds only | **Live refresh verified**: `feed_20261016T031604Z.txt`, 300 URLs, GitHub commit 018c866, provenance in the sidecar `.json` |
| Microsoft 365 URLs and IP address ranges (learn.microsoft.com, page dated 2026-08-14) | Source for brand-owned Microsoft domains in `rules.OFFICIAL_DOMAINS` | Public documentation | Checked 2026-10-16 |

## 7. Phase 6 fresh held-out collection (prepared, not started)

`python -m ml.phase6_collect` (protocol: `docs/PHASE6_PROTOCOL.md`). Writes `data/fresh/` (gitignored) and
`data/fresh/manifest.jsonl`. Per OpenPhish snapshot it records the UTC time, feed URL, GitHub commit, raw SHA-256, raw /
stored / invalid counts, the number of query strings or fragments dropped, and the stored file's SHA-256. Per Tranco
list it records the list ID, creation time, download URL and file SHA-256. OpenPhish data is never redistributed.

**Evaluation-only platform list v1** (`ml/phase6_platforms.json`, D55): PSL PRIVATE section from tldextract 5.4.0's bundled
snapshot (SHA-256 `b69315c085d53972724b8f2df111ffc329b0c84fe0a47d62c8c91655cc774a38`, MPL-2.0) plus the production
shared-hosting list; 2,883 suffixes; used only to classify the Phase 6 supplementary group.
**Full-URL re-fetch** (D56): `https://raw.githubusercontent.com/openphish/public_feed/<commit>/feed.txt`, verified against the
recorded raw SHA-256, held in memory only.
