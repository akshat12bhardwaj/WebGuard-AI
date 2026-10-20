# Phase 6 evaluation protocol — v1.0 (2026-10-16)

**Status: FINAL TEXT, NOT YET FROZEN.** Flags F1–F6 were decided by the user on 2026-10-16 (section 9). The protocol is frozen when
`python -m ml.phase6_collect freeze` records the SHA-256 of this file and of the production system in
`reports/phase6/frozen_system.json`. The collector refuses to run before that, and stops if this file or the system
changes afterwards. Any later change needs a new version number and a written reason here; criteria are never changed
after fresh data has been seen.

Source: the Phase 6 evaluation plan given in the session of 2026-10-16. It existed only in the terminal and is recorded
here. The acceptance criteria in section 6 are copied from it without change.

## 1. Frozen system under test

| Item | Value |
| --- | --- |
| Model bundle | `models/model_bundle.joblib`, SHA-256 `dd5c76779d4598e369784d9e5bb5e8963fd7322cb0f6c017395bf608af479bff` (XGBoost + isotonic, thresholds alert 0.3662 / high 0.5671) |
| Code and data recorded at freeze (fail closed if any entry is missing or differs) | `ml/{feature_extraction,predict,utils,external_data,kaggle_data}.py`, `backend/{rules,fusion,service,threat_intel,evidence,api}.py`, the collector `ml/phase6_collect.py`, **the evaluation runner `ml/phase6_evaluate.py`**, the evaluation-only platform list `ml/phase6_platforms.{py,json}`, the prior sets and pre-freeze OpenPhish snapshots that define the exclusions and F1 groups (section 5), tldextract's bundled Public Suffix List snapshot, the installed versions of Python, xgboost, scikit-learn, numpy, pandas, scipy, shap, joblib and tldextract, and this protocol. An entry recorded at freeze but no longer checked also fails |
| Prohibited after freeze | Any change to the model, thresholds, rules, fusion constants, guard, features or parsing used by E1–E4 |

## 2. Data roles

| Role | Sets | Use in the Phase 6 report |
| --- | --- | --- |
| Development | PhiUSIIL train/val, EXP-03 new_train/new_val | Never used for Phase 6 claims |
| Held-out (earlier) | PhiUSIIL test (phase-1 numbers) | Reported as-is; reused read-only for comparisons |
| Diagnostic | External OpenPhish/Tranco set (2026-10-15), Kaggle unseen domains, EXP-03 new_test, phase-4 brand diagnostic | Labelled "diagnostic" wherever shown |
| **Fresh held-out** | OpenPhish snapshots and a Tranco list collected **after the freeze** by `ml.phase6_collect` | The only basis for E1/E4 claims |

## 3. Experiments

**E1. Frozen-system evaluation on fresh data.**
- *Question:* does the frozen system detect phishing published after development, and how often does it raise false alarms on legitimate sites with and without subdomains?
- *Configurations:* (a) model + rules, with no threat-intelligence lookups (**primary**); (b) model + rules + live PhishTank (secondary).
- *Excluded configuration:* the local OpenPhish lookup is off in every configuration, because the positives come from OpenPhish and would match themselves.

**E2. Live Safe Browsing and URLhaus.** **Deferred (F4): reported as "not run" until credentials exist.**
- *Question:* do the clients map real responses correctly?
- *Status:* a functional check only, not a coverage estimate. It needs `GOOGLE_SAFE_BROWSING_KEY` and `URLHAUS_AUTH_KEY`.
- *Test inputs:* test URLs are submitted only to the lookup APIs and never opened in a browser.

**E3. End-to-end latency.**
- *Question:* what does the user wait in practice?
- *Data:* 200 legitimate URLs drawn from the fresh Tranco apex sample, looked up only.
- *Measurements:* p50 and p95 with no sources, and with all *available* sources. The report lists exactly which sources were enabled (F5); currently PhishTank and the local OpenPhish snapshot.
- *Recording:* note the machine and the time of day.

**E4. Brand rule on independent data.**
- *Question:* how often does the high-severity `BRAND_IN_HOST_MISMATCH` rule fire on legitimate and phishing hosts that were not used in its design?
- *Data:* the same fresh sets as E1.

## 4. Collection rules (`ml/phase6_collect.py`)

**OpenPhish**
- *Source:* the OpenPhish Community feed, `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`.
- *Cadence:* at most one snapshot per 12 h (the feed's update interval). A snapshot whose GitHub commit was already collected is skipped.
- *Recorded per snapshot:* UTC time, commit SHA, SHA-256 of the raw bytes, URL counts, and how many query strings were dropped.

**Stored form (privacy)**
- Each URL is reduced to `scheme://host/path`, dropping the query and fragment. Phishing query strings often carry victims' e-mail addresses or tokens.
- The raw feed text is **not** stored, only its hash.
- E1 and E4 score this stored form for every item, both classes.

**Window**
- 10 days from the first fresh snapshot (flag F2), at most 20 snapshots.
- Collection stops at the end of the window whatever the count.

**Tranco**
- *Which list:* the first list (standard and `subdomains=true`) created after the OpenPhish window ends. It may not be N26XW, Q2Y54 or any earlier list.
- *Storage:* the raw CSV is kept locally (gitignored), with its list ID, creation time and SHA-256.

**No overwriting:** files are created with exclusive-create mode, and existing files are never replaced.

**Licensing:** OpenPhish allows research/personal use and forbids redistribution, so `data/fresh/` is gitignored and never published. Tranco: cite Le Pochat et al. (NDSS 2019); the underlying rankings have their own licences.

## 5. Units, deduplication and exclusions

- **Unique host:** `ml.feature_extraction.get_host()`: lower case, `www.` stripped, IDNs converted to punycode, no trailing dot. A host seen in several snapshots counts once, at its first sighting.
- **Registered domain for exclusions:** the frozen `registered_domain()`. All earlier exclusion sets were built with it.
- **Prior registered domains (excluded from both classes):** PhiUSIIL (all splits), Kaggle binary hosts, the external set of 2026-10-15, EXP-03 new_{train,val,test}, and both OpenPhish snapshots used before the freeze.
- **Legitimate negatives:**
  - *Also excluded:* shared-hosting suffixes (as in D19/D27), IP hosts, hosts that are themselves public suffixes, and registered domains of any fresh OpenPhish positive.
  - *Apex sample:* 2,000 random hosts (seed 42) from the standard list, ranks ≤ 100,000.
  - *Subdomain sample:* 2,000 random hosts with a subdomain from the subdomain list, all ranks, at most 3 per registered domain (flag F3).
- **Hosts in both classes:** dropped as ambiguous.
- **Phishing host groups (F1):**
  - Every fresh host is first checked against all **prior hosts**: the hosts of the prior sets and of the pre-freeze snapshots. A host seen before is never used.
  - **Primary group:** new hosts whose registered domain is not a prior registered domain. All E1/E4 criteria apply here only.
  - **Supplementary group:** new hosts whose registered domain *is* prior **and** whose host is under a suffix on the **evaluation-only platform list v1** (`ml/phase6_platforms.json`; section 10). It is reported separately with the same metrics and intervals, and **no acceptance criterion**.
  - **Excluded, other:** new hosts on prior registered domains that are not under a listed platform suffix (compromised sites, or platforms on neither source list). Treated as *unknown*, never as confirmed shared hosting; counted and reported, not scored.
  - **Disclosed limitation:** the primary group under-represents phishing on shared platforms, the harder case for this model, so E1-a describes attacker-registered domains only.

## 6. Metrics, intervals and acceptance criteria (unchanged from the plan)

**Definitions** (these clarify the plan; no number is changed). Following F6, raw model-probability metrics and final
API outcomes are reported in separate tables:
- *Recall@t:* the share of fresh phishing hosts with **raw calibrated model probability** ≥ t.
- *FPR@t:* the same share on legitimate hosts.
- *Final category:* the `fuse()` output in configuration E1(a).
- *"Final high risk":* category `high_risk` or `dangerous`.
- *Intervals:* 95% percentile bootstrap with 2,000 resamples and seed 42, resampling within each class (`ci()` in `ml/phase6_evaluate.py`).
- *Domain-weighted rates:* point estimates only, with no interval.

| ID | Claim allowed only if | Notes |
| --- | --- | --- |
| E1-a | "Detection generalises to later phishing": recall@alert ≥ 0.75 **and** lower 95% bound ≥ 0.70, on **≥ 500** fresh phishing hosts | With fewer than 500 hosts the claim is not made; numbers are still reported |
| E1-b | Apex FPR@high ≤ 0.06 (point estimate; interval reported) | |
| E1-c | Final "high risk" on legitimate hosts (apex + subdomain together) ≤ 2% | |
| E1-d | Subdomain "caution or worse" rate is always reported; no pass bar | Disclosed limitation |
| E2 | Safe Browsing: test URL → `match`, benign → `no_match`, invalid key → `error` (never `no_match`). URLhaus: listed URL → `match`, benign → `no_match`, bad key → `error` | **Deferred (F4): not run until both keys exist** |
| E3 | p95 ≤ 10 ms model-only; p95 ≤ 6 s with all available sources | F5: enabled sources listed |
| E4 | High-severity brand rule on legitimate hosts ≤ 1%, with upper 95% bound ≤ 2%; phishing hit rate reported | |

Also reported, without criteria: recall@high; FPR@alert; per-group final-category shares; domain-weighted rates; E1(b)
deltas. Precision is not used for claims (arbitrary class ratio).

## 7. Stopping rule and missing data

- The window is fixed in advance and never extended after looking at counts or results.
- **Snapshot failures:** a snapshot that fails (network, HTTP error, empty feed) is logged and not retried more often than every 12 h. Missing snapshots shrink n and are not imputed.
- **Below 500 positives:** if fewer than 500 phishing hosts remain after exclusions, report the actual n, the wider intervals, and "E1-a not established".
- **Short legitimate samples:** if fewer than 2,000 hosts are available in a legitimate group, use all of them and report n and intervals (F3). Observations are never duplicated, resampled up or invented to reach 2,000.
- **PhishTank failures in E1(b):** errors and rate limits stay "not checked". They are reported as counts and never treated as `no_match`.

## 8. No tuning on fresh data

Nobody may change thresholds, rules, constants, the guard, features, sampling or exclusions after any fresh item has
been scored. The evaluation runner (`ml/phase6_evaluate.py`, itself in the freeze record) refuses to run if any frozen hash is missing or differs, if the window is still open, if the later Tranco lists are missing, or if any collected file is missing or differs from the SHA-256 recorded in the manifest. Interim results are not
computed: until the window closes, the collector reports only snapshot and host counts.

## 9. Decisions on the pre-freeze flags (user, 2026-10-16)

| Flag | Decision recorded |
| --- | --- |
| **F1** | Keep the prior-registered-domain exclusion for the primary evaluation. Add the supplementary platform group defined in section 5, reported separately with no acceptance criterion. Disclose the generalisation limitation. Basis: on 2026-10-16, only 65 of 263 new phishing hosts survived the exclusion |
| **F2** | Window fixed at 10 days, at most 20 snapshots, starting at the first fresh snapshot. Never extended after inspecting interim counts or results |
| **F3** | Use every eligible legitimate subdomain host (up to 2,000) and report the actual n and its uncertainty. No duplication or invented observations. About 1,122 were expected, using Q2Y54 as a stand-in |
| **F4** | E2 deferred until both keys exist; reported as **not run** |
| **F5** | E3 runs only with the sources available at run time, and the enabled sources are listed in the report |
| **F6** | Raw model-probability metrics and final API outcomes are reported separately; "final high risk" = `high_risk` + `dangerous` |

All numerical acceptance criteria in section 6 are unchanged from the plan.

## 10. Evaluation runner, platform list and query-dependent rules (added before the freeze, 2026-10-20)

**Runner.**
- *Commands:* `python -m ml.phase6_evaluate e1 [--with-phishtank] [--full-urls]` and `python -m ml.phase6_evaluate e3`.
- *Before scoring:* it calls the collector's fail-closed freeze check (section 8).
- *What it writes:* aggregate JSON only, to `reports/phase6/` with exclusive create, never overwriting. No URL or host name is written.
- *Report structure:* raw-model metrics (`raw_model`) and final API outcomes (`final_api`) are reported separately for every group (F6).
- *Status of E2:* reported as "not run" (F4).
- *Pre-freeze audit fixes (2026-10-20; no criterion changed):* criteria compare unrounded rates and bounds; a criterion with no scored hosts reads "not established" (E1-b used to be a bare null); a host on which the model fails is counted as `model_unavailable` and left out of the raw-model rates, never scored as below threshold; E3 reports the status of every lookup (`source_status_counts`), so fast failures are visible next to the latency.
- *Circularity:* the runner is written before the freeze and hashed by it, so a later edit to the runner blocks scoring.

**Evaluation-only platform list v1 (F1 supplementary group).** Built deterministically by `python -m ml.phase6_platforms` from:
- the PRIVATE section of the Public Suffix List snapshot bundled with tldextract 5.4.0 (SHA-256 `b69315c0…5cc774a38`; domains whose owners declare that third parties register names under them; MPL-2.0); and
- the production `SHARED_HOSTING_SUFFIXES`, unchanged.

The list has 2,883 suffixes and includes `typedream.app`. Wildcards (`*.x`) count as `x`; PSL exception (`!`) entries are dropped. Internationalised entries (13, e.g. `я.рус`) are stored as punycode with the same IDNA 2003 codec as `get_host()`, so they match pipeline hosts (pre-freeze fix 2026-10-20; list SHA-256 `ac7db8cd…94b6017`). A platform's own apex is not counted. Production code never uses this list.

*Limitation:* a platform listed in neither source is counted as "excluded, other", so the supplementary group may still undercount.

**Query-dependent rules.** These production rules need inputs the stored form removes:

| Rule | Removed input |
| --- | --- |
| `BRAND_IN_PATH` | query |
| `HTTP_WITH_CREDENTIAL_WORDS` | query |
| `NO_HTTPS` | via `HTTP_WITH_CREDENTIAL_WORDS` |
| `URL_CREDENTIALS_IN_AUTHORITY` | userinfo |
| `VERY_LONG_URL` | full length |

- *Primary run:* E1 scores the stored form, so it does **not fully measure these rules**. The report must say so.
- *Supplementary full-URL analysis* (`--full-urls`):
  - Each collected snapshot is re-fetched from the OpenPhish public GitHub history by its recorded commit (`raw.githubusercontent.com/openphish/public_feed/<commit>/feed.txt`) and verified against the recorded raw SHA-256.
  - Phishing hosts are scored on their first full URL **in memory only**. Only aggregates are written, and the full URLs are discarded.
  - Verified feasible on 2026-10-20 with a pre-freeze commit: the re-fetch matched the recorded hash `3ae958e9…`.
  - It fails closed with no partial result if any snapshot cannot be re-fetched or verified.
- *Limitations:*
  - It depends on GitHub keeping the history.
  - Personal data in query strings is processed transiently.
  - It covers phishing hosts only; the legitimate URLs are bare `https://domain/`.
  - It is reported as supplementary and carries no acceptance criterion.

**Not tested before collection:**
- E1 configuration (b) with live PhishTank, and E3. Both need live network calls, so they are exercised live only at evaluation time. E3 has one mocked test (all lookups failing are reported in `source_status_counts`); E1(b) has none beyond the PhishTank client's own response-parsing tests.
