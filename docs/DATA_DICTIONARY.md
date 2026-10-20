# Data dictionary

## Raw dataset (`data/raw/phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv`)

235,795 rows × 56 columns, no missing values (`reports/metrics/data_audit.json`).

- `FILENAME` (ignored), `URL` (**used**), `label` (**target**: 1 = legitimate, 0 = phishing per the UCI page).
- 53 precomputed columns, **all excluded** from the model:
  - URL-derived (21, including the text columns `Domain` and `TLD`): `URLLength`, `DomainLength`, `IsDomainIP`, `TLD`, `CharContinuationRate`, `TLDLength`, `NoOfSubDomain`,
    `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`,
    `DegitRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`,
    `SpacialCharRatioInURL`, `IsHTTPS`, plus `Domain`.
  - Reference-list derived (3): `URLSimilarityIndex`, `TLDLegitimateProb`, `URLCharProb`.
  - Page/HTML derived (rest): `LineOfCode`, `LargestLineLength`, `HasTitle`, `Title`, `DomainTitleMatchScore`, `URLTitleMatchScore`,
    `HasFavicon`, `Robots`, `IsResponsive`, `NoOfURLRedirect`, `NoOfSelfRedirect`, `HasDescription`, `NoOfPopup`, `NoOfiFrame`,
    `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`, `Bank`, `Pay`, `Crypto`,
    `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef`.

### Why they are excluded (measured)

| Finding | Value | Source |
| --- | --- | --- |
| `URLSimilarityIndex` = 100 | 100% of legitimate rows, 0.78% of phishing | `data_audit.json` |
| Columns separating classes alone with ROC-AUC ≥ 0.95 | `URLSimilarityIndex` 0.996, `LineOfCode` 0.990, `NoOfExternalRef` 0.988, `NoOfImage` 0.980, `NoOfSelfRef` 0.973, `NoOfJS` 0.971, `NoOfCSS` 0.958 | `leakage_single_feature.csv`, `figures/leakage_single_feature.png` |
| Mean `LineOfCode` | legitimate 1,947 vs phishing 66 | same. *Inference (not verified):* many phishing pages were probably captured after takedown, so HTML features describe dead pages |
| https scheme / `www.` prefix / no path / trailing slash | legitimate 100% / 100% / 100% / 0%; phishing 48.7% / 41.4% / 71.8% / 36.5% | `figures/url_format_artifacts.png` |
| HTML features need the page | Cannot be computed at inference without fetching suspicious pages | design |

## Label mapping

`is_phishing = 1 - label` → phishing is the positive class (1) everywhere in this repository.

## Cleaning (`ml/preprocessing.py`, `reports/metrics/preprocessing_report.json`)

| Step | Rows affected |
| --- | --- |
| Missing URL/label | 0 |
| Invalid URL (unsupported scheme, no host, invalid characters, bad port) | 8 dropped |
| Hosts with both labels (58 hosts) | 159 rows dropped |
| Duplicate hosts (model sees only the host) | 16,595 dropped |
| Output | 219,033 hosts: 134,792 legitimate, 84,241 phishing |

## Host normalisation (`ml/feature_extraction.py`)

Trim → add `http://` if no scheme → only http/https → `urlsplit` hostname, lower-case → strip trailing dot →
Unicode hostnames converted to punycode (stdlib IDNA 2003 codec) → only `[a-z0-9._-]` (or IP literal) allowed →
strip leading `www.`. Registered domain = eTLD+1 via tldextract with its bundled ICANN Public Suffix List (offline);
IP hosts map to themselves; hosts without a known suffix use their last two labels.

## Features (21 computed, 17 used by the model)

| Feature | Calculation (on the normalised host) | Model | Purpose / limitation |
| --- | --- | --- | --- |
| `host_length` | characters | yes | long hosts hide the real domain |
| `num_labels` | dot-separated parts | yes | depth |
| `num_dots` | `.` count | yes | depth (highly correlated with `num_labels`) |
| `num_hyphens` | `-` count | yes | `secure-login-x` style |
| `num_digits`, `digit_ratio` | digit count and share | yes | generated names |
| `num_special_chars` | characters outside `[a-z0-9.-]` | **no** | constant 0 |
| `longest_label_length`, `avg_label_length` | label lengths | yes | random/IPFS-like labels |
| `num_numeric_labels` | all-digit labels | yes | near-constant (SHAP ≈ 0) |
| `registered_domain_length` | length of eTLD+1 | yes | |
| `subdomain_count`, `subdomain_length` | labels / characters before eTLD+1 | yes | **biased**: 2.9% of legitimate vs 59.1% of phishing train hosts have a subdomain, partly a collection artifact |
| `tld_length` | length of public suffix | yes | |
| `host_entropy` | Shannon entropy of characters | yes | randomness |
| `max_consonant_run`, `vowel_ratio` | pronounceability | yes | |
| `is_ip` | host is an IPv4/IPv6 literal | **no** | 0 legitimate vs 108 phishing in train → label proxy |
| `has_punycode` | contains `xn--` | **no** | 0 legitimate vs 103 phishing → label proxy |
| `suspicious_word_count` | count of 14 curated words (login, verify, …) | yes | curated list = assumption |
| `is_shared_hosting` | host on one of 20 curated free-hosting suffixes | **no** | 0 legitimate vs 17,525 phishing → label proxy |

Single-feature ROC-AUC on the train split: `reports/metrics/feature_univariate_train.csv`
(top: `subdomain_length` 0.787, `subdomain_count` 0.783, `num_dots` 0.739).
No scaling is needed for tree models; Logistic Regression uses `StandardScaler` fitted on train inside its pipeline.
