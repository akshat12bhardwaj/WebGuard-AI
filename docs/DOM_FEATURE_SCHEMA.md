# Structural snapshot `dom-v1`

Snapshot semantics are fixed for this revision. Any changed feature meaning requires a new schema version. This is not the schema of PhiUSIIL's precomputed HTML columns. DOM inspection is rule-based only.

## Scope and bounds

The isolated main-frame extractor visits at most 5,000 elements in document order. It stops after 128 password inputs and records at most 32 credential-form records, 16 distinct origins per aggregate group, and eight meta-refresh destinations. Accessible iframe form counts use a separate shared 512-element traversal budget; iframe password values/content are never inspected. Payloads above 32,768 characters are rejected client-side. Injection waits at most 1.5 seconds before explicit fallback; a timed-out late result is ignored. Backend JSON bodies are limited to 64 KiB before parsing. Counters are strict integers 0–5,000; title length is capped at 10,000. Payload fields not in the schema are rejected.

This is a deterministic bounded snapshot, not a MutationObserver or continuous scan. A recheck extracts again. Changed form/link structure, navigation start or Chrome document ID invalidates structural cache reuse. Closed shadow roots, JS submission handlers, submit-button action overrides and nested/cross-origin frame contents are not analysed. No browser security restriction is bypassed.

## Envelope

- `schema_version`: `dom-v1`.
- `state`: inspected, partial, unavailable, not_requested, failed or incompatible.
- `page_origin`: HTTP(S) scheme/host/port only. No path, query, userinfo or fragment.
- `features`: present only after successful/partial extraction. Missing inspection is never substituted with zeros.
- `reason`: enumerated permission/unsupported/timeout/navigation_changed/extraction/schema/bounds when relevant.

Chrome document ID and navigation start are used by the extension for binding/cache freshness, not sent as page features to reputation services. URL and snapshot identity are checked before and after injection, and navigation epochs are checked again before displaying the API result. URL-only and structural records use different cache keys.

## Features

- `form_count`: FORM elements within the top-document traversal prefix.
- `password_count`: INPUT elements whose resolved type is password in that prefix.
- `orphan_password_count`: those password inputs with no owning `form` (uses native form association, including form=id).
- `hidden_password_count`: password inputs hidden by hidden/display/visibility, explicit zero opacity, or with no client rects. This includes ordinary multi-step forms and alone is informational.
- `credential_forms`: one record per encountered password-owning form (up to 32), with password count, hidden-password count, resolved action origin/scheme, GET/POST/dialog method, explicit-action presence and whether action origin/path equals the current page. Empty/missing actions resolve to the current document using native URL/base semantics. The path is used locally for comparison and is never included in the payload.
- `link_count`: sampled A elements; `placeholder_link_count`: missing/empty/#/javascript:void(0) placeholders; `unusual_link_count`: schemes outside http/https/mailto/tel. Statistical only.
- `link_origins`: sorted HTTP(S) origin→count aggregate, not a link inventory. Unsupported/invalid URLs are not guessed as same-site. Overflow marks partial and excludes excess origin buckets.
- `iframe_count`: sampled IFRAME elements; `inaccessible_frame_count`: null or restricted content documents; `iframe_origins`: resolved source-origin aggregate; `accessible_frame_form_count`: FORM nodes in the bounded accessible-frame traversal. Source-less/srcdoc frames inherit page/base-origin resolution for aggregate purposes.
- `script_count`: sampled SCRIPT elements including inline scripts; script source/body is never read.
- `resource_count`: sampled nonempty SCRIPT/IMG src and LINK href references; `resource_origins`: sorted HTTP(S) origin aggregates. No resource paths, queries, fragments or inventories are transmitted.
- `title_present`, `title_length`, `title_has_host`: booleans/length only; no title string is transmitted and no brand inconsistency is inferred solely from a title.
- `meta_refresh`: up to eight resolved HTTP(S) origins and finite bounded delays. No navigation history is read. Only explicit DOM-visible refresh metadata is considered.
- `truncated`: a traversal/origin/form/password/refresh/URL bound was reached. Inaccessible iframe coverage, unresolved/non-HTTP form destinations, or truncation yields partial inspection.

The backend derives same-site/cross-site counts and ratios from these origin aggregates using tldextract's offline Public Suffix List **including private suffixes**. Thus example.co.uk subdomains share a site, while separate github.io tenants do not. In partial snapshots these are sampled aggregates, not invented whole-page counts. Ratios with no usable denominator are null.

## Internal rules and production scoring

- `DOM_PASSWORD_HTTP`: high; password form action uses HTTP and method is not dialog.
- `DOM_CROSS_SITE_FORM`: information only; third-party HTTPS authentication/payment flows are common and do not independently raise risk.
- `DOM_CREDENTIAL_REDIRECT`: medium; cross-site meta refresh within ten seconds while visible password entry is present.
- `DOM_HIDDEN_PASSWORD`: information only.
- `DOM_STRUCTURAL_COMBINATION`: medium; cross-site credential destination, hidden password entry and rapid external refresh occur together.

There is no score averaging. High and medium findings can only impose existing category floors; confirmed reputation matches retain precedence. No DOM classifier is used. User-facing copy reports structural warnings and uncertainty, never raw identifiers or a claim that these rules prove phishing.
