// Detailed-report view model. Every value comes from the API v1.0 response; text that describes what a rule checks
// mirrors backend/rules.py and is labelled as a description, never as evidence. Missing evidence stays missing.
import { CATEGORY_LABEL, viewModel } from "./api.js";

// What each backend rule checks (backend/rules.py). Shown as "What is checked", not as a finding.
export const RULE_CHECKS = {
  TI_PHISHTANK_VERIFIED: "PhishTank lists this exact URL as a verified, valid phish.",
  TI_URLHAUS_LISTED: "URLhaus lists this exact URL as a malware-distribution URL.",
  TI_SAFE_BROWSING_MATCH: "Google Safe Browsing reports a threat match for this URL.",
  TI_OPENPHISH_LISTED: "This exact URL is in the local OpenPhish feed snapshot.",
  URL_CREDENTIALS_IN_AUTHORITY: "The address contains '@' before the host, which hides the real destination.",
  BRAND_IN_HOST_MISMATCH: "A brand from the curated list is in the registered name, or in a subdomain together with login/account words, on a domain the brand does not own.",
  BRAND_IN_SUBDOMAIN: "A brand from the curated list appears in the subdomain of a domain the brand does not own.",
  BRAND_IN_PATH: "A brand from the curated list appears in the path or query of a domain the brand does not own.",
  IP_ADDRESS_HOST: "The host is a raw IPv4/IPv6 address instead of a domain name.",
  HTTP_WITH_CREDENTIAL_WORDS: "The page uses plain http and the address contains login/account words.",
  NO_HTTPS: "The page uses plain http (without login words; those are reported by the rule above).",
  PUNYCODE_HOST: "The host is an internationalised (punycode, 'xn--') name.",
  SHARED_HOSTING_PLATFORM: "The host is on a curated list of shared/free hosting platforms.",
  UNUSUAL_HOST_CHARACTERS: "The host contains characters other than letters, digits, dots and hyphens.",
  NONSTANDARD_PORT: "The address uses a port other than the default, 80 or 443.",
  URL_SHORTENER: "The host is a known link shortener.",
  VERY_LONG_URL: "The normalised address is longer than 200 characters.",
};
const TI_RULE_SOURCE = {
  TI_PHISHTANK_VERIFIED: "PhishTank", TI_URLHAUS_LISTED: "URLhaus", TI_SAFE_BROWSING_MATCH: "Google Safe Browsing",
  TI_OPENPHISH_LISTED: "OpenPhish (local snapshot)",
};
// Hostname features of the model (docs/DATA_DICTIONARY.md).
export const FEATURE_LABELS = {
  host_length: "Host length (characters)", num_labels: "Number of dot-separated labels", num_dots: "Number of dots",
  num_hyphens: "Number of hyphens", num_digits: "Number of digits", digit_ratio: "Share of digits",
  longest_label_length: "Longest label (characters)", avg_label_length: "Average label length",
  num_numeric_labels: "All-digit labels", registered_domain_length: "Registered domain length",
  subdomain_count: "Number of subdomain labels", subdomain_length: "Subdomain length (characters)",
  tld_length: "Public suffix length", host_entropy: "Character randomness (Shannon entropy)",
  max_consonant_run: "Longest run of consonants", vowel_ratio: "Share of vowels", suspicious_word_count: "Login-type words in the host",
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const STATE_ORDER = { triggered: 0, unavailable: 1, not_evaluated: 2, passed: 3 };
const RECOMMEND = {
  dangerous: ["Leave the page. Do not enter passwords, codes or payment details.",
    "If you already entered details, change that password from the official site or app and contact the organisation."],
  high_risk: ["Do not sign in or pay on this page.", "Reach the organisation by typing its known address yourself, not via this link."],
  caution: ["Check the address character by character before entering any information.",
    "If a message asked you to open this link, verify the request through another channel."],
  low_risk: ["No strong warning signs were found. Still check the address before entering a password.",
    "Low risk is not proof of safety: new phishing pages are often not yet listed."],
  unknown: ["There was not enough evidence for an assessment. Treat the page with care and avoid entering sensitive data."],
};

// Truthful wording for every API v1.0 threat-intelligence status.
export const SOURCE_STATUS_TEXT = {
  match: "Listed (confirmed match)", no_match: "Checked — not listed", unverified: "Checked — reported, not verified",
  not_configured: "Not checked — not configured", error: "Not checked — error", rate_limited: "Not checked — rate limited",
  invalid_input: "Not checked — invalid input",
};
// Contract bands (docs/API_CONTRACT.md) used when the model thresholds are not in the response.
const CONTRACT_BANDS = { alert: 37, high: 57 };
const CONFIRMED_RISK = 95;

const urlObservation = (id, url) => {
  let u;
  try { u = new URL(url); } catch { return ""; }
  if (id === "VERY_LONG_URL") return `Observed: ${url.length} characters (threshold: more than 200).`;
  if (id === "NONSTANDARD_PORT") return `Observed: ${u.port ? `port ${u.port}` : "default port"}.`;
  if (id === "NO_HTTPS" || id === "HTTP_WITH_CREDENTIAL_WORDS") return `Observed scheme: ${u.protocol.replace(":", "")}.`;
  return "";
};

function ruleRow(r, tiBySource, url) {
  const source = TI_RULE_SOURCE[r.rule_id];
  const ti = source ? tiBySource.get(source) : null;
  let state, label;
  if (r.status === "fired") [state, label] = ["triggered", "Triggered"];
  else if (r.status === "not_fired") [state, label] = ["passed", "Passed"];
  else if (source) [state, label] = ["unavailable", "Unavailable"];
  else [state, label] = ["not_evaluated", "Not evaluated"];
  let finding;
  if (state === "triggered") finding = r.explanation || "The backend reported this rule as triggered without further detail.";
  else if (state === "passed") finding = source
    ? `${source} was checked and reported no confirmed listing${ti ? ` (status: ${ti.status})` : ""}. This is not proof of safety.`
    : "The suspicious condition was not found in this address. This is not proof of safety.";
  else finding = r.explanation || (source ? `${source} was not checked.` : "The backend could not evaluate this rule.");
  return {
    id: r.rule_id, title: String(r.title), severity: r.severity, state, label, finding, source: source ?? null,
    checks: RULE_CHECKS[r.rule_id] ?? "No description available for this rule.",
    observed: state === "unavailable" ? "" : urlObservation(r.rule_id, url),
  };
}

/** Build the report from a validated API response. */
/** Score bands exactly as backend/fusion.py places the score: 0..A-1, A..H-1, H..94, 95 = dangerous. */
export function scoreBands(b) {
  const th = b?.evidence?.model?.thresholds ?? {};
  return typeof th.alert === "number" && typeof th.high === "number"
    ? { alert: Math.round(100 * th.alert), high: Math.round(100 * th.high), dangerous: CONFIRMED_RISK }
    : { ...CONTRACT_BANDS, dangerous: CONFIRMED_RISK };
}

export function buildReport(b) {
  const v = viewModel(b), a = b.assessment, ev = b.evidence, m = ev.model ?? {};
  const tiBySource = new Map(ev.threat_intel.map((t) => [String(t.source), t]));
  const rules = ev.rules.map((r) => ruleRow(r, tiBySource, String(ev.url ?? "")))
    .sort((x, y) => STATE_ORDER[x.state] - STATE_ORDER[y.state] || SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity));
  const count = (s) => rules.filter((r) => r.state === s).length;
  const th = m.thresholds ?? {};
  const prob = typeof m.probability === "number" ? m.probability : null;
  const hasTh = typeof th.alert === "number" && typeof th.high === "number";
  const model = {
    available: m.available === true, error: String(m.error ?? ""),
    probability: prob, alert: hasTh ? th.alert : null, high: hasTh ? th.high : null,
    level: prob === null || !hasTh ? null : prob >= th.high ? "at or above the 'high' threshold"
      : prob >= th.alert ? "at or above the 'alert' threshold, below 'high'" : "below the 'alert' threshold",
    version: m.model_version ?? null, calibration: m.calibration ?? null,
    outOfRange: Array.isArray(m.out_of_training_range) ? m.out_of_training_range.map(String) : [],
    features: (Array.isArray(m.top_shap) ? m.top_shap : []).filter((f) => f && typeof f.feature === "string").map((f) => ({
      name: f.feature, label: FEATURE_LABELS[f.feature] ?? f.feature,
      value: typeof f.value === "number" ? f.value : null,
      contribution: typeof f.shap_log_odds === "number" ? f.shap_log_odds : null,
    })),
  };
  const sources = ev.threat_intel.map((t) => ({
    source: String(t.source), status: String(t.status), group: v.threatIntel.find((x) => x.source === String(t.source))?.status ?? "",
    statusText: SOURCE_STATUS_TEXT[t.status] ?? String(t.status),
    checked: ["match", "no_match", "unverified"].includes(t.status), detail: String(t.detail ?? ""),
    checkedAt: String(t.checked_at ?? ""), cached: t.cached === true, reference: String(t.reference ?? ""),
  }));
  // Assessment pipeline as the backend runs it (backend/service.py, backend/fusion.py): the URL goes to the model and
  // the reputation sources in parallel, the rules then read the reputation results, and fusion sets the category.
  // Each stage's status comes only from the response; a stage the response says did not run is never shown as done.
  // Backend notes that only repeat a source status ("X not checked: y") appear once, in the reputation stage.
  const sourceNote = (n) => sources.some((src) => n.startsWith(`${src.source} not checked:`));
  const caveats = a.notes.map(String).filter((n) => !sourceNote(n));
  const zone = model.level === null ? null : prob >= th.high ? "above high" : prob >= th.alert ? "between alert and high" : "below alert";
  const checkedN = sources.filter((src) => src.checked).length;
  const triggered = rules.filter((x) => x.state === "triggered");
  const c = { triggered: count("triggered"), passed: count("passed"), unavailable: count("unavailable"), not_evaluated: count("not_evaluated") };
  let scheme = "";
  try { scheme = new URL(String(ev.url)).protocol.replace(":", ""); } catch { /* left empty */ }
  const flow = [
    { id: "url", title: "Website URL", subtitle: "Address sent to the local backend; the page itself is never fetched",
      status: { label: "Submitted", tone: "teal" },
      rows: [["Host", String(ev.host ?? "")], ["Registered domain", String(ev.registered_domain ?? "")], ["Scheme", scheme]] },
    { id: "model", title: "Hostname model", subtitle: "Calibrated XGBoost on host-name features; a signal, not a rule",
      status: model.available ? { label: "Completed", tone: "teal" } : { label: "Unavailable", tone: "neutral" },
      rows: model.level ? [["Probability", prob.toFixed(3)], ["Zone", zone], ["Thresholds", `alert ${th.alert} · high ${th.high}`]]
        : [["Result", model.available ? "not enough model evidence returned" : `unavailable${model.error ? ` (${model.error})` : ""}`]],
      notes: caveats },
    { id: "reputation", title: "Reputation checks", subtitle: `${checkedN} of ${sources.length} sources checked`,
      status: !sources.length ? { label: "None returned", tone: "neutral" } : sources.some((src) => src.status === "match") ? { label: "Threat found", tone: "bad" }
        : checkedN === 0 ? { label: "Not checked", tone: "neutral" } : checkedN < sources.length ? { label: "Partly checked", tone: "caution" }
          : { label: "Completed", tone: "teal" } },
    { id: "rules", title: "Rule engine", subtitle: `${rules.length} deterministic rules on the URL and the reputation results`,
      status: !rules.length ? { label: "None returned", tone: "neutral" } : triggered.length ? { label: `${triggered.length} triggered`, tone: "bad" }
        : { label: "None triggered", tone: "teal" },
      rows: [["Triggered", String(c.triggered)], ["Passed", String(c.passed)], ["Unavailable", String(c.unavailable)], ["Not evaluated", String(c.not_evaluated)]],
      notes: triggered.map((r) => `${r.title}: ${r.finding}`) },
    { id: "final", title: "Final assessment", subtitle: a.decision_basis ? `Basis: ${a.decision_basis}` : "Basis not provided",
      status: { label: CATEGORY_LABEL[a.category], tone: `cat-${a.category}` },
      rows: [["Category", CATEGORY_LABEL[a.category]], ["Risk score", a.category === "unknown" ? "– (no score)" : `${a.risk_score} / 100`], ["Confidence", String(a.confidence)]] },
  ];
  const limitations = [
    ...(model.outOfRange.length ? [`Model features outside the training range: ${model.outOfRange.join(", ")}.`] : []),
    ...(Array.isArray(ev.errors) ? ev.errors.map((x) => `Backend error: ${x}`) : []),
  ];
  const unchecked = sources.filter((src) => !src.checked);
  const recommendations = [...(RECOMMEND[a.category] ?? [])];
  if (unchecked.length) {
    recommendations.push("Some reputation sources were not checked (see Reputation checks above), so a listing there could have been missed.");
  }
  return {
    category: a.category, label: CATEGORY_LABEL[a.category], note: v.note,
    riskScore: a.category === "unknown" ? null : a.risk_score, safetyScore: a.safety_score, confidence: a.confidence,
    basis: a.decision_basis ?? "", notes: a.notes.map(String), errors: Array.isArray(ev.errors) ? ev.errors.map(String) : [],
    url: String(ev.url ?? ""), host: String(ev.host ?? ""), registeredDomain: String(ev.registered_domain ?? ""),
    collectedAt: String(ev.collected_at ?? ""), apiVersion: b.api_version, disclaimer: b.disclaimer,
    rules, ruleCounts: c,
    // Score bands exactly as backend/fusion.py places the score (0..A-1, A..H-1, H..94, 95 = dangerous).
    bands: scoreBands(b),
    model, sources, flow, caveats, limitations, recommendations,
  };
}
