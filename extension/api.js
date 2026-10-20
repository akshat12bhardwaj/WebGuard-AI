// API v1.0 client + view model (docs/API_CONTRACT.md). Pure ES module: no DOM, testable with `node --test`.
export const API_BASE = "http://127.0.0.1:8000";
export const TIMEOUT_MS = 15000;

const CATEGORIES = {
  dangerous: { label: "Dangerous", note: "Listed as malicious by a threat-intelligence source. Do not enter any information." },
  high_risk: { label: "High risk", note: "Strong warning signs. This is a warning, not a confirmed listing." },
  caution: { label: "Caution", note: "Some warning signs. This is not proof that the site is malicious." },
  low_risk: { label: "Low risk", note: "No strong warning signs found. This is not proof that the site is safe." },
  unknown: { label: "Unknown", note: "Not enough evidence to assess this address." },
};
export const CATEGORY_LABEL = Object.fromEntries(Object.entries(CATEGORIES).map(([k, v]) => [k, v.label]));
const STATUS_GROUP = {
  match: "Matched", no_match: "Not listed", unverified: "Unverified",
  error: "Not checked", rate_limited: "Not checked", not_configured: "Not checked", invalid_input: "Not checked",
};
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const ERROR_TITLE = {
  unreachable: "Backend unavailable", timeout: "No answer in time", invalid_url: "Address rejected",
  http_error: "Backend error", bad_response: "Backend error", unsupported: "Page not supported", local: "Invalid address",
};
export const errorTitle = (kind) => ERROR_TITLE[kind] ?? "Analysis failed";

/** Validate a tab/user URL before sending it. Drops the #fragment (never needed, may hold tokens). */
export function prepareUrl(raw) {
  let u;
  try {
    u = new URL(String(raw ?? "").trim());
  } catch {
    return { ok: false, reason: "This is not a valid web address." };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { ok: false, reason: `Pages using "${u.protocol}" (browser or local pages) cannot be analyzed.` };
  }
  u.hash = "";
  const url = u.toString();
  if (url.length > 2048) return { ok: false, reason: "The address is longer than 2048 characters." };
  return { ok: true, url, display: u.hostname + (u.pathname === "/" ? "" : u.pathname) }; // no query in the UI
}

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Returns a list of contract violations (empty = valid). */
export function validateResponse(b) {
  const e = [];
  if (!isObj(b)) return ["response is not an object"];
  if (typeof b.api_version !== "string" || !b.api_version.startsWith("1.")) e.push("unsupported api_version");
  const a = b.assessment, ev = b.evidence;
  if (!isObj(a)) e.push("assessment missing");
  else {
    if (!(a.category in CATEGORIES)) e.push("unknown category");
    if (!Number.isInteger(a.risk_score)) e.push("risk_score not an integer");
    if (!(a.safety_score === null || Number.isInteger(a.safety_score))) e.push("bad safety_score");
    if (!["high", "medium", "low"].includes(a.confidence)) e.push("bad confidence");
    if (!Array.isArray(a.notes)) e.push("notes not a list");
  }
  if (!isObj(ev)) e.push("evidence missing");
  else {
    if (!Array.isArray(ev.threat_intel) || ev.threat_intel.some((t) => !isObj(t) || !(t.status in STATUS_GROUP))) e.push("bad threat_intel");
    if (!Array.isArray(ev.rules) || ev.rules.some((r) => !isObj(r) || typeof r.rule_id !== "string")) e.push("bad rules");
    if (!isObj(ev.model)) e.push("model missing");
  }
  if (typeof b.disclaimer !== "string") e.push("disclaimer missing");
  return e;
}

/** POST /api/v1/analyze. Never throws: returns {ok:true,data} or {ok:false,kind,message}. */
export async function analyze(url, { fetchImpl = fetch, timeoutMs = TIMEOUT_MS, base = API_BASE } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await fetchImpl(`${base}/api/v1/analyze`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url }), signal: ctrl.signal,
    });
  } catch (err) {
    return err?.name === "AbortError"
      ? { ok: false, kind: "timeout", message: `No answer within ${timeoutMs / 1000} s. The backend may be busy; try again.` }
      : { ok: false, kind: "unreachable", message: "Cannot reach the analyzer backend at 127.0.0.1:8000. Is it running?" };
  } finally {
    clearTimeout(timer);
  }
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* handled below */
  }
  if (res.status === 422) {
    const d = body?.detail;
    return { ok: false, kind: "invalid_url", message: typeof d === "string" ? `The backend rejected this address: ${d}.` : "The backend rejected this address." };
  }
  if (!res.ok) return { ok: false, kind: "http_error", message: `The backend returned an error (HTTP ${res.status}).` };
  const problems = validateResponse(body);
  if (problems.length) return { ok: false, kind: "bad_response", message: "The backend sent an unexpected answer.", problems };
  return { ok: true, data: body };
}

/** Turn a valid response into display-ready values (keeps model probability, score, rules and TI separate). */
export function viewModel(b) {
  const a = b.assessment, ev = b.evidence, cat = CATEGORIES[a.category];
  const fired = ev.rules.filter((r) => r.status === "fired")
    .sort((x, y) => SEVERITY_ORDER.indexOf(x.severity) - SEVERITY_ORDER.indexOf(y.severity));
  return {
    category: a.category, label: cat.label, note: cat.note,
    riskScore: a.risk_score, safetyScore: a.safety_score === null ? "–" : String(a.safety_score),
    confidence: a.confidence, basis: a.decision_basis ?? "", notes: a.notes,
    modelProbability: typeof ev.model?.probability === "number" ? ev.model.probability.toFixed(2) : "n/a",
    threatIntel: ev.threat_intel.map((t) => ({ source: String(t.source), status: STATUS_GROUP[t.status], detail: String(t.detail ?? "") })),
    rules: fired.map((r) => ({ severity: r.severity, title: String(r.title), explanation: String(r.explanation ?? "") })),
    host: String(ev.host ?? ""), disclaimer: b.disclaimer,
  };
}
