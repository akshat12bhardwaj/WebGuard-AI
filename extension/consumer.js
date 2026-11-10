// Consumer presentation only. No assessment or scoring logic lives here.
import { CATEGORY_LABEL, prepareUrl } from "./api.js";
export const MESSAGES = {
  low_risk: {
    symbol: "✓",
    headline: "No strong warning signs found.",
    action: "Stay alert. Check the address before sharing information.",
    meaning:
      "The available signals did not indicate a strong risk. Low risk is not a guarantee of safety.",
    steps: [
      "Check that the address matches the site you intended to visit.",
      "Be cautious with unexpected requests for passwords or payment.",
    ],
  },
  caution: {
    symbol: "!",
    headline: "Some warning signs need your attention.",
    action: "Verify the address before sharing information.",
    meaning:
      "Some signals deserve a closer look. This assessment does not confirm that the website is malicious.",
    steps: [
      "Reach the organisation through an address you already know.",
      "Verify unexpected messages through another channel.",
    ],
  },
  high_risk: {
    symbol: "!",
    headline: "Significant warning signs detected.",
    action: "Avoid entering passwords or payment details.",
    meaning:
      "The available signals indicate high risk. A warning alone is not a confirmed malicious listing.",
    steps: [
      "Do not sign in or make a payment on this page.",
      "Use the organisation’s official app or type its known address yourself.",
    ],
  },
  dangerous: {
    symbol: "×",
    headline: "A security source lists this address as malicious.",
    action: "Leave this page. Do not share personal information.",
    meaning:
      "A confirmed security reputation listing was returned for this address. Treat it as dangerous.",
    steps: [
      "Do not enter passwords, security codes or payment details.",
      "If you shared a password, change it through the official site or app.",
    ],
  },
  unknown: {
    symbol: "?",
    headline: "A reliable assessment is unavailable.",
    action: "Treat this address with care until you can check it again.",
    meaning:
      "There is not enough evidence for a meaningful risk result. Unavailable checks do not count as passed.",
    steps: [
      "Avoid sharing sensitive information while the result is unknown.",
      "Try another check when the analyzer is available.",
    ],
  },
};
const checked = (s) => ["match", "no_match", "unverified"].includes(s.status);
export function consumerModel(data) {
  const a = data.assessment,
    e = data.evidence,
    cat = a.category;
  const sources = e.threat_intel;
  const n = sources.filter(checked).length;
  const reputation = sources.some((s) => s.status === "match")
    ? "Warning found"
    : sources.some((s) => s.status === "unverified")
      ? "Unverified report"
      : !sources.length || !n
        ? "Unavailable"
        : n < sources.length
          ? "Partly checked"
          : "No listing found";
  const dom = e.dom || { state: "not_requested", rules: [] };
  const inspected = ["inspected", "partial"].includes(dom.state);
  const domWarnings = (dom.rules || []).filter(
    (r) => r.status === "fired" && ["high", "medium"].includes(r.severity),
  );
  const domInsight = domWarnings.length
    ? domWarnings.some((r) => r.rule_id === "DOM_PASSWORD_HTTP")
      ? "Password form uses an insecure connection."
      : "Page behavior needs attention."
    : dom.state === "partial"
      ? "Page structure partly checked."
      : inspected
        ? "No strong page warning signs found."
        : dom.state === "not_requested"
          ? "Address check only."
          : "Page structure could not be checked.";
  const address = e.rules.filter((r) => !r.rule_id.startsWith("TI_"));
  const addressStatus = address.some((r) => r.status === "fired")
    ? "Warning found"
    : address.some((r) => r.status === "not_evaluated")
      ? "Partly assessed"
      : address.length
        ? "No warning found"
        : "Not assessed";
  const fired = (id) =>
    (dom.rules || []).some((r) => r.rule_id === id && r.status === "fired");
  return {
    domState: dom.state,
    domInsight: domInsight,
    // Summary wording: missing or partial inspection is never presented as a passed check.
    domStatus: domWarnings.length
      ? "Warning found"
      : dom.state === "partial"
        ? "Partly checked"
        : inspected
          ? "No strong warning found"
          : dom.state === "not_requested"
            ? "Not inspected"
            : "Unavailable",
    // Informational findings that do not raise risk but help the person verify the page.
    domNotes:
      inspected && fired("DOM_CROSS_SITE_FORM")
        ? [
            "This sign-in form sends to another website. That is common for legitimate sign-in services; check that you recognise it.",
          ]
        : [],
    domShort: domWarnings.length
      ? domWarnings.some((r) => r.rule_id === "DOM_PASSWORD_HTTP")
        ? "Insecure password form."
        : "Page behavior needs attention."
      : dom.state === "partial"
        ? "Page partly inspected."
        : inspected
          ? "Page structure inspected."
          : dom.state === "not_requested"
            ? "Address check only."
            : "Page inspection unavailable.",
    domWarnings: domWarnings.map((r) =>
      r.rule_id === "DOM_PASSWORD_HTTP"
        ? "A password form sends information over an insecure connection."
        : r.rule_id === "DOM_CREDENTIAL_REDIRECT"
          ? "This page requests a password while preparing to redirect to another website."
          : "Several page-structure signals need a closer look.",
    ),
    category: cat,
    label: CATEGORY_LABEL[cat],
    ...MESSAGES[cat],
    score: cat === "unknown" ? null : a.risk_score,
    host: String(e.host || "Website"),
    url: String(e.url || ""),
    time: String(e.collected_at || ""),
    reputation,
    coverage: sources.length
      ? `${n} of ${sources.length} sources checked`
      : "No reputation sources available",
    partial:
      n < sources.length ||
      !sources.length ||
      e.model.available !== true ||
      address.some((r) => r.status === "not_evaluated") ||
      ["partial", "unavailable", "failed", "incompatible"].includes(dom.state),
    areas: [
      {
        title: "Address signals",
        text: "Looks for suspicious characteristics in the website address.",
        status: addressStatus,
        icon: "address",
      },
      {
        title: "Reputation",
        text: "Consults available security lists for known warnings.",
        status: reputation,
        icon: "reputation",
      },
      {
        title: "Risk patterns",
        text: "Evaluates patterns in the hostname for signs of risk.",
        status: e.model.available === true ? "Assessed" : "Unavailable",
        icon: "pattern",
      },
      {
        title: "Overall assessment",
        text: "Brings the available signals together into one result.",
        status: cat === "unknown" ? "Unavailable" : CATEGORY_LABEL[cat],
        icon: "shield",
      },
    ],
    sources: sources.filter(checked).map((s) => ({
      name: String(s.source),
      text:
        {
          match: "Warning found · listed",
          no_match: "Checked · no listing found",
          unverified: "Checked · report not verified",
        }[s.status] || "Unavailable",
    })),
  };
}
const SEVERITY = ["critical", "high", "medium", "low", "info"];
const bySeverity = (a, b) => SEVERITY.indexOf(a.severity) - SEVERITY.indexOf(b.severity);
// Card order: confirmed listing, high-severity, other warnings, clear results; checks not performed go last.
const warnRank = (severity) => (severity === "critical" ? 0 : severity === "high" ? 1 : 2);
// Page-structure rules (backend/dom_rules.py) in consumer words. Medium/high only; info rules never warn.
const DOM_FINDING = {
  DOM_PASSWORD_HTTP: ["Suspicious form detected", "A login form may submit information insecurely."],
  DOM_CREDENTIAL_REDIRECT: ["Suspicious redirect", "This page asks for a password while sending you to another website."],
};
const DOM_OTHER = ["Suspicious page behavior", "Several page elements together resemble a known phishing pattern."];
/**
 * The report's three evidence cards (address, page, reputation), most important first. Each says what was analysed
 * and what was found. Wording comes from backend rule ids/titles and statuses only: a check that did not run is
 * named as not performed (tone "none"), never as clear, and a missed listing never reads as proof of safety.
 */
export function findings(data) {
  const e = data.evidence,
    v = consumerModel(data);
  const card = (key, title, icon, rank, status, tone, text, more = []) =>
    ({ key, title, icon, rank, status, tone, text, more });

  const address = e.rules.filter((r) => !r.rule_id.startsWith("TI_"));
  const fired = address.filter((r) => r.status === "fired").sort(bySeverity);
  const warnings = fired.filter((r) => r.severity !== "info");
  const notes = fired.filter((r) => r.severity === "info").map((r) => `${r.title}.`);
  const analysed = address.some((r) => r.status !== "not_evaluated") || e.model.available === true;
  const addressCard = warnings.length
    ? card("address", "Address analysis", "address", warnRank(warnings[0].severity), warnings[0].title, "warn",
        "A warning sign in the website address.", [...warnings.slice(1).map((r) => `${r.title}.`), ...notes])
    : !analysed
      ? card("address", "Address analysis", "address", 5, "Address not analyzed", "none",
          "The website address could not be assessed this time.")
      : card("address", "Address analysis", "address", 4, "No strong address warnings", "ok",
          notes.length ? `Worth knowing: ${notes[0].charAt(0).toLowerCase()}${notes[0].slice(1)}`
            : "No significant address-based warning signs were identified.", notes.slice(1));

  const dom = e.dom || { state: "not_requested", rules: [] };
  const domFired = (dom.rules || [])
    .filter((r) => r.status === "fired" && ["high", "medium"].includes(r.severity))
    .sort(bySeverity);
  const domText = (r) => DOM_FINDING[r.rule_id] || DOM_OTHER;
  const [domHead, domBody] = domFired.length ? domText(domFired[0]) : [];
  const pageCard = domFired.length
    ? card("page", "Page inspection", "page", warnRank(domFired[0].severity), domHead, "warn", domBody,
        domFired.slice(1).map((r) => domText(r)[1]))
    : v.domNotes.length
      ? card("page", "Page inspection", "page", 3, "Sign-in goes to another site", "ok",
          "Common for legitimate sign-in services. Check that you recognise it.")
      : dom.state === "inspected"
        ? card("page", "Page inspection", "page", 4, "Website structure analyzed", "ok",
            "Forms, sign-in fields and redirects showed no warning signs.")
        : dom.state === "partial"
          ? card("page", "Page inspection", "page", 4, "No page warnings found", "ok",
              "No warning signs in the parts of the page that could be read.")
          : card("page", "Page inspection", "page", 5, "Page inspection not performed", "none",
              analysed ? "This result is based on the website address." : "The page was not read during this check.");

  const status = (s) => e.threat_intel.some((t) => t.status === s);
  const repCard = status("match")
    ? card("reputation", "Reputation", "reputation", 0, "Known threat identified", "warn",
        "A security reputation source lists this website as a threat.")
    : status("unverified")
      ? card("reputation", "Reputation", "reputation", 2, "Unconfirmed threat report", "warn",
          "A security source has a report about this website that is not confirmed.")
      : status("no_match")
        ? card("reputation", "Reputation", "reputation", 4, "No known threat listing", "ok",
            "Security sources had no listing. New threats may not be listed yet.")
        : card("reputation", "Reputation", "reputation", 5, "Reputation not available", "none",
            "Security sources could not be reached for this check.");

  const cards = [addressCard, pageCard, repCard];
  // Only high/medium rules raise the level (backend/fusion.py), so a raised score with no warning anywhere came from
  // the hostname pattern model. Say that, without inventing a specific cause.
  if (["caution", "high_risk"].includes(v.category) && !cards.some((c) => c.tone === "warn") && e.model.available === true)
    Object.assign(addressCard, { rank: 2, status: "Unusual patterns detected", tone: "warn",
      text: "Website address characteristics contributed to the risk assessment.", more: [] });
  return cards.sort((a, b) => a.rank - b.rank);
}
export const $ = (id) => document.getElementById(id);
export function el(tag, cls = "", text = "") {
  const n = document.createElement(tag);
  n.className = cls;
  n.textContent = text;
  return n;
}
export function formatTime(raw) {
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? "Time unavailable" : d.toLocaleString();
}
export function safeAddress(raw) {
  const p = prepareUrl(raw);
  return p.ok ? p.display : "Address unavailable";
}
// One 32-unit icon grid; the stroke does not scale (CSS .ico), so 16 px and 40 px icons share one visual weight.
const ICONS = {
  address: "M5 6h22v20H5z M5 12h22 M9 9h1 M13 9h1 M10 18h12 M10 22h7",
  reputation: "m16 3 11 5v9c0 6-7 10-11 12C12 27 5 23 5 17V8Z M11 16l4 4 7-8",
  pattern: "M4 9h7l5 14 5-14h7 M4 23h5 M23 23h5 M16 4v3 M16 26v3",
  shield: "m16 3 11 5v9c0 6-7 10-11 12C12 27 5 23 5 17V8Z M16 10v9 M16 22v1",
  page: "M8 4h11l5 5v19H8z M19 4v5h5 M12 15h8 M12 19h8 M12 23h5",
  check: "M9 16.5l4.5 4.5L23 11",
  alert: "M16 8v10 M16 23v1",
  cross: "M10 10l12 12 M22 10L10 22",
  question:
    "M12 12.5a4 4 0 1 1 6 3.4c-1.2.7-2 1.4-2 2.8v.8 M16 23.5v.5",
  pending: "M9 16h1 M15.5 16h1 M22 16h1",
  globe:
    "M16 4a12 12 0 1 0 0 24a12 12 0 1 0 0-24 M4 16h24 M16 4c-4.5 4-4.5 20 0 24 M16 4c4.5 4 4.5 20 0 24",
  "arrow-up-right": "M10 22L22 10 M12 10h10v10",
  "arrow-right": "M6 16h20 M19 9l7 7-7 7",
  "arrow-down": "M16 6v20 M9 19l7 7 7-7",
  "arrow-up": "M16 26V6 M9 13l7-7 7 7",
  refresh: "M25 16a9 9 0 1 1-2.6-6.4 M23 4v6h-6",
  pulse: "M3 16h6l3-8 6 16 3-8h8",
  lock: "M9 15h14v12H9z M12 15v-4a4 4 0 0 1 8 0v4 M16 20v3",
};
export const SYMBOL_ICON = {
  low_risk: "check",
  caution: "alert",
  high_risk: "alert",
  dangerous: "cross",
  unknown: "question",
};
export function icon(type) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 32 32");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("class", "ico");
  const path = document.createElementNS(svg.namespaceURI, "path");
  path.setAttribute("d", ICONS[type] || ICONS.shield);
  svg.append(path);
  return svg;
}
/** Replace every static <i data-icon="name"></i> placeholder with the shared SVG icon. */
export function mountIcons(root = document) {
  for (const slot of root.querySelectorAll("[data-icon]"))
    slot.replaceChildren(icon(slot.dataset.icon));
}
/** Area status → monochrome tone, so state is carried by shape and text, never by colour alone. */
export function tone(status) {
  return /^(no |low risk|assessed|available)/i.test(status)
    ? "ok"
    : /warning|unverified|high risk|dangerous|caution/i.test(status)
    ? "warn"
      : "muted";
}
