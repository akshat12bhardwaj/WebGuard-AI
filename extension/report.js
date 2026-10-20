// Detailed report tab: report.html?id=<assessment id>. Reads that record from chrome.storage.session (written by the
// service worker) and renders it with textContent only; every value comes from buildReport() over the API response.
import { validateResponse } from "./api.js";
import { idKey } from "./assessor.js";
import { renderGauge } from "./gauge.js";
import { buildReport } from "./report_model.js";

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const ICONS = {
  check: ["M5 12.5l4.5 4.5L19 7.5"],
  alert: ["M12 3.5 2.5 20h19z", "M12 10v4", "M12 17v.01"],
  minus: ["M21 12a9 9 0 1 1-18 0a9 9 0 1 1 18 0", "M8 12h8"],
  help: ["M21 12a9 9 0 1 1-18 0a9 9 0 1 1 18 0", "M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.6", "M12 17v.01"],
  shield: ["M12 3 4.5 6v5.5c0 4.7 3.2 8.3 7.5 9.5 4.3-1.2 7.5-4.8 7.5-9.5V6z"],
  gauge: ["M4 16a8 8 0 0 1 16 0", "M12 16l4-5"],
};
function icon(name) {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "i");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ICONS[name]) {
    const p = document.createElementNS(SVG, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}
const STATE_ICON = { triggered: "alert", passed: "check", unavailable: "minus", not_evaluated: "help" };
const badge = (state, text) => {
  const b = el("span", `badge st-${state}`);
  b.append(icon(STATE_ICON[state]), document.createTextNode(text));
  return b;
};
const fmt = (x, d = 3) => (typeof x === "number" ? x.toFixed(d) : "not provided");
const toneClass = (tone) => (tone.startsWith("cat-") ? tone : `t-${tone}`);
const SHORT_STATUS = { match: "Listed", no_match: "Not listed", unverified: "Unverified", not_configured: "Not configured",
  error: "Lookup failed", rate_limited: "Rate limited", invalid_input: "Invalid input" };

/** Assessment ID: first 12 hex characters of the SHA-256 of the exact response shown. */
async function assessmentId(data) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(data))));
  return [...hash.slice(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function renderFlow(r) {
  $("r-flow").replaceChildren(...r.flow.map((node, i) => {
    const li = el("li", `node ${toneClass(node.status.tone)}`);
    const head = el("div", "node-head");
    const top = el("div", "node-top");
    top.append(el("span", "node-step", `Step ${i + 1}`), el("span", "chip", node.status.label));
    head.append(top, el("h3", "", node.title), el("p", "node-sub", node.subtitle));
    const kv = el("dl", "kv");
    if (node.id === "reputation") {
      kv.id = "r-sources";
      for (const s of r.sources) {
        kv.append(el("dt", "", s.source.replace(" (local snapshot)", "")));
        const dd = el("dd", `g-${s.group.replace(" ", "-")}`, SHORT_STATUS[s.status] ?? s.status);
        dd.title = s.statusText + (s.detail ? ` — ${s.detail}` : "");
        kv.append(dd);
      }
    } else for (const [k, v] of node.rows ?? []) kv.append(el("dt", "", k), el("dd", "", v));
    li.append(head, kv);
    if (node.notes?.length) {
      const ul = el("ul", "node-notes");
      for (const n of node.notes) ul.append(el("li", "", n));
      li.append(ul);
    }
    return li;
  }));
}

function renderRules(r) {
  const c = r.ruleCounts;
  $("r-rule-counts").replaceChildren(...[["triggered", "Triggered"], ["passed", "Passed"], ["unavailable", "Unavailable"],
    ["not_evaluated", "Not evaluated"]].map(([k, label]) => badge(k, `${c[k]} ${label}`)));
  $("r-rule-total").textContent = `${r.rules.length} rules`;
  const sourceBy = new Map(r.sources.map((s) => [s.source, s]));
  $("r-rules").replaceChildren(...r.rules.map((rule) => {
    const tr = el("tr");
    const status = el("td");
    status.append(badge(rule.state, rule.label));
    const name = el("td");
    name.append(el("span", "rule-title", rule.title), el("span", "rule-id", rule.id), el("span", `sev s-${rule.severity}`, `${rule.severity} severity`));
    const finding = el("td", "", rule.finding);
    // Expandable evidence only where the response holds more than the finding line.
    const src = rule.source ? sourceBy.get(rule.source) : null;
    const rows = [];
    if (rule.observed) rows.push(["From the returned URL", rule.observed]);
    if (src) {
      rows.push(["Source status", `${src.statusText} (${src.status})`]);
      if (src.detail) rows.push(["Source detail", src.detail]);
      if (src.checkedAt) rows.push(["Checked at", `${src.checkedAt}${src.cached ? " (cached result)" : ""}`]);
      if (src.reference) rows.push(["Reference", src.reference]);
    }
    if (rows.length) {
      const more = el("details", "more");
      const dl = el("dl");
      for (const [k, v] of rows) dl.append(el("dt", "", k), el("dd", "", v));
      more.append(el("summary", "", "Evidence"), dl);
      finding.append(more);
    }
    tr.append(status, name, el("td", "checks", rule.checks), finding);
    return tr;
  }));
}

function renderModel(m) {
  const show = m.probability !== null && m.alert !== null && m.high !== null;
  $("r-scale").hidden = !show;
  if (show) {
    const pct = (x) => `${(Math.min(Math.max(x, 0), 1) * 100).toFixed(2)}%`;
    $("r-scale-dot").style.left = pct(m.probability);
    $("r-scale-alert").style.left = pct(m.alert);
    $("r-scale-high").style.left = pct(m.high);
    $("r-scale-caption").textContent = `Probability ${fmt(m.probability)} · ticks: alert ${m.alert}, high ${m.high}`;
  }
  const max = Math.max(...m.features.map((f) => Math.abs(f.contribution ?? 0)), 1e-9);
  $("r-features").replaceChildren(...(m.features.length ? m.features.map((f) => {
    const tr = el("tr");
    const name = el("td");
    name.append(el("span", "f-name", f.label), el("span", "rule-id", f.name));
    const contrib = el("td");
    if (f.contribution === null) contrib.textContent = "not provided";
    else {
      const box = el("div", "contrib");
      const bar = el("div", "bar");
      const fill = el("span", f.contribution > 0 ? "pos" : "neg");
      fill.style.width = `${(Math.abs(f.contribution) / max) * 50}%`;
      bar.append(fill);
      box.title = f.contribution > 0 ? "towards phishing" : f.contribution < 0 ? "towards legitimate" : "neutral";
      box.append(bar, el("span", "", `${f.contribution > 0 ? "+" : ""}${f.contribution.toFixed(3)}`));
      contrib.append(box);
    }
    tr.append(name, el("td", "", f.value === null ? "not provided" : String(+f.value.toFixed(3))), contrib);
    return tr;
  }) : [(() => { const tr = el("tr"); const td = el("td", "help", "The backend returned no feature contributions."); td.colSpan = 3; tr.append(td); return tr; })()]));
  $("r-model-meta").textContent = m.available ? `Model ${m.version ?? "version not provided"} · ${m.calibration ?? "calibration not provided"} calibration.`
    : `Model unavailable${m.error ? ` (${m.error})` : ""}.`;
}

function render(r, id) {
  document.title = `WebGuard AI — ${r.host || "report"}`;
  const t = new Date(r.collectedAt);
  $("r-time").textContent = Number.isNaN(t.getTime()) ? `Assessed: ${r.collectedAt || "not provided"}` : `Assessed ${t.toLocaleString()}`;
  $("r-id").textContent = id;
  $("r-api").textContent = r.apiVersion;
  $("r-status").className = `status-pill cat-${r.category}`;
  $("r-status-text").textContent = `Assessment complete · ${r.label}`;

  $("r-host").textContent = r.host || "Unknown host";
  $("r-url").textContent = r.url;
  renderGauge($("gauge"), { score: r.riskScore, category: r.category, bands: r.bands });
  $("gauge-label").textContent = r.riskScore === null ? `No risk score: ${r.label}` : `Risk score ${r.riskScore} out of 100: ${r.label}`;
  $("r-score").textContent = r.riskScore === null ? "–" : String(r.riskScore);
  $("r-badge").className = `cat-label cat-${r.category}`;
  $("r-badge").textContent = r.label;
  $("r-note").textContent = r.note;
  $("r-confidence").textContent = r.confidence;
  $("r-basis").textContent = r.basis || "not provided";

  for (const span of document.querySelectorAll(".m-icon")) span.replaceChildren(icon(span.dataset.icon));
  $("m-score").textContent = r.riskScore === null ? "–" : String(r.riskScore);
  $("m-score-card").className = `metric cat-${r.category}`;
  $("m-category").textContent = r.label;
  $("m-category-card").className = `metric cat-${r.category}`;
  for (const k of ["triggered", "passed", "unavailable"]) $(`m-${k}`).textContent = String(r.ruleCounts[k]);
  $("m-triggered-sub").textContent = `of ${r.rules.length} rules`;

  renderFlow(r);
  renderRules(r);
  renderModel(r.model);
  $("r-reco").replaceChildren(...r.recommendations.map((x) => el("li", "", x)));
  const unchecked = r.sources.filter((s) => !s.checked).map((s) => s.source);
  $("r-limits").replaceChildren(...[
    "Only the address was assessed. Page content, links on the page, forms and scripts were not downloaded or analysed.",
    ...(unchecked.length ? [`Not checked in this assessment: ${unchecked.join(", ")}. A listing there could have been missed.`] : []),
    ...r.limitations,
    "The model reads the host name only (trained on PhiUSIIL); it misses many phishing hosts and often over-flags legitimate hosts with a subdomain.",
    "Reputation lists lag behind new phishing sites. Rule and feature details are limited to what the API returns.",
  ].map((x) => el("li", "", x)));
  $("r-disclaimer").textContent = r.disclaimer;
  $("loading").hidden = true;
  $("report").hidden = false;
}

const id = new URLSearchParams(location.search).get("id") ?? "";
const rec = id ? (await chrome.storage.session.get(idKey(id)))[idKey(id)] : null;
const data = rec?.state === "done" ? rec.result : null;
if (!data || validateResponse(data).length) {
  $("loading").hidden = true;
  $("r-status-text").textContent = "No assessment";
  if (data) $("missing-text").textContent = "The stored assessment was not in the expected format, so no report is shown.";
  $("missing").hidden = false;
} else {
  render(buildReport(data), await assessmentId(data));
}
