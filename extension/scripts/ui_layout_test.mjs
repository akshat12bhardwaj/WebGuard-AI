// Responsive/alignment verification in real Chrome. Records are UI fixtures derived from one real backend response
// (category/score overridden to exercise every layout); they are not detection results.
// Usage: node ui_layout_test.mjs <chrome.exe> <extensionDir> <outDir> [backendPort=8001]
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { startChrome, sleep, until } from "./chrome_driver.mjs";

const [exe, source, output, port = "8001"] = process.argv.slice(2),
  out = resolve(output);
mkdirSync(out, { recursive: true });
const temp = mkdtempSync(join(tmpdir(), "webguard-ui-")),
  ext = join(temp, "extension");
cpSync(source, ext, { recursive: true, filter: (p) => !p.includes("node_modules") });
for (const name of ["manifest.json", "api.js"]) {
  const path = join(ext, name);
  writeFileSync(path, readFileSync(path, "utf8").replaceAll("127.0.0.1:8000", `127.0.0.1:${port}`));
}

// Real hybrid response: insecure + cross-site password forms on a long hostname.
const origin = "http://customer-support-and-account-recovery.example-services.test";
const form = (o, scheme) => ({ action_origin: o, action_scheme: scheme, method: "post", password_count: 1,
  hidden_password_count: 0, has_action: true, action_same_page: false });
const features = { form_count: 2, password_count: 2, orphan_password_count: 0, hidden_password_count: 0,
  credential_forms: [form(origin, "http"), form("https://accounts.example.org", "https")],
  link_count: 0, placeholder_link_count: 0, unusual_link_count: 0, link_origins: [], iframe_count: 0,
  inaccessible_frame_count: 0, iframe_origins: [], accessible_frame_form_count: 0, script_count: 0,
  resource_count: 0, resource_origins: [], title_present: true, title_length: 10, title_has_host: false,
  meta_refresh: [], truncated: false };
const response = await fetch(`http://127.0.0.1:${port}/api/v1/analyze`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ url: origin + "/account/sign-in", dom: { schema_version: "dom-v1", state: "inspected", page_origin: origin, features } }),
});
const real = await response.json();
assert.equal(response.status, 200, JSON.stringify(real));
assert.ok(real.evidence.dom.rules.some((r) => r.rule_id === "DOM_PASSWORD_HTTP" && r.status === "fired"));

const SCORES = { low_risk: 17, caution: 51, high_risk: 76, dangerous: 95, unknown: 50 };
const fixture = (cat, extra = {}) => {
  const r = structuredClone(real);
  r.assessment.category = cat;
  r.assessment.risk_score = SCORES[cat];
  r.assessment.safety_score = cat === "unknown" ? null : 100 - SCORES[cat];
  const id = extra.id || "ui-" + cat;
  r.evidence.url = `${origin}/${id}`; // distinct URL per fixture, so the popup's URL cache shows this record
  return { id, state: "done", scope: "url", url: r.evidence.url, host: r.evidence.host,
    startedAt: Date.now(), finishedAt: Date.now(), result: r, ...extra };
};

// Geometry audit run inside the page: overflow, icon/text overlap, unintended clipping.
const AUDIT = `(() => {
  const vis = (e) => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none"; };
  const hit = (a, b) => a.left < b.right - 0.5 && b.left < a.right - 0.5 && a.top < b.bottom - 0.5 && b.top < a.bottom - 0.5;
  const problems = [];
  if (document.documentElement.scrollWidth > innerWidth) problems.push("horizontal overflow " + document.documentElement.scrollWidth);
  for (const icon of document.querySelectorAll("[data-icon], .risk-symbol, .card-icon")) {
    if (!vis(icon)) continue;
    const ir = icon.getBoundingClientRect();
    for (const sib of icon.parentElement.children) {
      if (sib === icon || !vis(sib) || !sib.textContent.trim()) continue;
      if (hit(ir, sib.getBoundingClientRect())) problems.push("icon overlaps text: " + (sib.id || sib.className || sib.tagName) + " '" + sib.textContent.trim().slice(0, 30) + "'");
    }
    if (ir.right > innerWidth + 0.5 || ir.left < -0.5) problems.push("icon outside viewport");
  }
  const allowedClip = (e) => e.matches(".host, .url"); // deliberate: hostname ellipsis (full name in title), scrollable URL
  if (location.pathname.endsWith("popup.html"))
    for (const e of document.querySelectorAll("body *"))
      if (vis(e) && [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim()) && parseFloat(getComputedStyle(e).fontSize) < 12)
        problems.push("type below 12px: " + (e.id || e.className));
  for (const e of document.querySelectorAll("h1,h2,h3,p,li,button,a,.card-status,#r-label,.category")) {
    if (!vis(e) || allowedClip(e)) continue;
    if (e.scrollWidth > e.clientWidth + 1 && getComputedStyle(e).overflowX !== "visible") problems.push("clipped: " + (e.id || e.className || e.tagName));
    const r = e.getBoundingClientRect();
    if (r.right > innerWidth + 0.5) problems.push("beyond viewport: " + (e.id || e.className || e.tagName) + " " + Math.round(r.right));
  }
  const btn = [...document.querySelectorAll("button, a")].filter(vis).filter((b) => b.closest("main,header,footer") && b.getBoundingClientRect().height < 24 && !b.closest(".skip"));
  for (const b of btn) problems.push("small target: " + (b.id || b.textContent.trim().slice(0, 20)));
  return problems;
})()`;

const driver = startChrome(exe, join(temp, "profile")),
  results = { report: [], popup: [] };
try {
  await sleep(1000);
  results.chrome = (await driver.send("Browser.getVersion")).product;
  const { id } = await driver.send("Extensions.loadUnpacked", { path: ext });
  const base = `chrome-extension://${id}`;
  const helper = await driver.open(base + "/report.html", 800, 600);
  await until(() => helper.ev("document.readyState==='complete'"), "helper");
  const records = Object.fromEntries(Object.keys(SCORES).map((c) => [c, fixture(c)]));
  records.page = fixture("high_risk", { id: "ui-page", scope: "page", sourceTabId: 1 });
  await helper.ev(`chrome.storage.session.set(${JSON.stringify(Object.fromEntries(
    Object.values(records).flatMap((r) => [["a:" + r.id, r], ["u:" + r.url, r]])))}).then(()=>true)`);

  for (const width of [1440, 1280, 1024, 768, 390, 320]) {
    for (const cat of ["page", "dangerous", "low_risk"]) {
      if (cat !== "page" && ![1440, 390, 320].includes(width)) continue;
      const p = await driver.open(`${base}/report.html?id=ui-${cat === "page" ? "page" : cat}`, width, 900);
      await until(() => p.ev("!document.getElementById('report').hidden"), "report " + width);
      await sleep(700);
      const problems = await p.ev(AUDIT);
      results.report.push({ width, cat, problems, errors: p.errors() });
      if (cat === "page") await p.shot(join(out, `report_${width}.png`), true);
      else if (width !== 1440) await p.shot(join(out, `report_${cat}_${width}.png`), true);
      await driver.send("Target.closeTarget", { targetId: p.targetId });
    }
  }
  // Single-screen report: every state fits the target desktop viewports without vertical scrolling.
  results.oneScreen = [];
  for (const [width, height] of [[1920, 1080], [1440, 900], [1366, 768], [1280, 720]])
    for (const cat of ["page", ...Object.keys(SCORES)]) {
      const p = await driver.open(`${base}/report.html?id=ui-${cat}`, width, height);
      await until(() => p.ev("!document.getElementById('report').hidden"), "report " + width);
      await sleep(500);
      const fit = await p.ev("({scroll:document.documentElement.scrollHeight,view:innerHeight})");
      const problems = await p.ev(AUDIT);
      results.oneScreen.push({ width, height, cat, ...fit });
      results.report.push({ width, height, cat, problems, errors: p.errors() });
      if (cat === "page") await p.shot(join(out, `report_onescreen_${width}x${height}.png`));
      await driver.send("Target.closeTarget", { targetId: p.targetId });
    }
  for (const r of results.oneScreen) assert.ok(r.scroll <= r.view, "report scrolls: " + JSON.stringify(r));
  for (const cat of Object.keys(SCORES))
    for (const [dpr, height] of [[1, 600], [1.5, 600], [1, 400]]) {
      const p = await driver.open(`${base}/popup.html?url=${encodeURIComponent(records[cat].url)}`, 360, height);
      await driver.send("Emulation.setDeviceMetricsOverride", { width: 360, height, deviceScaleFactor: dpr, mobile: false }, p.sessionId);
      await until(() => p.ev("document.getElementById('gauge-box')?.dataset.state==='done'"), "popup " + cat);
      await sleep(1200);
      const problems = await p.ev(AUDIT);
      const fit = await p.ev("({vertical:document.documentElement.scrollHeight>innerHeight,body:Math.round(document.body.getBoundingClientRect().height)})");
      results.popup.push({ cat, dpr, height, ...fit, problems, errors: p.errors() });
      if (height === 600) await p.shot(join(out, `popup_settled_${cat}${dpr > 1 ? "_dpr15" : ""}.png`));
      await driver.send("Target.closeTarget", { targetId: p.targetId });
    }
  for (const r of [...results.report, ...results.popup]) {
    assert.deepEqual(r.problems, [], JSON.stringify(r));
    assert.deepEqual(r.errors, [], JSON.stringify(r));
  }
  for (const r of results.popup) assert.equal(r.vertical, false, JSON.stringify(r));
  results.assertions = "No overflow, icon/text overlap, clipping or console errors at any tested width/state; reports fit one screen at 1920×1080, 1440×900, 1366×768 and 1280×720.";
} catch (error) {
  results.error = error.stack;
  process.exitCode = 1;
} finally {
  driver.close();
  writeFileSync(join(out, "ui-layout-results.json"), JSON.stringify(results, null, 2));
  console.log(JSON.stringify({ chrome: results.chrome, assertions: results.assertions, error: results.error?.slice(0, 1500) }, null, 2));
}
