import assert from "node:assert/strict";
import { test } from "node:test";
import { consumerModel, safeAddress, MESSAGES, tone } from "../consumer.js";
const response = (category = "low_risk", patch = {}) => ({
  assessment: { category, risk_score: category === "unknown" ? 50 : 17 },
  evidence: {
    host: "example.org",
    url: "https://example.org/?token=private",
    collected_at: "2026-11-10T10:00:00Z",
    model: { available: true },
    rules: [{ rule_id: "NO_HTTPS", status: "not_fired" }],
    threat_intel: [{ source: "PhishTank", status: "no_match" }],
    ...patch,
  },
});
for (const category of Object.keys(MESSAGES))
  test(`consumer guidance: ${category}`, () => {
    const v = consumerModel(response(category));
    assert.ok(v.headline && v.action && v.steps.length);
    assert.equal(v.score, category === "unknown" ? null : 17);
    assert.doesNotMatch(v.action, /guaranteed|is safe|blocks/i);
  });
test("missing evidence is never presented as passed", () => {
  const v = consumerModel(
    response("unknown", {
      model: { available: false },
      rules: [],
      threat_intel: [],
    }),
  );
  assert.deepEqual(
    v.areas.map((a) => a.status),
    ["Not assessed", "Unavailable", "Unavailable", "Unavailable"],
  );
  assert.equal(v.partial, true);
  assert.equal(v.coverage, "No reputation sources available");
});
test("partly checked and unverified sources remain distinct", () => {
  const v = consumerModel(
    response("caution", {
      threat_intel: [
        { source: "A", status: "no_match" },
        { source: "B", status: "error" },
      ],
    }),
  );
  assert.equal(v.reputation, "Partly checked");
  assert.equal(v.coverage, "1 of 2 sources checked");
  assert.equal(v.partial, true);
  assert.equal(v.sources.length, 1);
  assert.equal(v.sources[0].name, "A"); // unavailable providers stay in diagnostics, not consumer rows
  const u = consumerModel(
    response("caution", {
      threat_intel: [{ source: "A", status: "unverified" }],
    }),
  );
  assert.equal(u.reputation, "Unverified report");
  assert.match(u.sources[0].text, /not verified/);
});
test("confirmed listings and fired address checks are warnings", () => {
  const v = consumerModel(
    response("dangerous", {
      threat_intel: [{ source: "A", status: "match" }],
      rules: [{ rule_id: "BRAND_IN_PATH", status: "fired" }],
    }),
  );
  assert.equal(v.reputation, "Warning found");
  assert.equal(v.areas[0].status, "Warning found");
});
test("displayed address hides query tokens and never makes an unsafe link", () => {
  assert.equal(
    safeAddress("https://example.org/a?token=private#x"),
    "example.org/a",
  );
  assert.equal(safeAddress("javascript:alert(1)"), "Address unavailable");
});
test("not evaluated address conditions remain incomplete", () => {
  const v = consumerModel(
    response("low_risk", {
      rules: [{ rule_id: "X", status: "not_evaluated" }],
    }),
  );
  assert.equal(v.areas[0].status, "Partly assessed");
  assert.equal(v.partial, true);
});
const domResponse = (state, fired = []) =>
  response("low_risk", {
    dom: {
      schema_version: "dom-v1",
      state,
      rules: [
        ["DOM_PASSWORD_HTTP", "high"],
        ["DOM_CROSS_SITE_FORM", "info"],
        ["DOM_HIDDEN_PASSWORD", "info"],
      ].map(([rule_id, severity]) => ({
        rule_id,
        severity,
        status: fired.includes(rule_id) ? "fired" : "not_fired",
      })),
    },
  });
test("page-structure status never presents missing or partial inspection as passed", () => {
  assert.equal(consumerModel(response()).domStatus, "Not inspected");
  for (const state of ["unavailable", "failed", "incompatible"])
    assert.equal(consumerModel(domResponse(state)).domStatus, "Unavailable");
  assert.equal(consumerModel(domResponse("partial")).domStatus, "Partly checked");
  assert.equal(consumerModel(domResponse("inspected")).domStatus, "No strong warning found");
  assert.equal(
    consumerModel(domResponse("partial", ["DOM_PASSWORD_HTTP"])).domStatus,
    "Warning found",
  );
});
test("legitimate external sign-in is a neutral note, not a warning; hidden fields add nothing", () => {
  const v = consumerModel(
    domResponse("inspected", ["DOM_CROSS_SITE_FORM", "DOM_HIDDEN_PASSWORD"]),
  );
  assert.deepEqual(v.domWarnings, []);
  assert.equal(v.domStatus, "No strong warning found");
  assert.equal(v.domNotes.length, 1);
  assert.match(v.domNotes[0], /common for legitimate/);
  assert.deepEqual(consumerModel(domResponse("unavailable", ["DOM_CROSS_SITE_FORM"])).domNotes, []);
});
test("status tone carries meaning by shape: clear, warning, unavailable", () => {
  for (const s of ["No warning found", "No listing found", "No strong warning found", "Low risk", "Assessed"])
    assert.equal(tone(s), "ok", s);
  for (const s of ["Warning found", "Unverified report", "High risk", "Dangerous", "Caution"])
    assert.equal(tone(s), "warn", s);
  for (const s of ["Unavailable", "Partly checked", "Partly assessed", "Not inspected", "Not assessed"])
    assert.equal(tone(s), "muted", s);
});

test("obsolete classifier metadata cannot produce a structural warning", () => {
  const v = consumerModel(response("low_risk", {dom: {state: "inspected", rules: [],
    model: {available: true, enabled: true, risk_signal: "high"}}}));
  assert.equal(v.domShort, "Page structure inspected.");
  assert.deepEqual(v.domWarnings, []);
  assert.equal(v.domStatus, "No strong warning found");
});
const card = (f, key) => f.find((c) => c.key === key);
test("report findings: confirmed listing first, then the most severe specific finding; extra warnings are kept", async () => {
  const { findings } = await import("../consumer.js");
  const f = findings(response("dangerous", {
    rules: [
      { rule_id: "NO_HTTPS", status: "fired", severity: "low", title: "Connection is not encrypted" },
      { rule_id: "BRAND_IN_HOST_MISMATCH", status: "fired", severity: "high", title: "Suspected brand impersonation" },
      { rule_id: "TI_PHISHTANK_VERIFIED", status: "fired", severity: "critical", title: "Verified phishing listing (PhishTank)" },
    ],
    threat_intel: [{ source: "PhishTank", status: "match" }, { source: "URLhaus", status: "no_match" }],
    dom: { state: "inspected", rules: [
      { rule_id: "DOM_CREDENTIAL_REDIRECT", status: "fired", severity: "medium" },
      { rule_id: "DOM_PASSWORD_HTTP", status: "fired", severity: "high" }] },
  }));
  assert.deepEqual(f.map((c) => [c.key, c.status, c.tone]), [
    ["reputation", "Known threat identified", "warn"],
    ["address", "Suspected brand impersonation", "warn"], // highest severity, not first in the list
    ["page", "Suspicious form detected", "warn"]]);
  assert.deepEqual(card(f, "address").more, ["Connection is not encrypted."]);
  assert.match(card(f, "page").text, /insecurely/);
  assert.equal(card(f, "page").more.length, 1);
});
test("report findings: checks that did not run are named as not performed, never as clear", async () => {
  const { findings } = await import("../consumer.js");
  const f = findings(response("unknown", { model: { available: false }, rules: [], threat_intel: [{ source: "PhishTank", status: "error" }] }));
  assert.deepEqual(f.map((c) => [c.status, c.tone]).sort(),
    [["Address not analyzed", "none"], ["Page inspection not performed", "none"], ["Reputation not available", "none"]]);
  assert.doesNotMatch(card(f, "page").text, /based on the website address/); // the address was not analysed either
  for (const state of ["unavailable", "failed", "incompatible", "not_requested"])
    assert.deepEqual([card(findings(response("low_risk", { dom: { state, rules: [] } })), "page").status],
      ["Page inspection not performed"], state);
  // Partial inspection: no warning in what was read, and the wording says only that.
  const partial = card(findings(response("low_risk", { dom: { state: "partial", rules: [] } })), "page");
  assert.deepEqual([partial.status, partial.tone], ["No page warnings found", "ok"]);
  assert.match(partial.text, /parts of the page/);
  const inspected = card(findings(response("low_risk", { dom: { state: "inspected", rules: [] } })), "page");
  assert.equal(inspected.status, "Website structure analyzed");
});
test("report findings: no provider counts or names; a missed listing is never proof of safety", async () => {
  const { findings } = await import("../consumer.js");
  const sources = [{ source: "PhishTank", status: "no_match" }, { source: "URLhaus", status: "not_configured" }];
  const all = findings(response("low_risk", { threat_intel: sources, dom: { state: "inspected", rules: [] } }));
  const rep = card(all, "reputation");
  assert.equal(rep.status, "No known threat listing");
  assert.match(rep.text, /may not be listed/);
  for (const c of all) assert.doesNotMatch(c.status + c.text, /\d+ of \d+|PhishTank|URLhaus|configured|partly|\bsafe\b/i);
  assert.equal(card(findings(response("caution", { threat_intel: [{ source: "PhishTank", status: "unverified" }] })), "reputation").status,
    "Unconfirmed threat report");
});
test("report findings: info notes are not warnings; a raised score without warnings is attributed to the address pattern only", async () => {
  const { findings } = await import("../consumer.js");
  const info = { rules: [{ rule_id: "SHARED_HOSTING_PLATFORM", status: "fired", severity: "info", title: "Hosted on a shared/free platform" }] };
  const low = card(findings(response("low_risk", info)), "address");
  assert.deepEqual([low.status, low.tone, low.text], ["No strong address warnings", "ok", "Worth knowing: hosted on a shared/free platform."]);
  const caution = card(findings(response("caution", info)), "address");
  assert.deepEqual([caution.status, caution.tone], ["Unusual patterns detected", "warn"]);
  // No pattern claim without the model.
  assert.notEqual(card(findings(response("caution", { ...info, model: { available: false } })), "address").status, "Unusual patterns detected");
});
