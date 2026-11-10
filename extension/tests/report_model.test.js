// MOCKED tests for the detailed-report view model (report_model.js). node --test extension/tests/
import assert from "node:assert/strict";
import { test } from "node:test";
import { validateResponse } from "../api.js";
import { RULE_CHECKS, buildReport } from "../report_model.js";

const rule = (rule_id, status, severity = "low", explanation = "") => ({ rule_id, status, severity, title: `T ${rule_id}`, explanation });
const response = (over = {}) => ({
  api_version: "1.0",
  assessment: { risk_score: 62, safety_score: 38, category: "high_risk", confidence: "medium", decision_basis: "Rule engine",
    notes: ["URLhaus not checked: not_configured"], ...over.assessment },
  evidence: {
    url: "http://paypal-login.example.com:8080/x", host: "paypal-login.example.com", registered_domain: "example.com",
    collected_at: "2026-10-20T10:00:00+00:00",
    model: { available: true, probability: 0.41, thresholds: { alert: 0.3662, high: 0.5671, rule: "r" }, calibration: "isotonic",
      model_version: "host-v1", out_of_training_range: [], top_shap: [{ feature: "subdomain_count", value: 1, shap_log_odds: 1.25 },
        { feature: "tld_length", value: 3, shap_log_odds: -0.2 }] },
    threat_intel: [{ source: "PhishTank", status: "unverified", detail: "reported, not verified" },
      { source: "URLhaus", status: "not_configured", detail: "set URLHAUS_AUTH_KEY" }],
    rules: [rule("TI_PHISHTANK_VERIFIED", "not_fired", "critical"), rule("TI_URLHAUS_LISTED", "not_evaluated", "critical", "URLhaus was not checked (not_configured)"),
      rule("BRAND_IN_HOST_MISMATCH", "fired", "high", "The registered name contains 'paypal'."), rule("NO_HTTPS", "not_fired"),
      rule("NONSTANDARD_PORT", "fired", "low", "The address uses port 8080."), rule("VERY_LONG_URL", "not_fired"), rule("NEW_RULE_X", "not_evaluated", "info")],
    errors: [], ...over.evidence },
  disclaimer: "Not proof that a site is safe.",
});

test("fixture matches the API contract", () => assert.deepEqual(validateResponse(response()), []));

test("rule states come only from each rule's own status: triggered, passed, unavailable, not evaluated", () => {
  const r = buildReport(response());
  const state = Object.fromEntries(r.rules.map((x) => [x.id, x.state]));
  assert.deepEqual(state, { BRAND_IN_HOST_MISMATCH: "triggered", NONSTANDARD_PORT: "triggered", TI_URLHAUS_LISTED: "unavailable",
    NEW_RULE_X: "not_evaluated", TI_PHISHTANK_VERIFIED: "passed", NO_HTTPS: "passed", VERY_LONG_URL: "passed" });
  assert.deepEqual(r.ruleCounts, { triggered: 2, passed: 3, unavailable: 1, not_evaluated: 1 });
  assert.equal(r.rules[0].id, "BRAND_IN_HOST_MISMATCH"); // triggered first, most severe first
});

test("findings use the backend's explanation; passed never claims safety; a checked-but-unverified source says so", () => {
  const by = Object.fromEntries(buildReport(response()).rules.map((x) => [x.id, x]));
  assert.equal(by.BRAND_IN_HOST_MISMATCH.finding, "The registered name contains 'paypal'.");
  assert.match(by.NO_HTTPS.finding, /not found .* not proof of safety/i);
  assert.match(by.TI_PHISHTANK_VERIFIED.finding, /PhishTank was checked .*status: unverified/);
  assert.equal(by.TI_URLHAUS_LISTED.finding, "URLhaus was not checked (not_configured)");
  assert.equal(by.NEW_RULE_X.checks, "No description available for this rule.");
  assert.equal(by.TI_URLHAUS_LISTED.observed, "");
});

test("observed values are derived from the returned URL only, with the real thresholds", () => {
  const by = Object.fromEntries(buildReport(response()).rules.map((x) => [x.id, x]));
  assert.equal(by.VERY_LONG_URL.observed, `Observed: ${"http://paypal-login.example.com:8080/x".length} characters (threshold: more than 200).`);
  assert.equal(by.NONSTANDARD_PORT.observed, "Observed: port 8080.");
  assert.equal(by.NO_HTTPS.observed, "Observed scheme: http.");
});

test("every production rule has a description", () => {
  for (const id of ["TI_PHISHTANK_VERIFIED", "TI_URLHAUS_LISTED", "TI_SAFE_BROWSING_MATCH", "TI_OPENPHISH_LISTED", "URL_CREDENTIALS_IN_AUTHORITY",
    "BRAND_IN_HOST_MISMATCH", "BRAND_IN_SUBDOMAIN", "BRAND_IN_PATH", "IP_ADDRESS_HOST", "HTTP_WITH_CREDENTIAL_WORDS", "NO_HTTPS", "PUNYCODE_HOST",
    "SHARED_HOSTING_PLATFORM", "UNUSUAL_HOST_CHARACTERS", "NONSTANDARD_PORT", "URL_SHORTENER", "VERY_LONG_URL"]) assert.ok(RULE_CHECKS[id], id);
});

test("model section reports real values and the threshold comparison; features only as returned", () => {
  const m = buildReport(response()).model;
  assert.equal(m.probability, 0.41);
  assert.equal(m.level, "at or above the 'alert' threshold, below 'high'");
  assert.deepEqual(m.features.map((f) => [f.name, f.value, f.contribution]), [["subdomain_count", 1, 1.25], ["tld_length", 3, -0.2]]);
});

test("missing evidence is never filled in", () => {
  const r = buildReport(response({ evidence: { model: { available: false, error: "OSError" }, threat_intel: [], rules: [] } }));
  assert.equal(r.model.available, false);
  assert.equal(r.model.probability, null);
  assert.equal(r.model.level, null);
  assert.deepEqual(r.model.features, []);
  assert.deepEqual(r.rules, []);
  assert.deepEqual(r.sources, []);
  assert.equal(r.flow[1].status.label, "Unavailable");
  assert.deepEqual(r.limitations, []);
});

test("pipeline stages report only what the response says, each backend note once", () => {
  const r = buildReport(response());
  assert.deepEqual(r.flow.map((x) => [x.id, x.status.label]),
    [["url", "Submitted"], ["model", "Completed"], ["reputation", "Partly checked"], ["rules", "2 triggered"], ["final", "High risk"]]);
  const model = r.flow[1];
  assert.deepEqual(model.rows, [["Probability", "0.410"], ["Zone", "between alert and high"], ["Thresholds", "alert 0.3662 · high 0.5671"]]);
  assert.equal(r.flow[2].subtitle, "1 of 2 sources checked");
  assert.deepEqual(r.flow[3].rows.map((x) => x[1]), ["2", "3", "1", "1"]);
  assert.deepEqual(r.flow[4].rows, [["Category", "High risk"], ["Risk score", "62 / 100"], ["Confidence", "medium"]]);
  assert.deepEqual(r.caveats, []); // "URLhaus not checked: ..." is a source-status note, shown with the source instead
  const caveat = buildReport(response({ assessment: { notes: ["Model unreliable here (host has a subdomain)", "URLhaus not checked: not_configured"] } }));
  assert.deepEqual(caveat.flow[1].notes, ["Model unreliable here (host has a subdomain)"]);
  assert.ok(r.recommendations.some((x) => /not checked/.test(x)));
});

test("pipeline never shows a stage that did not run as completed", () => {
  const none = buildReport(response({ evidence: { model: { available: false, error: "OSError" }, threat_intel: [], rules: [] } }));
  assert.deepEqual(none.flow.map((x) => x.status.label), ["Submitted", "Unavailable", "None returned", "None returned", "High risk"]);
  assert.deepEqual(none.flow[1].rows, [["Result", "unavailable (OSError)"]]);
  const unchecked = buildReport(response({ evidence: { threat_intel: [{ source: "URLhaus", status: "error", detail: "timeout" }] } }));
  assert.equal(unchecked.flow[2].status.label, "Not checked");
  const listed = buildReport(response({ evidence: { threat_intel: [{ source: "URLhaus", status: "match", detail: "listed" }] } }));
  assert.equal(listed.flow[2].status.label, "Threat found");
  const u = buildReport(response({ assessment: { category: "unknown", risk_score: 50, safety_score: null } }));
  assert.equal(u.riskScore, null);
  assert.equal(u.flow[4].rows[1][1], "– (no score)");
});

test("sources keep their availability; an unconfigured source is never shown as a successful check", () => {
  const s = buildReport(response()).sources;
  assert.deepEqual(s.map((x) => [x.source, x.checked, x.group, x.statusText]),
    [["PhishTank", true, "Unverified", "Checked — reported, not verified"], ["URLhaus", false, "Not checked", "Not checked — not configured"]]);
});

test("score bands follow the model thresholds exactly as the fusion places them; contract bands without them", () => {
  assert.deepEqual(buildReport(response()).bands, { alert: 37, high: 57, dangerous: 95 });
  const r = buildReport(response({ evidence: { model: { available: false } } }));
  assert.deepEqual(r.bands, { alert: 37, high: 57, dangerous: 95 });
});

test("rule counts always add up to the rows", () => {
  const r = buildReport(response());
  assert.equal(Object.values(r.ruleCounts).reduce((x, y) => x + y, 0), r.rules.length);
});
