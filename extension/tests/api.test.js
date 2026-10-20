// MOCKED tests (no browser, no backend): node --test extension/tests/
import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze, prepareUrl, validateResponse, viewModel } from "../api.js";

const response = (category, extra = {}) => ({
  api_version: "1.0",
  assessment: { risk_score: { dangerous: 95, high_risk: 70, caution: 45, low_risk: 10, unknown: 50 }[category],
    safety_score: category === "unknown" ? null : 30, category, confidence: "low", decision_basis: "x",
    notes: ["URLhaus not checked: not_configured"] },
  evidence: { url: "https://a.example.com/", host: "a.example.com", registered_domain: "example.com", collected_at: "t",
    model: { available: true, probability: 0.4321 },
    threat_intel: [{ source: "PhishTank", status: "no_match", detail: "" }, { source: "URLhaus", status: "not_configured", detail: "set key" },
      { source: "OpenPhish (local snapshot)", status: "match", detail: "exact URL listed" }, { source: "Google Safe Browsing", status: "unverified" }],
    rules: [{ rule_id: "NO_HTTPS", status: "fired", severity: "low", title: "t1", explanation: "e1" },
      { rule_id: "BRAND_IN_HOST_MISMATCH", status: "fired", severity: "high", title: "t2", explanation: "e2" },
      { rule_id: "IP_ADDRESS_HOST", status: "not_fired", severity: "medium", title: "t3", explanation: "" }],
    errors: [] },
  disclaimer: "… not proof that a site is safe.", ...extra,
});
const fakeFetch = (status, body) => async () => ({ status, ok: status >= 200 && status < 300, json: async () => body });

test("prepareUrl accepts http(s), drops the fragment, hides the query in the display", () => {
  const p = prepareUrl("https://Shop.Example.com/a/b?token=secret#frag");
  assert.equal(p.ok, true);
  assert.equal(p.url, "https://shop.example.com/a/b?token=secret");
  assert.equal(p.display, "shop.example.com/a/b");
});

for (const bad of ["chrome://extensions", "file:///C:/x.html", "about:blank", "edge://settings", "javascript:alert(1)", "", "not a url", undefined]) {
  test(`prepareUrl rejects ${bad}`, () => assert.equal(prepareUrl(bad).ok, false));
}

test("prepareUrl rejects over-long URLs", () => assert.equal(prepareUrl("https://a.com/" + "x".repeat(2100)).ok, false));

for (const cat of ["dangerous", "high_risk", "caution", "low_risk", "unknown"]) {
  test(`renders category ${cat} without claiming safety`, () => {
    const v = viewModel(response(cat));
    assert.equal(v.category, cat);
    assert.ok(v.label && v.note);
    // "safe" may only appear inside the required disclaimer "not proof that the site is safe"
    assert.doesNotMatch(`${v.label} ${v.note}`, /(?<!not proof that the site )\bis safe\b|\bsafe site\b/i);
    if (cat === "unknown") assert.equal(v.safetyScore, "–");
    if (cat === "caution") assert.match(v.note, /not proof that the site is malicious/);
    if (cat === "low_risk") assert.match(v.note, /not proof that the site is safe/);
  });
}

test("threat-intelligence statuses map to Matched / Not listed / Unverified / Not checked", () => {
  const v = viewModel(response("dangerous"));
  assert.deepEqual(v.threatIntel.map((t) => t.status), ["Not listed", "Not checked", "Matched", "Unverified"]);
});

test("only fired rules are shown, most severe first; model probability stays separate from the score", () => {
  const v = viewModel(response("caution"));
  assert.deepEqual(v.rules.map((r) => r.severity), ["high", "low"]);
  assert.equal(v.modelProbability, "0.43");
  assert.equal(v.riskScore, 45);
});

test("analyze: valid response", async () => {
  const r = await analyze("https://a.example.com/", { fetchImpl: fakeFetch(200, response("low_risk")) });
  assert.equal(r.ok, true);
});

test("analyze: 422 is an invalid-URL error with the backend's message", async () => {
  const r = await analyze("https://a/", { fetchImpl: fakeFetch(422, { detail: "Unsupported scheme" }) });
  assert.deepEqual([r.ok, r.kind], [false, "invalid_url"]);
  assert.match(r.message, /Unsupported scheme/);
  const list = await analyze("https://a/", { fetchImpl: fakeFetch(422, { detail: [{ loc: ["body", "url"] }] }) });
  assert.equal(list.kind, "invalid_url");
});

test("analyze: backend unreachable", async () => {
  const r = await analyze("https://a/", { fetchImpl: async () => { throw new TypeError("Failed to fetch"); } });
  assert.deepEqual([r.ok, r.kind], [false, "unreachable"]);
});

test("analyze: timeout aborts the request", async () => {
  const hang = (_u, { signal }) => new Promise((_res, rej) => signal.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))));
  const r = await analyze("https://a/", { fetchImpl: hang, timeoutMs: 20 });
  assert.deepEqual([r.ok, r.kind], [false, "timeout"]);
});

test("analyze: HTTP 500 and malformed bodies are errors, never a result", async () => {
  assert.equal((await analyze("x", { fetchImpl: fakeFetch(500, null) })).kind, "http_error");
  for (const body of [null, "text", {}, { ...response("caution"), api_version: "2.0" },
    response("safe"), { ...response("caution"), evidence: { ...response("caution").evidence, threat_intel: [{ source: "X", status: "clean" }] } }]) {
    const r = await analyze("x", { fetchImpl: fakeFetch(200, body) });
    assert.deepEqual([r.ok, r.kind], [false, "bad_response"], JSON.stringify(body)?.slice(0, 60));
  }
  const badJson = async () => ({ status: 200, ok: true, json: async () => { throw new SyntaxError("x"); } });
  assert.equal((await analyze("x", { fetchImpl: badJson })).kind, "bad_response");
});

test("validateResponse accepts the documented contract", () => assert.deepEqual(validateResponse(response("high_risk")), []));
