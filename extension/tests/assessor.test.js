// MOCKED tests for the freshness policy and record store (assessor.js) and the segmented gauge geometry (gauge.js).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ERROR_RETRY_MS, FRESH_MS, MAX_RECORDS, PENDING_MAX_MS, createAssessor, isUsable } from "../assessor.js";
import { gaugeGeometry } from "../gauge.js";
import { apiResponse } from "./fixtures.js";

function storage() {
  const s = {};
  return { s, get: async (k) => (k === null ? { ...s } : k in s ? { [k]: s[k] } : {}), set: async (o) => { Object.assign(s, o); },
    remove: async (ks) => { for (const k of ks) delete s[k]; } };
}

test("freshness policy: results 10 min, errors 30 s, pending 25 s", () => {
  assert.equal(FRESH_MS, 600000); assert.equal(ERROR_RETRY_MS, 30000); assert.equal(PENDING_MAX_MS, 25000);
  assert.ok(isUsable({ state: "done", finishedAt: 0 }, FRESH_MS - 1));
  assert.ok(!isUsable({ state: "done", finishedAt: 0 }, FRESH_MS));
  assert.ok(!isUsable({ state: "error", finishedAt: 0 }, ERROR_RETRY_MS));
  assert.ok(isUsable({ state: "pending", startedAt: 0 }, PENDING_MAX_MS - 1));
  assert.ok(!isUsable({ state: "pending", startedAt: 0 }, PENDING_MAX_MS));
  assert.ok(!isUsable(null, 0));
});

test("stale results are re-assessed; force re-assesses at once; fresh ones are reused", async () => {
  let t = 0, calls = 0, ids = 0;
  const a = createAssessor({ storage: storage(), now: () => t, newId: () => `id${++ids}`,
    analyzeFn: async (u) => { calls++; return { ok: true, data: apiResponse("low_risk", u) }; } });
  await a.ensure(1, "https://a.example/");
  t = FRESH_MS - 1; await a.ensure(1, "https://a.example/");
  assert.equal(calls, 1);
  await a.ensure(1, "https://a.example/", { force: true });
  assert.equal(calls, 2);
  t += FRESH_MS; await a.ensure(1, "https://a.example/");
  assert.equal(calls, 3);
});

test("each finished assessment is stored under its own id for the report; old ones are pruned", async () => {
  const st = storage();
  let ids = 0, t = 0;
  const a = createAssessor({ storage: st, now: () => ++t, newId: () => `id${++ids}`, analyzeFn: async (u) => ({ ok: true, data: apiResponse("low_risk", u) }) });
  for (let i = 0; i < MAX_RECORDS + 5; i++) await a.ensure(1, `https://s${i}.example/`);
  const kept = Object.keys(st.s).filter((k) => k.startsWith("a:"));
  assert.equal(kept.length, MAX_RECORDS);
  assert.ok(!("a:id1" in st.s) && !("u:https://s0.example/" in st.s));
  assert.equal(st.s[`a:id${MAX_RECORDS + 5}`].result.evidence.url, `https://s${MAX_RECORDS + 4}.example/`);
});

test("gauge: bands follow the backend's score bands, the marker sits on the score, no score means no marker", () => {
  const bands = { alert: 37, high: 57, dangerous: 95 };
  const g = gaugeGeometry({ score: 50, category: "caution", bands });
  assert.deepEqual(g.segments.map((s) => [s.category, s.from, s.to, s.active]),
    [["low_risk", 0, 37, false], ["caution", 37, 57, true], ["high_risk", 57, 95, false], ["dangerous", 95, 100, false]]);
  assert.deepEqual(g.marker, { x: 120, y: 22 }); // top of the arc
  assert.deepEqual(gaugeGeometry({ score: 0, category: "low_risk", bands }).marker, { x: 24, y: 118 });
  assert.deepEqual(gaugeGeometry({ score: 100, category: "dangerous", bands }).marker, { x: 216, y: 118 });
  assert.equal(gaugeGeometry({ score: null, category: "unknown", bands }).marker, null);
  assert.deepEqual(g.ticks.map((t) => t.value), [37, 57]);
});

test("permissions stay minimal: automatic mode is an opt-in; nothing is injected into pages", () => {
  const m = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url), "utf8"));
  assert.deepEqual(m.permissions, ["activeTab", "storage"]);
  assert.deepEqual(m.optional_permissions, ["tabs", "notifications"]);
  assert.deepEqual(m.host_permissions, ["http://127.0.0.1:8000/*"]);
  assert.equal(m.content_scripts, undefined);
  assert.ok(!JSON.stringify(m).includes("scripting") && !JSON.stringify(m).includes("<all_urls>"));
  for (const f of ["popup.js", "background.js", "assessor.js", "report.js", "gauge.js", "api.js", "report_model.js"]) {
    const src = readFileSync(new URL(`../${f}`, import.meta.url), "utf8");
    assert.ok(!/chrome\.scripting|executeScript|\.innerHTML\s*=|insertAdjacentHTML|\beval\(/.test(src), f);
  }
});

test("popup: no manual address checker, required elements present, no text below 12 px", () => {
  const html = readFileSync(new URL("../popup.html", import.meta.url), "utf8");
  assert.ok(!/<input|<form|Check another address/.test(html));
  for (const id of ["host", "gauge", "risk", "badge", "note", "open-report", "retry", "auto"]) assert.match(html, new RegExp(`id="${id}"`));
  for (const f of ["popup.css", "theme.css", "report.css"]) {
    const sizes = [...readFileSync(new URL(`../${f}`, import.meta.url), "utf8").matchAll(/font-size:\s*([\d.]+)px/g)].map((x) => Number(x[1]));
    assert.ok(sizes.every((s) => s >= 12), `${f}: ${sizes}`);
  }
});
