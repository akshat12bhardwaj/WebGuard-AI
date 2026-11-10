import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { inspectTab, validateSnapshot } from "../dom_inspection.js";
import { createAssessor, pageKey, urlKey } from "../assessor.js";
import { apiResponse } from "./fixtures.js";
const dom = () => ({
  schema_version: "dom-v1",
  state: "inspected",
  page_origin: "https://example.org",
  features: {
    form_count: 0,
    password_count: 0,
    orphan_password_count: 0,
    hidden_password_count: 0,
    credential_forms: [],
    link_count: 0,
    placeholder_link_count: 0,
    unusual_link_count: 0,
    link_origins: [],
    iframe_count: 0,
    inaccessible_frame_count: 0,
    iframe_origins: [],
    accessible_frame_form_count: 0,
    script_count: 0,
    resource_count: 0,
    resource_origins: [],
    title_present: false,
    title_length: 0,
    title_has_host: false,
    meta_refresh: [],
    truncated: false,
  },
});

function fake() {
  let calls = 0;
  const c = {
    tabs: { get: async () => ({ url: "https://example.org/" }) },
    scripting: {
      executeScript: async (opts) => {
        calls++;
        assert.equal(opts.world, "ISOLATED");
        assert.deepEqual(opts.target.frameIds, [0]);
        assert.equal(typeof opts.func, "function");
        return [
          {
            frameId: 0,
            documentId: "doc1",
            result: { snapshot: dom(), navigation_start: 10 },
          },
        ];
      },
    },
    get calls() {
      return calls;
    },
  };
  return c;
}
test("manual DOM executes once in isolated top frame without broad host access", async () => {
  const c = fake(),
    r = await inspectTab(c, 1, "https://example.org/");
  assert.equal(c.calls, 1);
  assert.equal(r.dom.state, "inspected");
  assert.equal(r.documentId, "doc1");
});
test("missing permissions yield URL-only fallback, not successful inspection", async () => {
  const c = fake();
  c.scripting.executeScript = async () => {
    throw new Error("Cannot access page without permission");
  };
  const r = await inspectTab(c, 1, "https://example.org/");
  assert.equal(r.dom.state, "unavailable");
  assert.equal(r.dom.reason, "permission");
});
test("unsupported page never injects", async () => {
  const c = fake();
  assert.equal(
    (await inspectTab(c, 1, "chrome://settings")).dom.state,
    "unavailable",
  );
  assert.equal(c.calls, 0);
});
test("navigation change invalidates extraction", async () => {
  const c = fake();
  let n = 0;
  c.tabs.get = async () => ({
    url: ++n === 1 ? "https://example.org/" : "https://other.org/",
  });
  const r = await inspectTab(c, 1, "https://example.org/");
  assert.equal(r.changed, true);
});
test("extraction timeout is explicit and bounded", async () => {
  const c = fake();
  c.scripting.executeScript = () => new Promise(() => {});
  const r = await inspectTab(c, 1, "https://example.org/", { timeoutMs: 5 });
  assert.equal(r.dom.reason, "timeout");
  assert.equal(r.dom.state, "failed");
});
test("invalid extracted data is rejected before transport", async () => {
  const c = fake();
  c.scripting.executeScript = async () => [
    {
      frameId: 0,
      result: { snapshot: { ...dom(), features: { password_count: -1 } } },
    },
  ];
  assert.equal(
    (await inspectTab(c, 1, "https://example.org/")).dom.reason,
    "schema",
  );
  assert.equal(
    validateSnapshot({
      ...dom(),
      page_origin: "https://example.org/?secret=x",
    }),
    false,
  );
});
test("null structural records are rejected without throwing", () => {
  for (const key of ["credential_forms", "link_origins", "meta_refresh"]) {
    const d = dom();
    d.features[key] = [null];
    assert.equal(validateSnapshot(d), false);
  }
});
function store() {
  const s = {};
  return {
    s,
    get: async (k) => (k === null ? { ...s } : { [k]: s[k] }),
    set: async (o) => Object.assign(s, structuredClone(o)),
    remove: async (keys) => keys.forEach((k) => delete s[k]),
  };
}
test("fresh URL-only cache cannot satisfy page inspection; unchanged DOM joins/reuses and dynamic changes recheck", async () => {
  const st = store();
  let calls = 0,
    n = 0;
  const a = createAssessor({
    storage: st,
    newId: () => String(++n),
    analyzeFn: async (url, opts) => {
      calls++;
      return { ok: true, data: apiResponse("low_risk", url) };
    },
  });
  const url = "https://example.org/";
  await a.ensure(1, url);
  const options = { dom: dom(), documentId: "d1", navigationStart: 1 };
  await Promise.all([a.ensure(1, url, options), a.ensure(1, url, options)]);
  assert.equal(calls, 2);
  await a.ensure(1, url, options);
  assert.equal(calls, 2);
  const changed = dom();
  changed.features.password_count = 1;
  await a.ensure(1, url, { ...options, dom: changed });
  assert.equal(calls, 3);
  assert.ok(st.s[urlKey(url)]);
  assert.ok(st.s[pageKey(1, url)]);
  await a.ensure(2, url, options);
  assert.equal(calls, 4);
});
test("reload document identity invalidates DOM cache", async () => {
  const st = store();
  let calls = 0;
  const a = createAssessor({
    storage: st,
    analyzeFn: async (url) => {
      calls++;
      return { ok: true, data: apiResponse("low_risk", url) };
    },
  });
  await a.ensure(1, "https://example.org/", { dom: dom(), documentId: "old" });
  await a.ensure(1, "https://example.org/", { dom: dom(), documentId: "new" });
  assert.equal(calls, 2);
});
test("older page snapshot cannot replace a newer result", async () => {
  const st = store();
  let release,
    n = 0;
  const a = createAssessor({
    storage: st,
    newId: () => String(++n),
    analyzeFn: async (url, opts) => {
      if (opts.dom.features.password_count === 0)
        return new Promise((r) => {
          release = () => r({ ok: true, data: apiResponse("low_risk", url) });
        });
      return { ok: true, data: apiResponse("high_risk", url) };
    },
  });
  const url = "https://example.org/",
    old = a.ensure(1, url, { dom: dom() });
  await new Promise((r) => setImmediate(r));
  const changed = dom();
  changed.features.password_count = 1;
  await a.ensure(1, url, { dom: changed });
  release();
  await old;
  assert.equal(st.s[pageKey(1, url)].result.assessment.category, "high_risk");
});
test("extractor code never reads input values, page HTML, cookies or script bodies", () => {
  const src = readFileSync(
    new URL("../dom_extractor.js", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(
    src,
    /\.value\b|\.innerHTML\b|\.outerHTML\b|document\.cookie|\.textContent\b/,
  );
  const m = JSON.parse(
    readFileSync(new URL("../manifest.json", import.meta.url)),
  );
  assert.equal(m.content_scripts, undefined);
  assert.deepEqual(m.host_permissions, ["http://127.0.0.1:8000/*"]);
});

test("sensitive or unexpected fields cannot be sent in a DOM snapshot", () => {
  const d = dom();
  d.features.page_html = "secret";
  assert.equal(validateSnapshot(d), false);
  const t = dom();
  t.features.meta_refresh = [
    { origin: "https://example.org/?token=x", delay_seconds: 0 },
  ];
  assert.equal(validateSnapshot(t), false);
});

test("tab URL withheld without permission falls back instead of reporting a navigation change", async () => {
  const c = fake();
  c.tabs.get = async () => ({ id: 1 });
  const result = await inspectTab(c, 1, "https://example.org/");
  assert.equal(result.dom.reason, "permission");
  assert.equal(result.changed, undefined);
  assert.equal(c.calls, 0);
});
