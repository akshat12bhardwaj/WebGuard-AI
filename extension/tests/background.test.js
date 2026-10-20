// MOCKED tests for automatic assessment (background.js + assessor.js) with a fake chrome API and fake backend.
import assert from "node:assert/strict";
import { afterEach, beforeEach, mock, test } from "node:test";
import { apiResponse } from "./fixtures.js";

const flush = async (n = 8) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };
const ev = () => { const l = []; return { addListener: (f) => l.push(f), fire: (...a) => l.map((f) => f(...a)) }; };

function fakeChrome({ granted = true } = {}) {
  const store = {}, log = [];
  const pick = (k) => (k === null ? { ...store } : Object.fromEntries([].concat(k).filter((x) => x in store).map((x) => [x, store[x]])));
  const c = {
    log, store,
    storage: { session: { get: async (k) => structuredClone(pick(k)), set: async (o) => { Object.assign(store, structuredClone(o)); },
      remove: async (ks) => { for (const k of [].concat(ks)) delete store[k]; } } },
    permissions: { contains: async () => c.granted, onAdded: ev(), onRemoved: ev() },
    tabs: { onUpdated: ev(), onActivated: ev(), onRemoved: ev(), get: async (id) => c.tabs.byId[id], byId: {},
      create: async (o) => { log.push(["create", o.url]); } },
    runtime: { onMessage: ev() },
    action: { setBadgeText: async (o) => { log.push(["badge", o.tabId, o.text]); }, setBadgeBackgroundColor: async () => {} },
    notifications: { create: async (id, o) => { log.push(["notify", id, o.title, o.message]); }, clear: async (id) => { log.push(["clear", id]); }, onClicked: ev() },
    granted,
  };
  return c;
}

let chrome, requests, replies, n = 0;
async function load(opts) {
  chrome = fakeChrome(opts);
  globalThis.chrome = chrome;
  requests = [];
  replies = {}; // url -> pending resolver for slow backends; otherwise answer at once
  globalThis.fetch = async (_u, init) => {
    const url = JSON.parse(init.body).url;
    requests.push(url);
    const body = await (replies[url] ?? Promise.resolve(apiResponse(url.includes("bad") ? "high_risk" : "low_risk", url)));
    if (body === "down") throw new TypeError("Failed to fetch");
    return { status: 200, ok: true, json: async () => body };
  };
  await import(`../background.js?v=${++n}`); // fresh module instance per test
}
const visit = async (tabId, url, { active = true, status } = {}) => {
  chrome.tabs.onUpdated.fire(tabId, status ? { status } : { url }, { id: tabId, url, active });
  await flush();
};
const settle = async () => { mock.timers.tick(500); await flush(); };
const badges = (tabId) => chrome.log.filter(([k, t]) => k === "badge" && t === tabId).map(([, , text]) => text);
const notes = () => chrome.log.filter(([k]) => k === "notify");

beforeEach(() => mock.timers.enable({ apis: ["setTimeout"] }));
afterEach(() => { mock.timers.reset(); delete globalThis.chrome; });

test("without the opt-in nothing is assessed automatically", async () => {
  await load({ granted: false });
  await visit(1, "https://www.example.com/");
  await settle();
  assert.deepEqual(requests, []);
  assert.deepEqual(notes(), []);
});

test("a visit is assessed once (duplicate and 'complete' events collapse), badge shows the score, notification closes after 2.5 s", async () => {
  await load();
  await visit(1, "https://www.example.com/a#x");
  await visit(1, "https://www.example.com/a#x");
  await visit(1, "https://www.example.com/a#x", { status: "complete" });
  await settle();
  assert.deepEqual(requests, ["https://www.example.com/a"]); // fragment dropped, one request
  assert.deepEqual(badges(1), ["…", "17"]);
  assert.equal(notes().length, 1);
  const [, id, title, message] = notes()[0];
  assert.equal(title, "Low risk · 17/100");
  assert.equal(message, "www.example.com");
  assert.ok(!chrome.log.some(([k]) => k === "clear"));
  mock.timers.tick(2500);
  await flush();
  assert.ok(chrome.log.some(([k, x]) => k === "clear" && x === id));
});

test("refresh, SPA route changes and cached revisits of the same site do not notify again", async () => {
  await load();
  await visit(1, "https://www.example.com/");
  await settle();
  await visit(1, "https://www.example.com/", { status: "complete" }); // refresh: fresh cached result, no request
  await settle();
  await visit(1, "https://www.example.com/inbox"); // SPA route change: new URL is assessed, but no second notification
  await settle();
  assert.deepEqual(requests, ["https://www.example.com/", "https://www.example.com/inbox"]);
  assert.equal(notes().length, 1);
  await visit(1, "https://bad.example.org/"); // another site: notify
  await settle();
  assert.equal(notes().length, 2);
});

test("a slow response for an old address never overwrites the newer one", async () => {
  await load();
  let release;
  replies["https://slow.example.com/"] = new Promise((r) => { release = r; });
  await visit(1, "https://slow.example.com/");
  await settle();
  await visit(1, "https://www.example.com/");
  await settle();
  release(apiResponse("high_risk", "https://slow.example.com/"));
  await flush();
  assert.equal(badges(1).at(-1), "17"); // still the current page's score
  assert.equal(notes().length, 1);
  assert.match(notes()[0][3], /example\.com$/);
  assert.ok(Object.keys(chrome.store).includes("u:https://slow.example.com/")); // kept, but only for that address
});

test("background tabs get a badge but no notification", async () => {
  await load();
  await visit(2, "https://www.example.com/", { active: false });
  await settle();
  assert.deepEqual(badges(2), ["…", "17"]);
  assert.deepEqual(notes(), []);
});

test("unsupported pages are never sent; a failed request shows '!' and no notification", async () => {
  await load();
  await visit(1, "chrome://settings/");
  await settle();
  assert.deepEqual(requests, []);
  assert.deepEqual(badges(1), [""]);
  replies["https://down.example.com/"] = Promise.resolve("down");
  await visit(1, "https://down.example.com/");
  await settle();
  assert.deepEqual(badges(1).slice(-1), ["!"]);
  assert.deepEqual(notes(), []);
  assert.equal(chrome.store["u:https://down.example.com/"].state, "error");
});

test("popup requests are de-duplicated and need no automatic mode", async () => {
  await load({ granted: false });
  chrome.runtime.onMessage.fire({ type: "assess", tabId: 3, url: "https://www.example.com/" });
  chrome.runtime.onMessage.fire({ type: "assess", tabId: 3, url: "https://www.example.com/" });
  await flush();
  assert.deepEqual(requests, ["https://www.example.com/"]);
  assert.equal(chrome.store["u:https://www.example.com/"].state, "done");
  assert.deepEqual(notes(), []);
});

test("clicking a notification opens that assessment's report", async () => {
  await load();
  await visit(1, "https://www.example.com/");
  await settle();
  const id = notes()[0][1];
  chrome.notifications.onClicked.fire(id);
  await flush();
  assert.deepEqual(chrome.log.find(([k]) => k === "create"), ["create", `report.html?id=${encodeURIComponent(id.slice(3))}`]);
  assert.equal(chrome.store[`a:${id.slice(3)}`].state, "done");
});
