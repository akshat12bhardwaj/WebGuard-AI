// One assessment per URL, shared by the service worker (automatic checks) and the popup.
// Records live in chrome.storage.session (memory only, cleared when the browser closes), because an MV3 service worker
// loses its in-memory state after ~30 s idle. Pure ES module with injected storage/analyze/clock: testable with node --test.
import { analyze, prepareUrl } from "./api.js";

// Freshness policy (documented in README): a result is reused for 10 min (below the backend's 15-min reputation cache);
// a failed check is retried after 30 s; a pending record older than 25 s (request timeout 15 s + margin) is abandoned.
export const FRESH_MS = 10 * 60 * 1000;
export const ERROR_RETRY_MS = 30 * 1000;
export const PENDING_MAX_MS = 25 * 1000;
export const MAX_RECORDS = 60;
// Optional permissions the user grants from the popup to turn on automatic checks of visited sites.
export const AUTO_PERMISSIONS = { permissions: ["tabs", "notifications"] };

export const urlKey = (url) => `u:${url}`;
export const idKey = (id) => `a:${id}`;
export const tabKey = (tabId) => `t:${tabId}`;

/** Can this record be shown instead of starting a new request? (pending: still within the request timeout) */
export function isUsable(rec, now) {
  if (!rec) return false;
  if (rec.state === "pending") return now - rec.startedAt < PENDING_MAX_MS;
  return now - rec.finishedAt < (rec.state === "done" ? FRESH_MS : ERROR_RETRY_MS);
}

const read = async (storage, key) => (await storage.get(key))[key] ?? null;

/**
 * onUpdate(tabId, record, opts) is called for every tab that is still on the record's URL: once when a request starts
 * (state "pending"), once when it ends ("done"/"error"), or once with a reusable record (opts.cached = true).
 * A response never updates a tab that has moved on to another URL.
 */
export function createAssessor({ storage, analyzeFn = analyze, now = Date.now, newId = () => crypto.randomUUID(), onUpdate = () => {} }) {
  const inflight = new Map(); // url -> { promise, tabs: Map(tabId -> opts) }

  async function prune() {
    const all = await storage.get(null);
    const done = Object.entries(all).filter(([k]) => k.startsWith("a:")).map(([, r]) => r)
      .sort((x, y) => y.finishedAt - x.finishedAt);
    const drop = done.slice(MAX_RECORDS);
    const keys = drop.flatMap((r) => [idKey(r.id), ...(all[urlKey(r.url)]?.id === r.id ? [urlKey(r.url)] : [])]);
    if (keys.length) await storage.remove(keys);
  }

  function ensure(tabId, rawUrl, opts = {}) {
    const p = prepareUrl(rawUrl);
    if (!p.ok) {
      return storage.set({ [tabKey(tabId)]: { url: null } }).then(() => {
        onUpdate(tabId, { state: "unsupported", reason: p.reason }, opts);
        return null;
      });
    }
    const url = p.url;
    const tabSaved = storage.set({ [tabKey(tabId)]: { url } });
    // Registered synchronously, so simultaneous calls for one URL (another tab, a redirect, a repeated event) join it.
    const running = inflight.get(url);
    if (running) {
      running.tabs.set(tabId, opts);
      return tabSaved.then(() => running.promise);
    }
    const tabs = new Map([[tabId, opts]]);
    const stillOn = async (t) => (await read(storage, tabKey(t)))?.url === url;
    const promise = (async () => {
      await tabSaved;
      const rec = await read(storage, urlKey(url));
      // Only finished records are reused: a stored "pending" without a live request belongs to a stopped worker.
      if (!opts.force && rec?.state !== "pending" && isUsable(rec, now())) {
        for (const [t, o] of tabs) if (await stillOn(t)) onUpdate(t, rec, { ...o, cached: true });
        return rec;
      }
      const pending = { id: newId(), url, host: new URL(url).hostname, state: "pending", startedAt: now() };
      await storage.set({ [urlKey(url)]: pending });
      for (const [t, o] of tabs) onUpdate(t, pending, o);
      const res = await analyzeFn(url);
      const end = { ...pending, finishedAt: now() };
      const final = res.ok ? { ...end, state: "done", result: res.data } : { ...end, state: "error", error: { kind: res.kind, message: res.message } };
      await storage.set({ [urlKey(url)]: final, [idKey(final.id)]: final });
      await prune();
      for (const [t, o] of tabs) if (await stillOn(t)) onUpdate(t, final, o); // stale responses update nobody
      return final;
    })().finally(() => inflight.delete(url));
    inflight.set(url, { promise, tabs });
    return promise;
  }

  return { ensure };
}
