// Automatic checks remain address-only and opt-in. Manual checks may inspect bounded page structure
// using temporary activeTab access. No input values, page text, script bodies or raw HTML are collected.
import { inspectTab } from "./dom_inspection.js";
import { CATEGORY_LABEL } from "./api.js";
import { AUTO_PERMISSIONS, createAssessor, tabKey } from "./assessor.js";

const NOTIFY_MS = 2500; // notification lifetime
const SETTLE_MS = 500; // collapse redirects and rapid URL changes into one check
const BADGE_COLOR = {
  low_risk: "#1f9d74",
  caution: "#b7791f",
  high_risk: "#c2581c",
  dangerous: "#c81e3a",
  unknown: "#64748b",
};
const storage = chrome.storage.session;

let autoOn = null;
const autoEnabled = async () =>
  (autoOn ??= await chrome.permissions.contains(AUTO_PERMISSIONS));
chrome.permissions.onAdded.addListener(() => {
  autoOn = null;
  listenToClicks();
});
chrome.permissions.onRemoved.addListener(() => {
  autoOn = null;
});

const quiet = (p) => p?.catch?.(() => {}); // the tab may be gone; badge/notification calls must never throw

async function badge(tabId, rec) {
  if (tabId < 0) return;
  let text = "",
    color = BADGE_COLOR.unknown;
  if (rec.state === "pending") text = "…";
  else if (rec.state === "error") text = "!";
  else if (rec.state === "done") {
    const a = rec.result.assessment;
    text = a.category === "unknown" ? "?" : String(a.risk_score);
    color = BADGE_COLOR[a.category];
  }
  await quiet(chrome.action.setBadgeText({ tabId, text }));
  if (text)
    await quiet(chrome.action.setBadgeBackgroundColor({ tabId, color }));
}

async function notify(tabId, rec) {
  // once per site per tab: SPA route changes, refreshes and cached re-visits of the same host stay silent
  const key = `n:${tabId}`;
  if ((await storage.get(key))[key] === rec.host) return;
  await storage.set({ [key]: rec.host });
  const a = rec.result.assessment,
    label = CATEGORY_LABEL[a.category];
  const id = `wg:${rec.id}`;
  await quiet(
    chrome.notifications.create(id, {
      type: "basic",
      iconUrl: "icons/icon128.png",
      silent: true,
      priority: 0,
      title:
        a.category === "unknown"
          ? `${label} — not enough evidence`
          : `${label} · ${a.risk_score}/100`,
      message: rec.host,
      contextMessage: "WebGuard AI · address check, not proof of safety",
    }),
  );
  setTimeout(() => quiet(chrome.notifications.clear(id)), NOTIFY_MS);
}

const assessor = createAssessor({
  storage,
  onUpdate: async (tabId, rec, opts) => {
    if (rec.state === "unsupported")
      return quiet(chrome.action.setBadgeText({ tabId, text: "" }));
    if (
      opts.pageEpoch !== undefined &&
      opts.pageEpoch !== (navigationEpoch.get(tabId) || 0)
    )
      return;
    await badge(tabId, rec);
    if (opts.notify && rec.state === "done" && (await autoEnabled()))
      await notify(tabId, rec);
  },
});

const timers = new Map();
const navigationEpoch = new Map();
chrome.tabs.onUpdated.addListener(async (tabId, change, tab) => {
  if (change.url || change.status === "loading")
    navigationEpoch.set(tabId, (navigationEpoch.get(tabId) || 0) + 1);
  const url =
    change.url ?? (change.status === "complete" ? tab.url : undefined); // absent without the "tabs" permission
  if (!url || !(await autoEnabled())) return;
  clearTimeout(timers.get(tabId));
  timers.set(
    tabId,
    setTimeout(() => {
      timers.delete(tabId);
      assessor.ensure(tabId, url, { notify: tab.active });
    }, SETTLE_MS),
  );
});
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  if (!(await autoEnabled())) return;
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (tab?.url) assessor.ensure(tabId, tab.url, { notify: false }); // switching tabs updates the badge, no notification
});
chrome.tabs.onRemoved.addListener((tabId) =>
  quiet(storage.remove([tabKey(tabId), `n:${tabId}`])),
);

// The popup asks for an assessment of the tab it was opened on (works without automatic mode via activeTab).
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg?.type !== "assess") return;
  if (!msg.inspect) {
    assessor.ensure(msg.tabId, msg.url, {
      force: Boolean(msg.force),
      notify: false,
    });
    return;
  }
  // User-initiated page checks only. Automatic listeners never call inspectTab.
  const run = async () => {
    const epoch = navigationEpoch.get(msg.tabId) || 0;
    let snapshot = await inspectTab(chrome, msg.tabId, msg.url);
    if (snapshot.changed || epoch !== (navigationEpoch.get(msg.tabId) || 0))
      return { navigationChanged: true };
    const rec = await assessor.ensure(msg.tabId, msg.url, {
      force: Boolean(msg.force),
      notify: false,
      pageEpoch: epoch,
      ...snapshot,
    });
    if (epoch !== (navigationEpoch.get(msg.tabId) || 0))
      return { navigationChanged: true };
    return rec;
  };
  run()
    .then(respond)
    .catch(() => respond({ inspectionError: true }));
  return true; // Keep the MV3 message channel alive until extraction + API request finish.
});
// chrome.notifications exists only while the optional permission is granted, so register when it appears.
let clicksRegistered = false;
function listenToClicks() {
  if (clicksRegistered || !chrome.notifications) return;
  clicksRegistered = true;
  chrome.notifications.onClicked.addListener((id) => {
    if (!id.startsWith("wg:")) return;
    chrome.tabs.create({
      url: `report.html?id=${encodeURIComponent(id.slice(3))}`,
    });
    quiet(chrome.notifications.clear(id));
  });
}
listenToClicks();
