// Score-first popup: shows the latest real assessment of the active tab, or starts one (through the service worker,
// which de-duplicates requests). All text goes through textContent; backend strings are untrusted.
import { CATEGORY_LABEL, errorTitle, prepareUrl, viewModel } from "./api.js";
import { AUTO_PERMISSIONS, isUsable, urlKey } from "./assessor.js";
import { renderGauge } from "./gauge.js";
import { scoreBands } from "./report_model.js";

const $ = (id) => document.getElementById(id);
const MIN_SCAN_MS = 700; // display only: a scan seen in this popup stays visible this long; the request is never delayed
const CONTRACT_BANDS = { alert: 37, high: 57, dangerous: 95 };

/** Fit a host on one line: shrink to 13 px, then trim from the left (the registered domain is at the end). */
function fitHost(el, host) {
  el.title = host;
  el.textContent = host;
  el.style.fontSize = "";
  for (let size = 17; el.scrollWidth > el.clientWidth && size > 13; size--) el.style.fontSize = `${size - 1}px`;
  for (let cut = 1; el.scrollWidth > el.clientWidth && cut < host.length; cut++) el.textContent = `…${host.slice(cut)}`;
}

function ago(ms) {
  const s = Math.round(ms / 1000);
  return s < 10 ? "just now" : s < 60 ? `${s} s ago` : `${Math.round(s / 60)} min ago`;
}

function setGauge(state, { score = null, category = null, bands = CONTRACT_BANDS } = {}) {
  $("gauge-box").dataset.state = state;
  renderGauge($("gauge"), { score, category, bands });
  $("gauge-label").textContent = score === null ? "No risk score" : `Risk score ${score} out of 100`;
  $("risk").textContent = score === null ? "–" : String(score);
}

function showScanning(host) {
  setGauge("scanning");
  $("badge").className = "category";
  $("badge").textContent = "Assessing…";
  $("note").textContent = `Checking ${host} with the local WebGuard backend.`;
  $("fresh").textContent = "";
  $("open-report").hidden = $("retry").hidden = true;
}

function showDone(rec, seenRunning) {
  const v = viewModel(rec.result), a = rec.result.assessment;
  const score = a.category === "unknown" ? null : a.risk_score; // the contract's placeholder 50 is not a measurement
  setGauge("done", { score, category: a.category, bands: scoreBands(rec.result) });
  $("badge").className = `category cat-${a.category}`;
  $("badge").textContent = CATEGORY_LABEL[a.category];
  $("note").textContent = v.note;
  $("fresh").textContent = seenRunning ? "Assessed just now" : `Saved · ${ago(Date.now() - rec.finishedAt)}`;
  $("open-report").hidden = false;
  $("open-report").onclick = () => chrome.tabs.create({ url: `report.html?id=${encodeURIComponent(rec.id)}` });
  $("retry").hidden = true;
}

function showProblem(kind, message, retry) {
  setGauge("problem");
  $("badge").className = "category";
  $("badge").textContent = errorTitle(kind);
  $("note").textContent = message;
  $("fresh").textContent = "";
  $("open-report").hidden = true;
  $("retry").hidden = !retry;
}

async function initAuto() {
  const sw = $("auto");
  const render = (on) => {
    sw.setAttribute("aria-checked", String(on));
    $("auto-text").textContent = on ? "On: each visited address is checked; no page content is read."
      : "Check each site you visit (address only).";
  };
  render(await chrome.permissions.contains(AUTO_PERMISSIONS));
  sw.addEventListener("click", async () => {
    const on = sw.getAttribute("aria-checked") === "true";
    // The request must run inside this click: Chrome then shows its own permission prompt.
    const enabled = on ? !(await chrome.permissions.remove(AUTO_PERMISSIONS)) : await chrome.permissions.request(AUTO_PERMISSIONS);
    render(enabled);
  });
}

async function main() {
  initAuto();
  // ?url= is the documented test hook (scripts/live_chrome_test.mjs); normally the active tab is used.
  const testUrl = new URLSearchParams(location.search).get("url");
  const tab = testUrl ? { id: -1, url: testUrl } : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  const p = prepareUrl(tab?.url);
  if (!p.ok) {
    fitHost($("host"), "This page can't be assessed");
    return showProblem("unsupported", p.reason, false);
  }
  const key = urlKey(p.url), host = new URL(p.url).hostname;
  fitHost($("host"), host);
  let scanStart = null, seenRunning = false, timer = null;

  const handle = (rec) => {
    if (!rec || rec.url !== p.url) return; // never show another address's result
    clearTimeout(timer);
    if (rec.state === "pending") {
      seenRunning = true;
      scanStart ??= Date.now();
      return showScanning(host);
    }
    const show = () => (rec.state === "done" ? showDone(rec, seenRunning) : showProblem(rec.error.kind, rec.error.message, true));
    const wait = scanStart === null ? 0 : MIN_SCAN_MS - (Date.now() - scanStart);
    if (wait > 0) timer = setTimeout(show, wait); else show();
  };
  chrome.storage.onChanged.addListener((changes, area) => { if (area === "session" && changes[key]) handle(changes[key].newValue); });
  const request = (force) => {
    scanStart = Date.now();
    seenRunning = true;
    showScanning(host);
    chrome.runtime.sendMessage({ type: "assess", tabId: tab.id, url: p.url, force }).catch(() => {}); // result arrives via storage
  };
  $("retry").addEventListener("click", () => request(true));

  const rec = (await chrome.storage.session.get(key))[key];
  if (rec?.state !== "pending" && isUsable(rec, Date.now())) handle(rec); // a saved result: no new request
  else request(false); // none, or one running: the service worker joins a running request instead of sending another
}

main();
