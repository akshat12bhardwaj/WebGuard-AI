// All assessment text is written as textContent. No backend HTML is trusted.
import { errorTitle, prepareUrl, validateResponse } from "./api.js";
import { AUTO_PERMISSIONS, isUsable, urlKey, pageKey } from "./assessor.js";
import { renderGauge } from "./gauge.js";
import { scoreBands } from "./report_model.js";
import {
  $,
  consumerModel,
  icon,
  mountIcons,
  safeAddress,
  SYMBOL_ICON,
} from "./consumer.js";
mountIcons();
// Chrome sizes the native popup to a whole-pixel height rounded down; at 125%/150% scaling sub-pixel borders make
// the body fractionally taller (e.g. 297.2 px) and a needless scrollbar appears. Round the body up instead.
// Observe the content, not the body: the latched min-height would stop a shrinking body from ever re-measuring.
const fitBody = new ResizeObserver(() => {
  const body = document.body;
  body.style.minHeight = "";
  body.style.minHeight = `${Math.ceil(body.getBoundingClientRect().height)}px`;
});
for (const part of document.body.children) fitBody.observe(part);
const symbol = (name) => $("symbol").replaceChildren(icon(name));
const MIN_SCAN_MS = 450;
function fitHost(node, host) {
  node.title = host;
  node.textContent = host;
  node.style.fontSize = "";
  for (let size = 17; node.scrollWidth > node.clientWidth && size > 13; size--)
    node.style.fontSize = `${size - 1}px`;
  for (
    let cut = 1;
    node.scrollWidth > node.clientWidth && cut < host.length;
    cut++
  )
    node.textContent = `…${host.slice(cut)}`;
}
function ago(ms) {
  const seconds = Math.max(0, Math.round(ms / 1000));
  return seconds < 10
    ? "now"
    : seconds < 60
      ? `${seconds}s`
      : `${Math.round(seconds / 60)}m`;
}

function setGauge(
  state,
  score = null,
  category = null,
  bands = { alert: 37, high: 57, dangerous: 95 },
) {
  const box = $("gauge-box"),
    meter = $("meter");
  box.dataset.state = state;
  box.setAttribute("aria-busy", String(state === "scanning"));
  // The verdict class must wrap the symbol too, so high-risk/dangerous symbols render inverted.
  box.querySelector(".verdict").className =
    "verdict" + (category ? ` cat-${category}` : "");
  renderGauge(meter, { score, category, bands });
  $("risk").textContent = score === null ? "–" : String(score);
  $("score-label").ariaLabel =
    score === null
      ? "No assessment score available"
      : `Risk score ${score} out of 100; not a probability of safety`;
}
function showScanning() {
  $("fresh").textContent = "Checking";
  setGauge("scanning");
  $("badge").className = "category";
  $("badge").textContent = "Checking…";
  symbol("pending");
  $("note").textContent = "Looking for warning signs on this website.";
  $("next-action").textContent = "";
  $("coverage").textContent = "Passwords and typed values are never read.";
  $("coverage").title = "";
  $("open-report").hidden = $("retry").hidden = true;
}
function showProblem(kind, message, retry = true) {
  $("fresh").textContent = "";
  setGauge("problem");
  $("badge").className = "category";
  $("badge").textContent = errorTitle(kind);
  symbol("question");
  $("note").textContent = message;
  $("next-action").textContent =
    kind === "unsupported"
      ? ""
      : "Avoid sharing sensitive information until you can check.";
  $("coverage").textContent = "";
  $("open-report").hidden = true;
  $("retry").hidden = !retry;
  $("retry").classList.remove("icon-only");
  $("retry").removeAttribute("aria-label");
  $("retry").title = "";
  $("retry-label").textContent = "Try again";
}
function showDone(rec, seenRunning) {
  if (validateResponse(rec.result).length)
    return showProblem(
      "bad_response",
      "The saved assessment could not be read. Try a fresh check.",
    );
  const v = consumerModel(rec.result);
  setGauge("done", v.score, v.category, scoreBands(rec.result));
  $("badge").className = `category cat-${v.category}`;
  $("badge").textContent = v.label;
  symbol(SYMBOL_ICON[v.category]);
  $("note").textContent = v.headline;
  $("next-action").textContent = v.action;
  // One coverage line: a page warning first, then limited coverage; incomplete checks never read as complete.
  $("coverage").textContent = `${
    v.partial && !v.domWarnings.length
      ? "Limited checks"
      : v.domShort.replace(/\.$/, "")
  }${v.score === null ? "" : " · Score is not a guarantee"}`;
  $("coverage").title = v.partial
    ? "Some checks could not be completed. The full report shows coverage."
    : "";
  $("fresh").textContent = seenRunning
    ? "Just checked"
    : `Saved · ${ago(Date.now() - rec.finishedAt)}`;
  $("open-report").hidden = false;
  $("open-report").onclick = () =>
    chrome.tabs.create({ url: `report.html?id=${encodeURIComponent(rec.id)}` });
  $("retry").hidden = false;
  $("retry").classList.add("icon-only");
  $("retry").title = $("retry").ariaLabel = "Recheck";
  $("retry-label").textContent = "Recheck";
}
async function initAuto() {
  const sw = $("auto");
  const render = (on) => {
    sw.setAttribute("aria-checked", String(on));
    $("auto-text").hidden = true;
    sw.title =
      "Automatic checks assess website addresses only. Page inspection runs when you open WebGuard.";
    $("auto-text").textContent = on
      ? "On · Addresses go to the analyzer and reputation services."
      : "Check each site you visit (address only).";
  };
  try {
    render(await chrome.permissions.contains(AUTO_PERMISSIONS));
  } catch {
    sw.disabled = true;
    $("auto-text").hidden = false;
    $("auto-text").textContent = "Settings unavailable. Reopen the extension.";
  }
  sw.addEventListener("click", async () => {
    sw.disabled = true;
    try {
      const on = sw.getAttribute("aria-checked") === "true";
      const enabled = on
        ? !(await chrome.permissions.remove(AUTO_PERMISSIONS))
        : await chrome.permissions.request(AUTO_PERMISSIONS);
      render(enabled);
      if (!on && !enabled) {
        $("auto-text").hidden = false;
        $("auto-text").textContent =
          "Permission not granted. Manual checks still work.";
      }
    } catch {
      $("auto-text").hidden = false;
      $("auto-text").textContent =
        "Could not change permissions. Please try again.";
    } finally {
      sw.disabled = false;
    }
  });
}
async function main() {
  void initAuto();
  const testUrl = new URLSearchParams(location.search).get("url");
  const tab = testUrl
    ? { id: -1, url: testUrl }
    : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  const p = prepareUrl(tab?.url);
  if (!p.ok) {
    fitHost($("host"), "This page can’t be assessed");
    return showProblem(
      "unsupported",
      tab?.url
        ? p.reason
        : "The current address is unavailable. Reopen WebGuard from the website’s toolbar icon.",
      false,
    );
  }
  const host = new URL(p.url).hostname;
  fitHost($("host"), host);
  $("host").title = safeAddress(p.url);
  const manual = !testUrl;
  const key = manual ? pageKey(tab.id, p.url) : urlKey(p.url);
  let scanStart = null,
    seenRunning = false,
    timer = null,
    watchdog = null;
  const handle = (rec) => {
    if (!rec || rec.url !== p.url) return;
    clearTimeout(timer);
    if (rec.state === "pending") {
      seenRunning = true;
      scanStart ??= Date.now();
      return showScanning();
    }
    clearTimeout(watchdog);
    const show = () =>
      rec.state === "done"
        ? showDone(rec, seenRunning)
        : showProblem(
            rec.error?.kind,
            rec.error?.message || "The check could not be completed.",
          );
    const wait =
      scanStart === null ? 0 : MIN_SCAN_MS - (Date.now() - scanStart);
    if (wait > 0) timer = setTimeout(show, wait);
    else show();
  };
  chrome.storage.onChanged.addListener((changes, area) => {
    if (!manual && area === "session" && changes[key])
      handle(changes[key].newValue);
  });
  const request = (force) => {
    clearTimeout(timer);
    clearTimeout(watchdog);
    scanStart = Date.now();
    seenRunning = true;
    showScanning();
    watchdog = setTimeout(
      () =>
        showProblem("timeout", "The check did not finish. Please try again."),
      26000,
    );
    chrome.runtime
      .sendMessage({
        type: "assess",
        tabId: tab.id,
        url: p.url,
        force,
        inspect: manual,
      })
      .then((rec) => {
        if (!manual) return;
        clearTimeout(watchdog);
        if (rec?.navigationChanged)
          return showProblem(
            "unsupported",
            "The page changed during the check. Reopen WebGuard on the current page.",
            false,
          );
        if (rec?.state) handle(rec);
        else
          showProblem(
            "bad_response",
            "The check could not finish. Please try again.",
          );
      })
      .catch(() => {
        clearTimeout(watchdog);
        showProblem(
          "unreachable",
          "The analyzer could not start. Reload the extension and try again.",
        );
      });
  };
  $("retry").addEventListener("click", () => request(true));
  const rec = (await chrome.storage.session.get(key))[key];
  if (!manual && rec?.state !== "pending" && isUsable(rec, Date.now()))
    handle(rec);
  else request(false);
}
main().catch(() =>
  showProblem(
    "bad_response",
    "This page could not be checked. Reopen WebGuard from your browser toolbar.",
    false,
  ),
);
