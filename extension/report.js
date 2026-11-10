// Single-screen report. All assessment text is written as textContent; no backend HTML is trusted.
import { validateResponse, prepareUrl } from "./api.js";
import { idKey, urlKey } from "./assessor.js";
import { renderGauge } from "./gauge.js";
import { scoreBands } from "./report_model.js";
import {
  $,
  el,
  icon,
  mountIcons,
  SYMBOL_ICON,
  consumerModel,
  findings,
  safeAddress,
  formatTime,
} from "./consumer.js";
let current = null,
  busy = false,
  sourceTabId = null;
function findingCard(f) {
  const card = el("article", "card"),
    head = el("div", "card-head"),
    mark = el("span", "card-icon"),
    status = el("p", "card-status", f.status);
  card.dataset.key = f.key;
  card.dataset.tone = f.tone;
  mark.append(icon(f.icon));
  head.append(mark, el("h3", "", f.title));
  card.append(head, status, el("p", "card-text", f.text));
  if (f.more.length) {
    // Extra findings open in a popover, so the page never grows taller.
    const id = `more-${f.key}`,
      button = el("button", "more", `+${f.more.length} more`),
      pop = el("div", "more-list"),
      items = el("ul");
    button.type = "button";
    button.setAttribute("popovertarget", id);
    pop.id = id;
    pop.popover = "auto";
    items.append(...f.more.map((text) => el("li", "", text)));
    pop.append(el("h4", "eyebrow", f.title), items);
    card.append(button, pop);
  }
  return card;
}
function render(data) {
  current = data;
  const v = consumerModel(data);
  document.title = `WebGuard AI — ${v.host}`;
  $("r-host").textContent = v.host;
  $("r-url").textContent = safeAddress(v.url);
  // Shown only when the address adds a path to the hostname above it.
  $("r-url").hidden = $("r-url").textContent.replace(/\/$/, "") === v.host;
  $("r-url").title =
    "Assessed address; query parameters are hidden for privacy.";
  $("r-badge").className = `verdict cat-${v.category}`;
  $("r-symbol").replaceChildren(icon(SYMBOL_ICON[v.category]));
  $("r-label").textContent = v.label;
  $("r-note").textContent = v.headline;
  $("r-score").textContent = v.score === null ? "–" : String(v.score);
  renderGauge($("r-meter"), {
    score: v.score,
    category: v.category,
    bands: scoreBands(data),
  });
  $("score-label").ariaLabel =
    v.score === null
      ? "No reliable assessment score available"
      : `Assessment score ${v.score} out of 100. Not a probability or a guarantee of safety.`;
  const t = new Date(v.time);
  $("r-time").textContent = Number.isNaN(t.getTime())
    ? ""
    : `Checked ${t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  $("r-time").title = formatTime(v.time);
  $("cards").replaceChildren(...findings(data).map(findingCard));
  $("r-action").textContent = v.action;
  $("recheck-label").textContent =
    sourceTabId !== null ? "Recheck page" : "Recheck address";
  $("r-disclaimer").textContent = data.disclaimer;
  $("loading").hidden = $("missing").hidden = $("operation").hidden = true;
  $("recheck-error").hidden = true;
  $("report").hidden = false;
  $("report").classList.remove("reveal");
  requestAnimationFrame(() => $("report").classList.add("reveal"));
}
function missing(message) {
  $("loading").hidden = $("operation").hidden = $("report").hidden = true;
  $("missing").hidden = false;
  if (message) $("missing-text").textContent = message;
}
function waitForAssessment(url, inspect = false) {
  if (inspect && sourceTabId !== null)
    return chrome.runtime
      .sendMessage({
        type: "assess",
        tabId: sourceTabId,
        url,
        force: true,
        inspect: true,
      })
      .then((rec) => {
        if (rec?.navigationChanged)
          throw new Error(
            "The website has changed. Open WebGuard on the current page to inspect it.",
          );
        if (rec?.state !== "done" || validateResponse(rec.result).length)
          throw new Error(
            rec?.error?.message ||
              "The check could not finish. Please try again.",
          );
        return rec;
      });
  return new Promise((resolve, reject) => {
    const key = urlKey(url);
    let timer;
    const cleanup = () => {
      clearTimeout(timer);
      chrome.storage.onChanged.removeListener(changed);
    };
    const handle = (rec) => {
      if (!rec || rec.url !== url || rec.state === "pending") return;
      cleanup();
      if (rec.state === "done" && !validateResponse(rec.result).length)
        resolve(rec);
      else
        reject(
          new Error(
            rec.state === "done"
              ? "The analyzer returned an unexpected response. Please try again."
              : rec.error?.message || "This check could not be completed.",
          ),
        );
    };
    const changed = (changes, area) => {
      if (area === "session" && changes[key]) handle(changes[key].newValue);
    };
    chrome.storage.onChanged.addListener(changed);
    timer = setTimeout(() => {
      cleanup();
      reject(
        new Error(
          "The check did not finish. Check that the local analyzer is running, then try again.",
        ),
      );
    }, 26000);
    chrome.runtime
      .sendMessage({ type: "assess", tabId: -1, url, force: true })
      .catch(() => {
        cleanup();
        reject(
          new Error(
            "Could not start the check. Reload the extension and try again.",
          ),
        );
      });
  });
}
function setBusy(on) {
  busy = on;
  $("check-submit").disabled = $("recheck-top").disabled = on;
  $("report").setAttribute("aria-busy", String(on));
}
// From the entry form: the page shows a progress line until the result arrives.
async function check(raw) {
  if (busy) return;
  const p = prepareUrl(raw);
  $("check-error").hidden = true;
  if (!p.ok) {
    $("check-error").textContent = p.reason;
    $("check-error").hidden = false;
    $("check-url").focus();
    return;
  }
  setBusy(true);
  $("missing").hidden = true;
  $("operation").hidden = false;
  $("operation").textContent = `Checking ${new URL(p.url).hostname}…`;
  try {
    show(await waitForAssessment(p.url));
  } catch (error) {
    missing();
    $("check-error").textContent = error.message;
    $("check-error").hidden = false;
    $("check-url").focus();
  } finally {
    setBusy(false);
  }
}
// From the report: the earlier result stays on screen (marked busy) and a failure never replaces it.
async function recheck() {
  if (busy || !current) return;
  const label = $("recheck-label").textContent;
  setBusy(true);
  $("recheck-error").hidden = true;
  $("recheck-label").textContent = "Checking…";
  try {
    show(await waitForAssessment(current.evidence.url, true));
  } catch (error) {
    $("recheck-label").textContent = label;
    $("recheck-error").textContent = `${error.message} The result shown is from the earlier check.`;
    $("recheck-error").hidden = false;
  } finally {
    setBusy(false);
  }
}
function show(rec) {
  // A page recheck keeps its source tab; an address-only check has none.
  sourceTabId = rec.sourceTabId ?? null;
  history.replaceState(null, "", `report.html?id=${encodeURIComponent(rec.id)}`);
  render(rec.result);
}
$("check-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void check($("check-url").value);
});
$("recheck-top").addEventListener("click", () => void recheck());
async function init() {
  const id = new URLSearchParams(location.search).get("id");
  if (!id) return missing();
  const rec = (await chrome.storage.session.get(idKey(id)))[idKey(id)];
  if (!rec || rec.state !== "done")
    return missing(
      "This saved assessment is no longer available. Results are kept for this browser session. Check the address again.",
    );
  if (validateResponse(rec.result).length)
    return missing(
      "The saved assessment could not be read. Check the address again for a fresh result.",
    );
  sourceTabId = rec.sourceTabId ?? null;
  render(rec.result);
}
mountIcons();
init().catch(() =>
  missing(
    "Could not access saved assessments. Reload the extension and check an address again.",
  ),
);
