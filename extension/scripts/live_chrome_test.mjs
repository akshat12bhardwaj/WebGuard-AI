// LIVE Chrome test: load the unpacked extension with CDP Extensions.loadUnpacked (pipe transport) and drive the popup
// through its documented test hook popup.html?url=<address> (a tab has no toolbar click, so activeTab can't be used).
// Usage: node live_chrome_test.mjs <chrome.exe> <extensionDir> <outDir>     (backend running on 127.0.0.1:8000)
// Real backend: low / caution / high / long host. MOCK records (seeded in session storage): dangerous, unknown, error.
// Not covered here (manual): toolbar click, the automatic-mode permission prompt and real system notifications.
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [chrome, extDir, outDir] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const NUL = String.fromCharCode(0);
const proc = spawn(chrome, ["--headless=new", `--user-data-dir=${join(outDir, "profile")}`, "--remote-debugging-pipe",
  "--enable-unsafe-extension-debugging", "--no-first-run", "about:blank"], { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
let seq = 0, buf = "";
const pending = new Map(), events = [];
proc.stdio[4].on("data", (chunk) => {
  buf += chunk.toString("utf8");
  let i;
  while ((i = buf.indexOf(NUL)) >= 0) {
    const d = JSON.parse(buf.slice(0, i));
    buf = buf.slice(i + 1);
    if (d.id && pending.has(d.id)) {
      const p = pending.get(d.id);
      pending.delete(d.id);
      d.error ? p.rej(new Error(d.error.message)) : p.res(d.result);
    } else if (d.method) events.push(d);
  }
});
const send = (method, params = {}, sessionId) => new Promise((res, rej) => {
  const id = ++seq;
  pending.set(id, { res, rej });
  proc.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + NUL);
});
async function open(url, width, height) {
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  await send("Runtime.enable", {}, sessionId);
  await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false }, sessionId);
  await send("Page.navigate", { url }, sessionId);
  const ev = async (expr) => (await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true }, sessionId)).result.value;
  const shot = async (name, full = false) => {
    const { data } = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: full }, sessionId);
    writeFileSync(join(outDir, name), Buffer.from(data, "base64"));
  };
  const errors = () => events.filter((e) => e.sessionId === sessionId && (e.method === "Runtime.exceptionThrown"
    || (e.method === "Runtime.consoleAPICalled" && e.params.type === "error"))).map((e) => JSON.stringify(e.params).slice(0, 160));
  return { targetId, sessionId, ev, shot, errors };
}
const LAYOUT = `(() => { const h = document.getElementById('host'); const sizes = [...document.querySelectorAll('body *')]
  .filter(e => e.offsetParent && [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim())).map(e => parseFloat(getComputedStyle(e).fontSize));
  return { height: document.documentElement.scrollHeight, verticalScroll: document.documentElement.scrollHeight > innerHeight,
    horizontalScroll: document.documentElement.scrollWidth > innerWidth, minFontPx: Math.min(...sizes),
    hostOneLine: h.scrollWidth <= h.clientWidth && h.getClientRects().length === 1 && h.offsetHeight < 30, hostShown: h.textContent, hostFull: h.title }; })()`;
const STATE = `({ state: document.getElementById('gauge-box').dataset.state, score: document.getElementById('risk').textContent,
  category: document.getElementById('badge').textContent, note: document.getElementById('note').textContent, fresh: document.getElementById('fresh').textContent,
  report: !document.getElementById('open-report').hidden, retry: !document.getElementById('retry').hidden,
  manualChecker: !!document.querySelector('input, form'), logo: document.querySelector('img[src$="logo.svg"]').naturalWidth > 0 })`;

const results = {};
try {
  await sleep(1500);
  results.chrome_version = (await send("Browser.getVersion")).product;
  const { id } = await send("Extensions.loadUnpacked", { path: extDir });
  const base = `chrome-extension://${id}`;
  const popup = async (name, url, { wait = 9000 } = {}) => {
    const t0 = Date.now();
    const p = await open(url ? `${base}/popup.html?url=${encodeURIComponent(url)}` : `${base}/popup.html`, 340, 600);
    let s;
    for (let i = 0; i < wait / 150; i++) {
      await sleep(150);
      s = await p.ev(STATE);
      if (s && s.state !== "scanning" && s.state !== "idle") break;
    }
    results[name] = { ms_until_final: Date.now() - t0, ...s, layout: await p.ev(LAYOUT), errors: p.errors() };
    await p.shot(`popup_${name}.png`);
    return p;
  };

  await popup("own_page", null);
  await popup("low", "https://www.wikipedia.org/");
  await popup("caution", "https://img01.microsoft.com.edgekey.net/");
  await popup("high", "https://secure-paypal.com/");
  await popup("long_host", "https://customer-support-portal.eu-west-2.internal-services.example-company-holdings.co.uk/");

  // Re-opening the popup reuses the saved result: no second request, "Saved" label.
  const again = await popup("low_again", "https://www.wikipedia.org/");
  results.low_again.records = await again.ev("chrome.storage.session.get(null).then(s => Object.keys(s).filter(k => k.startsWith('a:')).length)");

  // MOCK records for states the real backend cannot safely produce here.
  await again.ev(`(async () => {
    const r = await chrome.storage.session.get('u:https://www.wikipedia.org/');
    const real = r['u:https://www.wikipedia.org/'].result;
    const mk = (url, patch) => { const res = structuredClone(real); res.evidence.url = url; res.evidence.host = new URL(url).hostname; Object.assign(res.assessment, patch); return res; };
    const put = (url, rec) => chrome.storage.session.set({ ['u:' + url]: rec, ['a:' + rec.id]: rec });
    const now = Date.now();
    await put('https://mock-dangerous.example/', { id: 'mockD', url: 'https://mock-dangerous.example/', host: 'mock-dangerous.example', state: 'done', startedAt: now, finishedAt: now,
      result: mk('https://mock-dangerous.example/', { category: 'dangerous', risk_score: 95, safety_score: 5, decision_basis: 'Threat intelligence: MOCK listing' }) });
    await put('https://mock-unknown.example/', { id: 'mockU', url: 'https://mock-unknown.example/', host: 'mock-unknown.example', state: 'done', startedAt: now, finishedAt: now,
      result: mk('https://mock-unknown.example/', { category: 'unknown', risk_score: 50, safety_score: null, confidence: 'low' }) });
    await chrome.storage.session.set({ 'a:mockBad': { id: 'mockBad', state: 'done', result: { api_version: '1.0', assessment: { category: 'safe' } } } });
    await put('https://mock-down.example/', { id: 'mockE', url: 'https://mock-down.example/', host: 'mock-down.example', state: 'error', startedAt: now, finishedAt: now,
      error: { kind: 'unreachable', message: 'Cannot reach the analyzer backend at 127.0.0.1:8000. Is it running?' } });
    return true; })()`);
  await popup("mock_dangerous", "https://mock-dangerous.example/");
  await popup("mock_unknown", "https://mock-unknown.example/");
  await popup("mock_backend_down", "https://mock-down.example/");

  // Keyboard: Tab reaches the report button and shows a visible focus ring.
  {
    const k = await open(`${base}/popup.html?url=${encodeURIComponent("https://www.wikipedia.org/")}`, 340, 600);
    await sleep(800);
    await k.ev("document.activeElement && document.activeElement.blur(); true");
    for (let i = 0; i < 2; i++) {
      await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 }, k.sessionId);
      await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 }, k.sessionId);
    }
    results.keyboard = await k.ev("(() => { const a = document.activeElement; const s = getComputedStyle(a); return { focused: a.id || a.tagName, outline: s.outlineStyle + ' ' + s.outlineWidth }; })()");
  }

  // Detailed report from the popup button.
  const p = await open(`${base}/popup.html?url=${encodeURIComponent("https://secure-paypal.com/")}`, 340, 600);
  await sleep(1200);
  await p.ev("document.getElementById('open-report').click(); true");
  let report = null;
  for (let i = 0; i < 30 && !report; i++) {
    await sleep(200);
    report = (await send("Target.getTargets")).targetInfos.find((t) => t.url.includes("/report.html?id="));
  }
  if (!report) throw new Error("report tab did not open");
  for (const [name, url, w] of [["report_high", report.url, 1280], ["report_high_narrow", report.url, 390], ["report_mock_dangerous", `${base}/report.html?id=mockD`, 1280],
    ["report_mock_unknown", `${base}/report.html?id=mockU`, 1280], ["report_missing", `${base}/report.html?id=nope`, 1280], ["report_malformed", `${base}/report.html?id=mockBad`, 1280]]) {
    const r = await open(url, w, 900);
    await sleep(1200);
    results[name] = { ...(await r.ev(`({ visible: !document.getElementById('report').hidden, missing: !document.getElementById('missing').hidden,
      score: document.getElementById('r-score').textContent, category: document.getElementById('r-badge').textContent,
      rule_rows: document.querySelectorAll('#r-rules tr').length, counts: document.getElementById('r-rule-counts').textContent,
      sources: document.querySelectorAll('#r-sources dt').length, sourceLines: [...document.querySelectorAll('#r-sources dt')].map(d => d.textContent + ': ' + d.nextElementSibling.textContent), flow: [...document.querySelectorAll('#r-flow .chip')].map(c => c.textContent),
      logo: document.querySelector('img[src$="logo.svg"]').naturalWidth > 0, horizontalScroll: document.documentElement.scrollWidth > innerWidth })`)), errors: r.errors() };
    await r.shot(`${name}.png`, true);
  }
} catch (e) {
  results.error = String(e.stack ?? e);
} finally {
  writeFileSync(join(outDir, "results.json"), JSON.stringify(results, null, 2));
  console.log(JSON.stringify(results, null, 2));
  proc.kill();
}
