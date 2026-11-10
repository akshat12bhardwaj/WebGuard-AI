// LIVE Chrome test: load the unpacked extension with CDP Extensions.loadUnpacked (pipe transport) and drive the popup
// through its documented test hook popup.html?url=<address> (a tab has no toolbar click, so activeTab can't be used).
// Usage: node live_chrome_test.mjs <chrome.exe> <extensionDir> <outDir> [port=8000]   (backend on 127.0.0.1:<port>)
// Real backend: low / caution / high / long host. MOCK records (seeded in session storage): dangerous, unknown, error.
// Not covered here (manual): toolbar click, the automatic-mode permission prompt and real system notifications.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [chrome, sourceDir, outDir, port = "8000"] = process.argv.slice(2);
// A non-default port runs against a temporary copy that changes only the loopback QA port.
let extDir = sourceDir;
if (port !== "8000") {
  extDir = join(mkdtempSync(join(tmpdir(), "webguard-live-")), "extension");
  cpSync(sourceDir, extDir, { recursive: true, filter: (p) => !p.includes("node_modules") });
  for (const name of ["manifest.json", "api.js"])
    writeFileSync(join(extDir, name), readFileSync(join(extDir, name), "utf8").replaceAll("127.0.0.1:8000", `127.0.0.1:${port}`));
}
mkdirSync(outDir, { recursive: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const NUL = String.fromCharCode(0);
const proc = spawn(
  chrome,
  [
    "--headless=new",
    `--user-data-dir=${mkdtempSync(join(tmpdir(), "webguard-live-profile-"))}`,
    "--remote-debugging-pipe",
    "--enable-unsafe-extension-debugging",
    "--no-first-run",
    "about:blank",
  ],
  { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] },
);
let seq = 0,
  buf = "";
const pending = new Map(),
  events = [];
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
const send = (method, params = {}, sessionId) =>
  new Promise((res, rej) => {
    const id = ++seq;
    pending.set(id, { res, rej });
    proc.stdio[3].write(
      JSON.stringify({ id, method, params, sessionId }) + NUL,
    );
  });
async function open(url, width, height) {
  const { targetId } = await send("Target.createTarget", {
    url: "about:blank",
  });
  const { sessionId } = await send("Target.attachToTarget", {
    targetId,
    flatten: true,
  });
  await send("Runtime.enable", {}, sessionId);
  await send(
    "Emulation.setDeviceMetricsOverride",
    { width, height, deviceScaleFactor: 1, mobile: false },
    sessionId,
  );
  await send("Page.navigate", { url }, sessionId);
  const ev = async (expr) => {
    const result = await send(
      "Runtime.evaluate",
      { expression: expr, returnByValue: true, awaitPromise: true },
      sessionId,
    );
    if (result.exceptionDetails)
      throw new Error(
        result.exceptionDetails.exception?.description ||
          result.exceptionDetails.text,
      );
    return result.result.value;
  };
  const shot = async (name, full = false) => {
    const { data } = await send(
      "Page.captureScreenshot",
      { format: "png", captureBeyondViewport: full },
      sessionId,
    );
    writeFileSync(join(outDir, name), Buffer.from(data, "base64"));
  };
  const errors = () =>
    events
      .filter(
        (e) =>
          e.sessionId === sessionId &&
          (e.method === "Runtime.exceptionThrown" ||
            (e.method === "Runtime.consoleAPICalled" &&
              e.params.type === "error")),
      )
      .map((e) => JSON.stringify(e.params).slice(0, 160));
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
  manualChecker: !!document.querySelector('input, form'), logo: document.querySelector('img[src$="identity.svg"]').naturalWidth > 0 })`;

const results = {};
try {
  await sleep(1500);
  results.chrome_version = (await send("Browser.getVersion")).product;
  const { id } = await send("Extensions.loadUnpacked", { path: extDir });
  const base = `chrome-extension://${id}`;
  const popup = async (name, url, { wait = 9000 } = {}) => {
    const t0 = Date.now();
    const p = await open(
      url
        ? `${base}/popup.html?url=${encodeURIComponent(url)}`
        : `${base}/popup.html`,
      360,
      600,
    );
    let s;
    for (let i = 0; i < wait / 150; i++) {
      await sleep(150);
      s = await p.ev(STATE);
      if (s && s.state !== "scanning" && s.state !== "idle") break;
    }
    results[name] = {
      ms_until_final: Date.now() - t0,
      ...s,
      layout: await p.ev(LAYOUT),
      errors: p.errors(),
    };
    await p.shot(`popup_${name}.png`);
    return p;
  };

  await popup("own_page", null);
  await popup("low", "https://www.wikipedia.org/");
  await popup("caution", "https://img01.microsoft.com.edgekey.net/");
  await popup("high", "https://secure-paypal.com/");
  await popup(
    "long_host",
    "https://customer-support-portal.eu-west-2.internal-services.example-company-holdings.co.uk/",
  );

  // Re-opening the popup reuses the saved result: no second request, "Saved" label.
  const again = await popup("low_again", "https://www.wikipedia.org/");
  results.low_again.records = await again.ev(
    "chrome.storage.session.get(null).then(s => Object.keys(s).filter(k => k.startsWith('a:')).length)",
  );

  // MOCK records for states the real backend cannot safely produce here.
  await again.ev(`(async () => {
    const r = await chrome.storage.session.get('u:https://www.wikipedia.org/');
    const real = r['u:https://www.wikipedia.org/'].result;
    const mk = (url, patch) => { const res = structuredClone(real); res.evidence.url = url; res.evidence.host = new URL(url).hostname; Object.assign(res.assessment, patch);
      if (patch.category === 'dangerous') { res.evidence.threat_intel = [{source:'PhishTank',status:'match',detail:'MOCK confirmed listing'}]; res.evidence.rules = [{rule_id:'TI_PHISHTANK_VERIFIED',status:'fired',severity:'critical',title:'MOCK listing'}]; }
      if (patch.category === 'unknown') { res.evidence.model = {available:false,probability:null,thresholds:{},error:'MOCK model unavailable'}; res.evidence.threat_intel = [{source:'PhishTank',status:'error',detail:'MOCK timeout'}]; res.evidence.rules = []; }
      return res; };
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
    const k = await open(
      `${base}/popup.html?url=${encodeURIComponent("https://www.wikipedia.org/")}`,
      360,
      600,
    );
    await sleep(800);
    await k.ev("document.activeElement && document.activeElement.blur(); true");
    for (let i = 0; i < 2; i++) {
      await send(
        "Input.dispatchKeyEvent",
        { type: "keyDown", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 },
        k.sessionId,
      );
      await send(
        "Input.dispatchKeyEvent",
        { type: "keyUp", key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 },
        k.sessionId,
      );
    }
    results.keyboard = await k.ev(
      "(() => { const a = document.activeElement; const s = getComputedStyle(a); return { focused: a.id || a.tagName, outline: s.outlineStyle + ' ' + s.outlineWidth }; })()",
    );
  }

  // Detailed report from the popup button.
  const p = await open(
    `${base}/popup.html?url=${encodeURIComponent("https://secure-paypal.com/")}`,
    360,
    600,
  );
  await sleep(1200);
  await p.ev("document.getElementById('open-report').click(); true");
  let report = null;
  for (let i = 0; i < 30 && !report; i++) {
    await sleep(200);
    report = (await send("Target.getTargets")).targetInfos.find((t) =>
      t.url.includes("/report.html?id="),
    );
  }
  if (!report) throw new Error("report tab did not open");
  for (const [name, url, w] of [
    ["report_high", report.url, 1280],
    ["report_tablet", report.url, 768],
    ["report_small", report.url, 320],
    ["report_large", report.url, 1600],
    ["report_high_narrow", report.url, 390],
    ["report_mock_dangerous", `${base}/report.html?id=mockD`, 1280],
    ["report_mock_unknown", `${base}/report.html?id=mockU`, 1280],
    ["report_dangerous_mobile", `${base}/report.html?id=mockD`, 320],
    ["report_missing", `${base}/report.html?id=nope`, 1280],
    ["report_malformed", `${base}/report.html?id=mockBad`, 1280],
  ]) {
    const r = await open(url, w, 900);
    await sleep(1200);
    results[name] = {
      ...(await r.ev(`({ visible: !document.getElementById('report').hidden, missing: !document.getElementById('missing').hidden,
      score: document.getElementById('r-score').textContent, category: document.getElementById('r-label').textContent,
      findings: [...document.querySelectorAll('.card')].map(c => c.querySelector('h3').textContent + ': ' + c.querySelector('.card-status').textContent),
      oneScreen: document.documentElement.scrollHeight <= innerHeight,
      logo: document.querySelector('img[src$="identity.svg"]').naturalWidth > 0, horizontalScroll: document.documentElement.scrollWidth > innerWidth })`)),
      errors: r.errors(),
    };
    await r.shot(`${name}.png`, true);
  }
  {
    const record = await again.ev(
      "chrome.storage.session.get(null).then(s=>Object.values(s).find(r=>r.host?.startsWith('customer-support-portal')&&r.state==='done'))",
    );
    const r = await open(`${base}/report.html?id=${record.id}`, 320, 900);
    await sleep(400);
    results.long_report = {
      host: await r.ev("document.getElementById('r-host').textContent"),
      horizontalScroll: await r.ev(
        "document.documentElement.scrollWidth>innerWidth",
      ),
      errors: r.errors(),
    };
    await r.shot("report_long_mobile.png", true);
  }
  // Real form submission and recheck, through the installed service worker.
  {
    const r = await open(`${base}/report.html`, 390, 900);
    await sleep(300);
    await r.ev(
      "document.getElementById('check-url').value='https://www.wikipedia.org/'; document.getElementById('check-form').requestSubmit(); true",
    );
    for (let i = 0; i < 100; i++) {
      await sleep(150);
      if (await r.ev("!document.getElementById('report').hidden")) break;
    }
    results.check_another = await r.ev(
      "({visible:!document.getElementById('report').hidden,host:document.getElementById('r-host').textContent,score:document.getElementById('r-score').textContent,id:new URLSearchParams(location.search).get('id')})",
    );
    await r.ev("document.getElementById('recheck-top').click(); true");
    await r.shot("report_loading.png");
    // The earlier result stays visible while rechecking; done when the URL names the new record.
    for (let i = 0; i < 100; i++) {
      await sleep(150);
      if (await r.ev(`new URLSearchParams(location.search).get('id') !== ${JSON.stringify(results.check_another.id)} && document.getElementById('report').getAttribute('aria-busy') === 'false'`)) break;
    }
    results.recheck = await r.ev(
      "({visible:!document.getElementById('report').hidden,id:new URLSearchParams(location.search).get('id')})",
    );
    await send(
      "Emulation.setEmulatedMedia",
      { features: [{ name: "prefers-reduced-motion", value: "reduce" }] },
      r.sessionId,
    );
    results.reduced_motion = await r.ev(
      "({matches:matchMedia('(prefers-reduced-motion: reduce)').matches,animation:getComputedStyle(document.getElementById('report')).animationName,scroll:getComputedStyle(document.documentElement).scrollBehavior})",
    );
    results.contrast = await r.ev(
      "({body:getComputedStyle(document.body).color,background:getComputedStyle(document.documentElement).backgroundColor,secondary:getComputedStyle(document.querySelector('.app-meta')).color})",
    );
    await r.shot("report_low_mobile.png", true);
    results.interaction_errors = r.errors();
  }
  // Denied permissions use a labelled page-local mock, not an actual permission prompt.
  {
    const p = await popup(
      "permission_denied_before",
      "https://www.wikipedia.org/",
    );
    await p.ev(
      "chrome.permissions.request=async()=>false; document.getElementById('auto').click(); true",
    );
    await sleep(150);
    results.permission_denied = await p.ev(
      "({on:document.getElementById('auto').getAttribute('aria-checked'),message:document.getElementById('auto-text').textContent})",
    );
  }
  // Longer settings copy must fit both denied and enabled states.
  {
    const page=await popup('settings_before','https://www.wikipedia.org/');
    await page.ev("chrome.permissions.request=async()=>false;document.getElementById('auto').click();true");await sleep(80);
    results.settings_denied={layout:await page.ev(LAYOUT),errors:page.errors()};
    await page.ev("chrome.permissions.request=async()=>true;document.getElementById('auto').click();true");await sleep(80);
    results.settings_enabled={layout:await page.ev(LAYOUT),errors:page.errors()};
  }
  // An expired cached URL must produce a fresh assessment.
  await again.ev(
    "(async()=>{const k='u:https://www.wikipedia.org/';const s=await chrome.storage.session.get(k);s[k].finishedAt=Date.now()-11*60000;await chrome.storage.session.set(s);return true;})()",
  );
  await popup("expired_cache", "https://www.wikipedia.org/");
  // A genuine failed fetch from the extension service worker; the backend process is left running.
  {
    const worker = (await send("Target.getTargets")).targetInfos.find(
      (t) => t.type === "service_worker" && t.url.startsWith(base),
    );
    const { sessionId } = await send("Target.attachToTarget", {
      targetId: worker.targetId,
      flatten: true,
    });
    await send("Network.enable", {}, sessionId);
    await send(
      "Network.emulateNetworkConditions",
      { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 },
      sessionId,
    );
    const offline = await popup(
      "network_offline",
      "https://offline-check.example/",
    );
    await offline.shot("popup_network_offline.png");
    await send(
      "Network.emulateNetworkConditions",
      {
        offline: false,
        latency: 0,
        downloadThroughput: -1,
        uploadThroughput: -1,
      },
      sessionId,
    );
  }
  for (const [name, result] of Object.entries(results)) {
    if (result?.layout) {
      assert.equal(
        result.layout.horizontalScroll,
        false,
        name + " horizontal overflow",
      );
      assert.equal(
        result.layout.verticalScroll,
        false,
        name + " popup too tall",
      );
      assert.ok(result.layout.minFontPx >= 12, name + " readable type");
    }
    if (result?.errors)
      assert.deepEqual(result.errors, [], name + " browser errors");
    if (name.startsWith("report_"))
      assert.equal(
        result.horizontalScroll,
        false,
        name + " horizontal overflow",
      );
  }
  assert.equal(results.low.category, "Low risk");
  assert.equal(results.caution.category, "Caution");
  assert.equal(results.high.category, "High risk");
  assert.equal(results.mock_unknown.score, "–");
  for (const name of ["report_high", "report_large", "report_mock_dangerous", "report_mock_unknown"])
    assert.equal(results[name].oneScreen, true, name + " fits one desktop screen");
  assert.equal(results.mock_dangerous.category, "Dangerous");
  assert.match(results.low_again.fresh, /Saved/);
  assert.match(results.expired_cache.fresh, /Just checked/);
  assert.equal(results.check_another.visible, true);
  assert.equal(results.check_another.host, "wikipedia.org");
  assert.equal(results.recheck.visible, true);
  assert.notEqual(results.recheck.id, results.check_another.id);
  assert.equal(results.permission_denied.on, "false");
  assert.match(results.permission_denied.message, /not granted/);
  assert.equal(results.reduced_motion.animation, "none");
  assert.equal(results.reduced_motion.scroll, "auto");
  assert.deepEqual(results.interaction_errors, []);
  assert.equal(results.long_report.horizontalScroll, false);
  assert.equal(results.network_offline.state, "problem");
  assert.equal(results.network_offline.category, "Backend unavailable");
  results.assertions =
    "All functional, layout, reduced-motion and browser-error assertions passed.";
} catch (e) {
  results.error = String(e.stack ?? e);
} finally {
  writeFileSync(join(outDir, "results.json"), JSON.stringify(results, null, 2));
  console.log(
    JSON.stringify(
      {
        chrome: results.chrome_version,
        assertions: results.assertions,
        error: results.error,
        scenarios: Object.keys(results).length,
      },
      null,
      2,
    ),
  );
  proc.kill();
  if (results.error) process.exitCode = 1;
}
