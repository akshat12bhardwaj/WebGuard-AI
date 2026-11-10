// Real Chrome + revised real backend. Copies extension only to point at the isolated QA backend port.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  cpSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { startChrome, sleep, until } from "./chrome_driver.mjs";
const [exe, source, output, port = "8001"] = process.argv.slice(2),
  out = resolve(output);
mkdirSync(out, { recursive: true });
const temp = mkdtempSync(join(tmpdir(), "webguard-dom-r2-")),
  ext = join(temp, "extension");
cpSync(source, ext, {
  recursive: true,
  filter: (p) => !p.includes("node_modules"),
});
for (const name of ["manifest.json", "api.js"]) {
  const path = join(ext, name);
  writeFileSync(
    path,
    readFileSync(path, "utf8").replaceAll(
      "127.0.0.1:8000",
      `127.0.0.1:${port}`,
    ),
  );
}
const SECRET = "TYPED_VALUE_MUST_NOT_LEAVE_PAGE",
  TOKEN = "RESOURCE_QUERY_MUST_NOT_LEAVE_PAGE";
let fixturePort;
function page(path) {
  const origin = `http://127.0.0.1:${fixturePort}`,
    https = `https://127.0.0.1:${fixturePort}`;
  const login = (action) =>
    `<form method="post" ${action === null ? "" : `action="${action}"`}><label>Account<input type="text" value="${SECRET}"></label><label>Password<input type="password" value="${SECRET}"></label><button>Sign in</button></form>`;
  let body = "<h1>Controlled WebGuard fixture</h1>";
  if (path === "/benign") body += login(https + "/submit");
  if (path === "/insecure") body += login(origin + "/submit?token=" + TOKEN);
  if (path === "/external") body += login("https://accounts.google.com/submit");
  if (path === "/hidden")
    body += `<div style="display:none">${login(https + "/submit")}</div>`;
  if (path === "/missing") body += login(null);
  if (path === "/orphan") body += '<input type="password">';
  if (path === "/malformed") body += login("http://[");
  if (path === "/frames")
    body += `<iframe src="http://localhost:${fixturePort}/empty"></iframe><iframe srcdoc="&lt;form&gt;&lt;input type=password&gt;&lt;/form&gt;"></iframe>`;
  if (path === "/resources")
    body += `<a href="#">Placeholder</a><a href="javascript:void(0)">Placeholder</a><a href="https://outside.test/x?token=${TOKEN}">External</a><img src="/asset?token=${TOKEN}"><script src="/script?token=${TOKEN}"></script>`;
  if (path === "/large")
    body += '<a href="https://outside.test/">Link</a>'.repeat(7000);
  if (path === "/origins")
    body += Array.from(
      { length: 60 },
      (_, i) => `<a href="https://site${i}.test/">Link</a>`,
    ).join("");
  if (path === "/redirect")
    body +=
      `<meta http-equiv="refresh" content="9;url=http://localhost:${fixturePort}/landing">` +
      login(https + "/submit");
  return `<!doctype html><html><head><title>Controlled fixture</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body>${body}</body></html>`;
}
const server = createServer((req, res) => {
  const path = new URL(req.url, "http://local").pathname;
  if (path === "/script" || path === "/asset") {
    res.writeHead(200, { "Content-Type": "application/javascript" });
    res.end("");
    return;
  }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(page(path));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
fixturePort = server.address().port;
const driver = startChrome(exe, join(temp, "profile")),
  results = { fixtures: {}, layouts: [] };
try {
  await sleep(1000);
  results.chrome = (await driver.send("Browser.getVersion")).product;
  const { id } = await driver.send("Extensions.loadUnpacked", { path: ext });
  const base = `chrome-extension://${id}`;
  const helper = await driver.open(base + "/report.html", 390, 900);
  await sleep(300);
  const worker = await until(
    async () =>
      (await driver.send("Target.getTargets")).targetInfos.find(
        (t) => t.type === "service_worker" && t.url.startsWith(base),
      ),
    "worker",
  );
  const { sessionId: workerSession } = await driver.send(
    "Target.attachToTarget",
    { targetId: worker.targetId, flatten: true },
  );
  await driver.send("Network.enable", {}, workerSession);
  const trigger = async (tab) => {
    const url = await tab.ev("location.href");
    const outer = await until(
      async () =>
        (
          await driver.send("Target.getTargets", { filter: [{}] })
        ).targetInfos.find((t) => t.type === "tab" && t.url === url),
      "outer tab",
    );
    await driver.send("Extensions.triggerAction", {
      id,
      targetId: outer.targetId,
    });
  };
  const inspect = async (name, host = "127.0.0.1") => {
    const url = `http://${host}:${fixturePort}/${name}`,
      tab = await driver.open(url, 900, 700);
    await until(() => tab.ev("document.readyState==='complete'"), "ready " + name);
    await sleep(name === "frames" ? 600 : 120);
    await driver.send("Target.activateTarget", { targetId: tab.targetId });
    await trigger(tab);
    const info = await until(
      async () =>
        (await driver.send("Target.getTargets")).targetInfos.find(
          (t) => t.url === base + "/popup.html",
        ),
      "native popup",
    );
    const popup = await driver.attach(info.targetId);
    if (name === "empty") {
      await until(
        () =>
          popup.ev(
            "document.getElementById('gauge-box')?.dataset.state==='scanning'",
          ),
        "native loading",
      );
      await popup.shot(join(out, "native_loading.png"));
      results.loading = await popup.ev(
        "({vertical:document.documentElement.scrollHeight>innerHeight,horizontal:document.documentElement.scrollWidth>innerWidth})",
      );
      assert.equal(results.loading.vertical, false);
      assert.equal(results.loading.horizontal, false);
    }
    await until(
      async () =>
        await popup.ev(
          "document.getElementById('gauge-box')?.dataset.state==='done'",
        ),
      "assessment",
    );
    const rec = await until(
      () =>
        helper.ev(
          `chrome.storage.session.get(null).then(s=>Object.values(s).find(r=>r.state==='done'&&r.url===${JSON.stringify(url)}&&r.scope==='page'))`,
        ),
      "DOM record " + name,
    );
    assert.ok(rec?.result?.evidence?.dom, "DOM reached the backend: " + name);
    results.fixtures[name] = {
      category: rec.result.assessment.category,
      dom: rec.result.evidence.dom,
      errors: popup.errors(),
    };
    if (name === "long-host")
      await popup.shot(join(out, "native_long_hostname.png"));
    if (name === "insecure") {
      results.native_popup = await popup.ev(
        "({width:innerWidth,height:innerHeight,bodyHeight:document.body.scrollHeight,scroll:document.documentElement.scrollHeight>innerHeight,horizontal:document.documentElement.scrollWidth>innerWidth})",
      );
      await popup.shot(join(out, "native_popup.png"));
      await popup.ev("document.getElementById('open-report').click();true");
      results.reportId = rec.id;
    }
    await driver
      .send("Target.closeTarget", { targetId: info.targetId })
      .catch(() => {});
    await driver.send("Target.closeTarget", { targetId: tab.targetId });
    await sleep(250);
    return rec;
  };
  await driver.send(
    "Network.emulateNetworkConditions",
    {
      offline: false,
      latency: 700,
      downloadThroughput: -1,
      uploadThroughput: -1,
    },
    workerSession,
  );
  for (const name of [
    "empty",
    "benign",
    "insecure",
    "external",
    "hidden",
    "missing",
    "orphan",
    "malformed",
    "frames",
    "resources",
    "large",
    "origins",
    "redirect",
  ]) {
    await inspect(name);
    if (name === "empty")
      await driver.send(
        "Network.emulateNetworkConditions",
        {
          offline: false,
          latency: 0,
          downloadThroughput: -1,
          uploadThroughput: -1,
        },
        workerSession,
      );
  }
  await inspect(
    "long-host",
    "customer-support-and-account-recovery.example-services.webguard.local",
  );
  const f = (n) => results.fixtures[n].dom.features;
  assert.equal(f("empty").password_count, 0);
  assert.equal(f("benign").password_count, 1);
  assert.equal(results.fixtures.insecure.category, "high_risk");
  assert.ok(
    !results.fixtures.external.dom.rules.some(
      (r) => r.status === "fired" && r.severity === "high",
    ),
  );
  assert.equal(f("hidden").hidden_password_count, 1);
  assert.equal(f("missing").credential_forms[0].has_action, false);
  assert.equal(f("orphan").orphan_password_count, 1);
  assert.equal(f("malformed").credential_forms[0].action_scheme, "invalid");
  assert.equal(f("frames").iframe_count, 2);
  assert.ok(f("frames").inaccessible_frame_count >= 1);
  assert.equal(results.fixtures.large.dom.state, "partial");
  assert.ok(f("large").link_count <= 5000);
  assert.equal(results.fixtures.origins.dom.state, "partial");
  assert.ok(f("origins").link_origins.length <= 16);
  assert.ok(f("resources").placeholder_link_count >= 2);
  assert.ok(f("redirect").meta_refresh.length);
  {
    const tab = await driver.open("chrome://version", 900, 700);
    await until(() => tab.ev("document.readyState==='complete'"), "tab ready");
    await sleep(150);
    await trigger(tab);
    const info = await until(
      async () =>
        (await driver.send("Target.getTargets")).targetInfos.find(
          (t) => t.url === base + "/popup.html",
        ),
      "unsupported popup",
    );
    const p = await driver.attach(info.targetId);
    await until(
      () =>
        p.ev("document.getElementById('gauge-box')?.dataset.state==='problem'"),
      "unsupported state",
    );
    results.unsupported = await p.ev(
      "({category:document.getElementById('badge').textContent,score:document.getElementById('risk').textContent,vertical:document.documentElement.scrollHeight>innerHeight})",
    );
    assert.equal(results.unsupported.score, "–");
    assert.equal(results.unsupported.vertical, false);
    await p.shot(join(out, "native_unsupported.png"));
    await driver.send("Target.closeTarget", { targetId: info.targetId });
    await driver.send("Target.closeTarget", { targetId: tab.targetId });
  }
  {
    const url = `http://127.0.0.1:${fixturePort}/insecure`;
    const response = await fetch(`http://127.0.0.1:${port}/api/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const baseResult = await response.json();
    results.hybrid_comparison = {
      urlOnly: baseResult.assessment.category,
      combined: results.fixtures.insecure.category,
    };
    assert.equal(results.hybrid_comparison.urlOnly, "caution");
    assert.equal(results.hybrid_comparison.combined, "high_risk");
  }
  // Dynamic page updates: same document/URL, newly added form must invalidate the structural cache.
  {
    const tab = await driver.open(
      `http://127.0.0.1:${fixturePort}/dynamic`,
      900,
      700,
    );
    // The action popup closes when its tab commits a navigation, so trigger only after load.
    await until(() => tab.ev("document.readyState==='complete'"), "dynamic ready");
    // A just-closed popup can still be listed; attaching to it would fail.
    await until(
      async () =>
        !(await driver.send("Target.getTargets")).targetInfos.some(
          (t) => t.url === base + "/popup.html",
        ),
      "previous popup closed",
    );
    await driver.send("Target.activateTarget", { targetId: tab.targetId });
    await trigger(tab);
    let popupInfo = await until(
      async () =>
        (await driver.send("Target.getTargets")).targetInfos.find(
          (t) => t.url === base + "/popup.html",
        ),
      "dynamic popup",
    );
    let popup = await driver.attach(popupInfo.targetId);
    await until(
      () =>
        popup.ev(
          "document.getElementById('gauge-box')?.dataset.state==='done'",
        ),
      "dynamic initial",
    );
    const before = await helper.ev(
      `chrome.storage.session.get(null).then(s=>Object.values(s).find(r=>r.scope==='page'&&r.url.endsWith('/dynamic')&&r.state==='done'))`,
    );
    await tab.ev(
      "(()=>{const f=document.createElement('form');f.method='post';f.action='/submit';const p=document.createElement('input');p.type='password';f.append(p);document.body.append(f);return true;})()",
    );
    await popup.ev("document.getElementById('retry').click();true");
    await until(
      () =>
        popup.ev(
          "document.getElementById('gauge-box')?.dataset.state==='done'",
        ),
      "dynamic recheck",
    );
    const after = await helper.ev(
      `chrome.storage.session.get(null).then(s=>Object.values(s).find(r=>r.scope==='page'&&r.url.endsWith('/dynamic')&&r.state==='done'&&r.id!==${JSON.stringify(before.id)}))`,
    );
    assert.equal(after.result.evidence.dom.features.password_count, 1);
    assert.equal(after.result.assessment.category, "high_risk");
    results.dynamic = {
      before: before.id,
      after: after.id,
      category: after.result.assessment.category,
    };
    // Regression: repeated report rechecks keep inspecting the source page (previously the 2nd became address-only).
    const rep = await driver.open(`${base}/report.html?id=${after.id}`, 1280, 900);
    await until(
      () => rep.ev("!document.getElementById('report').hidden"),
      "dynamic report",
    );
    results.report_rechecks = [];
    for (let i = 0; i < 2; i++) {
      const previous = await rep.ev("location.search");
      await rep.ev("document.getElementById('recheck-top').click();true");
      await until(
        async () =>
          (await rep.ev("location.search")) !== previous &&
          (await rep.ev("!document.getElementById('report').hidden")),
        "report recheck " + i,
      );
      const rid = new URLSearchParams(await rep.ev("location.search")).get(
        "id",
      );
      const rec = await helper.ev(
        `chrome.storage.session.get('a:${rid}').then(s=>s['a:${rid}'])`,
      );
      results.report_rechecks.push({
        scope: rec.scope,
        dom: rec.result.evidence.dom?.state,
        label: await rep.ev(
          "document.getElementById('recheck-label').textContent",
        ),
        summary: await rep.ev(
          "document.querySelector('.card[data-key=page] .card-status')?.textContent",
        ),
      });
    }
    for (const r of results.report_rechecks) {
      assert.equal(r.scope, "page", JSON.stringify(r));
      assert.equal(r.dom, "inspected", JSON.stringify(r));
      assert.equal(r.label, "Recheck page");
      assert.equal(r.summary, "Suspicious form detected");
    }
    assert.deepEqual(rep.errors(), []);
    await driver.send("Target.closeTarget", { targetId: rep.targetId });
    // Opening the report tab already closes the action popup.
    await driver
      .send("Target.closeTarget", { targetId: popupInfo.targetId })
      .catch(() => {});
  }
  // Without activeTab permission, scripting rejects; the URL assessment still completes.
  {
    const tab = await driver.open(
      `http://127.0.0.1:${fixturePort}/ungranted`,
      900,
      700,
    );
    await driver.send("Target.activateTarget", { targetId: tab.targetId });
    await until(
      () => tab.ev("document.readyState==='complete'"),
      "ungranted page ready",
    );
    const actual = await helper.ev(
      "chrome.tabs.query({}).then(t=>Math.max(...t.map(x=>x.id)))",
    );
    const rec = await helper.ev(
      `chrome.runtime.sendMessage({type:'assess',inspect:true,force:true,tabId:${actual},url:${JSON.stringify(`http://127.0.0.1:${fixturePort}/ungranted`)}})`,
    );
    assert.ok(rec?.result, JSON.stringify(rec));
    assert.equal(rec.result.evidence.dom.state, "unavailable");
    results.permission_fallback = {
      state: rec.result.evidence.dom.state,
      category: rec.result.assessment.category,
    };
  }
  // Stable layout across all verdicts and effective 100%, 125%, 150% popup viewports.
  const seed = await helper.ev(
    "chrome.storage.session.get(null).then(s=>Object.values(s).find(r=>r.state==='done'&&r.result))",
  );
  for (const cat of [
    "low_risk",
    "caution",
    "high_risk",
    "dangerous",
    "unknown",
  ]) {
    const url = `https://${cat.replace("_", "-")}.example/`;
    await helper.ev(
      `(()=>{const r=${JSON.stringify(seed)};r.id='layout-'+${JSON.stringify(cat)};r.scope='url';r.url=${JSON.stringify(url)};r.finishedAt=Date.now();r.result.assessment.category=${JSON.stringify(cat)};r.result.assessment.risk_score=${cat === "unknown" ? 50 : cat === "dangerous" ? 95 : cat === "low_risk" ? 17 : cat === "high_risk" ? 76 : 51};r.result.evidence.url=r.url;r.result.evidence.host=new URL(r.url).hostname;r.result.assessment.safety_score=r.result.assessment.category==='unknown'?null:100-r.result.assessment.risk_score;return chrome.storage.session.set({['u:'+r.url]:r});})()`,
    );
    for (const [width, height] of [
      [360, 600],
      [360, 480],
      [360, 400],
    ]) {
      const p = await driver.open(
        `${base}/popup.html?url=${encodeURIComponent(url)}`,
        width,
        height,
      );
      await until(
        () =>
          p.ev("document.getElementById('gauge-box')?.dataset.state==='done'"),
        "layout",
      );
      const layout = await p.ev(
        "({vertical:document.documentElement.scrollHeight>innerHeight,horizontal:document.documentElement.scrollWidth>innerWidth,bodyHeight:document.body.getBoundingClientRect().height,button:document.getElementById('open-report').getBoundingClientRect().bottom,footer:document.querySelector('footer').getBoundingClientRect().bottom})",
      );
      results.layouts.push({ cat, width, height, ...layout });
      await p.shot(join(out, `popup_${cat}_${width}_${height}.png`));
      assert.equal(layout.horizontal, false, "horizontal " + cat + width);
      assert.equal(layout.vertical, false, "vertical " + cat + width);
      assert.ok(layout.footer <= height, "footer " + cat + width);
      await driver.send("Target.closeTarget", { targetId: p.targetId });
    }
  }
  // Real extension-origin browser zoom, then the actual toolbar popup (not a resized tab).
  results.extension_tab_zoom_attempts = [];
  for (const zoom of [1, 1.25, 1.5]) {
    await helper.ev(
      `chrome.tabs.getCurrent().then(t=>chrome.tabs.setZoom(t.id,${zoom}))`,
    );
    const url = `http://127.0.0.1:${fixturePort}/zoom-${zoom}`;
    const tab = await driver.open(url, 900, 700);
    await until(() => tab.ev("document.readyState==='complete'"), "tab ready");
    await sleep(150);
    await trigger(tab);
    const info = await until(
      async () =>
        (await driver.send("Target.getTargets")).targetInfos.find(
          (t) => t.url === base + "/popup.html",
        ),
      "zoom popup",
    );
    const popup = await driver.attach(info.targetId);
    await until(
      () =>
        popup.ev(
          "document.getElementById('gauge-box')?.dataset.state==='done'",
        ),
      "zoom result",
    );
    const layout = await popup.ev(
      "({width:innerWidth,height:innerHeight,ratio:devicePixelRatio,bodyHeight:document.body.getBoundingClientRect().height,vertical:document.documentElement.scrollHeight>innerHeight,horizontal:document.documentElement.scrollWidth>innerWidth,footer:document.querySelector('footer').getBoundingClientRect().bottom})",
    );
    results.extension_tab_zoom_attempts.push({ zoom, ...layout });
    await popup.shot(join(out, `native_zoom_${zoom}.png`));
    assert.equal(layout.vertical, false, "native zoom " + zoom);
    assert.equal(layout.horizontal, false);
    assert.ok(layout.footer <= layout.height + 1);
    await driver
      .send("Target.closeTarget", { targetId: info.targetId })
      .catch(() => {});
    await driver.send("Target.closeTarget", { targetId: tab.targetId });
    await sleep(200);
  }
  await helper.ev(
    "chrome.tabs.getCurrent().then(t=>chrome.tabs.setZoom(t.id,1))",
  );
  // Native permission-denied and long copy states retain accessible controls.
  {
    const p = await driver.open(
      `${base}/popup.html?url=${encodeURIComponent("https://low-risk.example/")}`,
      360,
      400,
    );
    await until(
      () =>
        p.ev("document.getElementById('gauge-box')?.dataset.state==='done'"),
      "fallback copy",
    );
    await p.ev(
      "chrome.permissions.request=async()=>false;document.getElementById('auto').click();true",
    );
    await sleep(100);
    results.permission_layout = await p.ev(
      "({height:document.documentElement.scrollHeight,footer:document.querySelector('footer').getBoundingClientRect().bottom})",
    );
    assert.ok(results.permission_layout.footer <= 400);
    await p.size(360, 600);
    await p.ev(
      "document.getElementById('note').textContent='Eine ausführlichere Beschreibung: Einige Warnzeichen erfordern Ihre Aufmerksamkeit. Prüfen Sie die Website sorgfältig.';true",
    );
    results.long_copy = await p.ev(
      "({height:document.documentElement.scrollHeight,footer:document.querySelector('footer').getBoundingClientRect().bottom,horizontal:document.documentElement.scrollWidth>innerWidth})",
    );
    assert.ok(results.long_copy.footer <= 600);
    assert.equal(results.long_copy.horizontal, false);
    await p.shot(join(out, "popup_long_copy.png"));
  }
  // Genuine failed fetch in the installed worker; the local backend remains running.
  {
    await driver.send(
      "Network.emulateNetworkConditions",
      { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 },
      workerSession,
    );
    const p = await driver.open(
      `${base}/popup.html?url=${encodeURIComponent("https://offline-new.webguard.example/")}`,
      360,
      400,
    );
    await until(
      () =>
        p.ev("document.getElementById('gauge-box')?.dataset.state==='problem'"),
      "offline popup",
    );
    results.offline = await p.ev(
      "({retry:!document.getElementById('retry').hidden,footer:document.querySelector('footer').getBoundingClientRect().bottom,vertical:document.documentElement.scrollHeight>innerHeight})",
    );
    assert.equal(results.offline.retry, true);
    assert.equal(results.offline.vertical, false);
    await p.shot(join(out, "popup_offline.png"));
    await driver.send(
      "Network.emulateNetworkConditions",
      {
        offline: false,
        latency: 0,
        downloadThroughput: -1,
        uploadThroughput: -1,
      },
      workerSession,
    );
  }
  // Full report and a complete loop while visible; no backend requests are made by the illustration.
  const report = await driver.open(
    `${base}/report.html?id=${results.reportId}`,
    1280,
    900,
  );
  await driver.send("Target.activateTarget", { targetId: report.targetId });
  await until(
    () => report.ev("!document.getElementById('report').hidden"),
    "report",
  );
  assert.match(
    await report.ev("document.querySelector('.card[data-key=page] .card-text').textContent"),
    /insecure/,
  );
  await sleep(450);
  await report.shot(join(out, "report_dom_desktop.png"), true);
  const requests = () =>
    driver.events.filter(
      (e) =>
        e.method === "Network.requestWillBeSent" &&
        e.params.request.url.includes("/api/v1/analyze"),
    );
  // The single-screen report has no looping illustration, and an open report never contacts the backend.
  const before = requests().length;
  await sleep(3000);
  results.animation = await report.ev(
    "({infinite:document.getAnimations().filter(a=>a.effect?.getComputedTiming().iterations===Infinity).length,oneScreen:document.documentElement.scrollHeight<=innerHeight})",
  );
  assert.equal(results.animation.infinite, 0);
  assert.equal(results.animation.oneScreen, true);
  assert.equal(requests().length, before);
  await driver.send(
    "Emulation.setEmulatedMedia",
    { features: [{ name: "prefers-reduced-motion", value: "reduce" }] },
    report.sessionId,
  );
  results.animation.reduced = await report.ev(
    "getComputedStyle(document.getElementById('report')).animationName",
  );
  assert.equal(results.animation.reduced, "none");
  await report.size(390, 900);
  await report.shot(join(out, "report_dom_mobile.png"), true);
  assert.equal(
    await report.ev("document.documentElement.scrollWidth>innerWidth"),
    false,
  );
  const bodies = requests()
    .map((e) => e.params.request.postData || "")
    .join("");
  assert.ok(!bodies.includes(SECRET));
  assert.ok(!bodies.includes(TOKEN));
  results.privacy = {
    requests: requests().length,
    noTypedValues: true,
    noResourceQueries: true,
  };
  results.errors = report.errors();
  assert.deepEqual(results.errors, []);
  for (const [name, r] of Object.entries(results.fixtures))
    assert.deepEqual(r.errors, [], name);
  // Native desktop scaling probes in independent real Chrome processes.
  results.desktop_scaling = [];
  for (const scale of [1.25, 1.5]) {
    const probe = startChrome(exe, join(temp, "profile-scale-" + scale), {
      scale,
    });
    try {
      await sleep(650);
      const { id: probeId } = await probe.send("Extensions.loadUnpacked", {
        path: ext,
      });
      const url = `http://127.0.0.1:${fixturePort}/insecure`,
        tab = await probe.open(url, 900, 700);
      await sleep(200);
      const outer = await until(
        async () =>
          (
            await probe.send("Target.getTargets", { filter: [{}] })
          ).targetInfos.find((t) => t.type === "tab" && t.url === url),
        "scaled outer tab",
      );
      await probe.send("Extensions.triggerAction", {
        id: probeId,
        targetId: outer.targetId,
      });
      const info = await until(
        async () =>
          (await probe.send("Target.getTargets")).targetInfos.find(
            (t) => t.url === `chrome-extension://${probeId}/popup.html`,
          ),
        "scaled popup",
      );
      const popup = await probe.attach(info.targetId);
      await until(
        () =>
          popup.ev(
            "document.getElementById('gauge-box')?.dataset.state==='done'",
          ),
        "scaled result",
      );
      const layout = await popup.ev(
        "({width:innerWidth,height:innerHeight,ratio:devicePixelRatio,bodyHeight:document.body.getBoundingClientRect().height,vertical:document.documentElement.scrollHeight>innerHeight,horizontal:document.documentElement.scrollWidth>innerWidth,footer:document.querySelector('footer').getBoundingClientRect().bottom})",
      );
      results.desktop_scaling.push({ scale, ...layout });
      assert.ok(Math.abs(layout.ratio - scale) < 0.01);
      assert.equal(layout.vertical, false);
      assert.equal(layout.horizontal, false);
      assert.ok(layout.footer <= layout.height + 1);
      await popup.shot(join(out, `native_desktop_scale_${scale}.png`));
    } finally {
      probe.close();
    }
  }
  results.assertions =
    "All DOM extraction, hybrid assessment, native popup, layout, privacy and report assertions passed.";
} catch (error) {
  results.error = error.stack;
  process.exitCode = 1;
} finally {
  writeFileSync(
    join(out, "browser-results.json"),
    JSON.stringify(results, null, 2),
  );
  console.log(
    JSON.stringify(
      {
        chrome: results.chrome,
        assertions: results.assertions,
        error: results.error,
      },
      null,
      2,
    ),
  );
  driver.close();
  server.closeAllConnections();
  server.close();
}
