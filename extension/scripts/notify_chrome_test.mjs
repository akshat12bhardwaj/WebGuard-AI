// Automatic mode + notifications in real Chrome. The optional-permission prompt cannot be clicked headlessly, so a
// temporary copy declares tabs+notifications as granted; everything else (worker, listeners, API, notifications) is real.
// Usage: node notify_chrome_test.mjs <chrome.exe> <extensionDir> <outDir> [backendPort=8001]
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { startChrome, sleep, until } from "./chrome_driver.mjs";

const [exe, source, output, port = "8001"] = process.argv.slice(2),
  out = resolve(output);
mkdirSync(out, { recursive: true });
const temp = mkdtempSync(join(tmpdir(), "webguard-notify-")),
  ext = join(temp, "extension");
cpSync(source, ext, { recursive: true, filter: (p) => !p.includes("node_modules") });
for (const name of ["manifest.json", "api.js"]) {
  const path = join(ext, name);
  writeFileSync(path, readFileSync(path, "utf8").replaceAll("127.0.0.1:8000", `127.0.0.1:${port}`));
}
const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
manifest.permissions.push(...manifest.optional_permissions);
delete manifest.optional_permissions;
writeFileSync(join(ext, "manifest.json"), JSON.stringify(manifest));

const server = createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(`<!doctype html><title>Fixture</title><form method=post action="http://evil.test/x"><input type=password></form>`);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const fixture = server.address().port;
const driver = startChrome(exe, join(temp, "profile")),
  results = {};
try {
  await sleep(1000);
  results.chrome = (await driver.send("Browser.getVersion")).product;
  const { id } = await driver.send("Extensions.loadUnpacked", { path: ext });
  const base = `chrome-extension://${id}`;
  const helper = await driver.open(base + "/report.html", 800, 600);
  await until(() => helper.ev("document.readyState==='complete'"), "helper");
  const workerTarget = await until(async () => (await driver.send("Target.getTargets")).targetInfos
    .find((t) => t.type === "service_worker" && t.url.startsWith(base)), "worker");
  const worker = await driver.attach(workerTarget.targetId);
  results.auto_enabled = await worker.ev("chrome.permissions.contains({permissions:['tabs','notifications']})");
  assert.equal(results.auto_enabled, true);
  // Record real calls made by the background code (the wrappers forward to Chrome unchanged).
  await worker.ev(`(() => {
    globalThis.__notes = []; globalThis.__scripts = 0;
    const create = chrome.notifications.create.bind(chrome.notifications);
    chrome.notifications.create = (nid, opt) => { __notes.push({ nid, title: opt.title, message: opt.message, context: opt.contextMessage, at: Date.now() }); return create(nid, opt); };
    const exec = chrome.scripting.executeScript.bind(chrome.scripting);
    chrome.scripting.executeScript = (...a) => { __scripts++; return exec(...a); };
    return true; })()`);
  const notes = () => worker.ev("__notes");
  const visit = async (tab, url) => {
    await driver.send("Page.navigate", { url }, tab.sessionId);
    await until(() => tab.ev("document.readyState==='complete'"), "load " + url);
  };
  const recordFor = (url) => helper.ev(`chrome.storage.session.get('u:${url}').then(s=>s['u:${url}'])`);

  const tab = await driver.open("about:blank", 900, 700);
  await driver.send("Target.activateTarget", { targetId: tab.targetId });
  const a = `http://127.0.0.1:${fixture}/first`;
  await visit(tab, a);
  await until(async () => (await notes()).length === 1, "first notification");
  const recA = await until(async () => { const r = await recordFor(a); return r?.state === "done" && r; }, "record a");
  const [n1] = await notes();
  const label = { low_risk: "Low risk", caution: "Caution", high_risk: "High risk", dangerous: "Dangerous", unknown: "Unknown" }[recA.result.assessment.category];
  assert.equal(n1.nid, "wg:" + recA.id, "notification belongs to this page's record");
  assert.ok(n1.title.startsWith(label), "title category agrees with assessment");
  if (recA.result.assessment.category !== "unknown") assert.ok(n1.title.includes(`${recA.result.assessment.risk_score}/100`));
  assert.equal(n1.message, "127.0.0.1");
  results.first = { ...n1, category: recA.result.assessment.category, score: recA.result.assessment.risk_score };
  results.visible_in_chrome = await worker.ev(`chrome.notifications.getAll().then(all=>Object.keys(all))`);
  assert.ok(results.visible_in_chrome.includes(n1.nid), "Chrome holds the notification");
  await sleep(3000);
  results.cleared_after_lifetime = !(await worker.ev(`chrome.notifications.getAll().then(all=>Object.keys(all))`)).includes(n1.nid);
  assert.ok(results.cleared_after_lifetime);

  // Same site again (reload + another path): no duplicate notification.
  await visit(tab, a);
  await visit(tab, `http://127.0.0.1:${fixture}/second`);
  await sleep(2500);
  results.same_site_notifications = (await notes()).length;
  assert.equal(results.same_site_notifications, 1, "same host is not re-notified");

  // Another site: one new notification for the new host only.
  const b = `http://localhost:${fixture}/third`;
  await visit(tab, b);
  await until(async () => (await notes()).length === 2, "second-site notification");
  results.second = (await notes())[1];
  assert.equal(results.second.message, "localhost");

  // Rapid navigation: only the page the tab ends on may be notified.
  await driver.send("Page.navigate", { url: `http://127.0.0.2:${fixture}/left-quickly` }, tab.sessionId);
  await sleep(60);
  await visit(tab, `http://127.0.0.1:${fixture}/landed`);
  await sleep(3000);
  results.rapid = (await notes()).slice(2).map((n) => n.message);
  assert.ok(!results.rapid.includes("127.0.0.2"), "a page the tab left is never notified");

  // Background tab: badge updates, no notification.
  const bg = await driver.open(`http://127.0.0.3:${fixture}/background`, 900, 700);
  await driver.send("Target.activateTarget", { targetId: tab.targetId });
  await sleep(3000);
  results.background_notified = (await notes()).some((n) => n.message === "127.0.0.3");
  assert.equal(results.background_notified, false);

  // Unsupported page: no request, no notification.
  const before = (await notes()).length;
  await visit(tab, "chrome://version");
  await sleep(1500);
  assert.equal((await notes()).length, before);

  // Automatic checks never inspect page content.
  results.scripting_calls_during_auto = await worker.ev("__scripts");
  assert.equal(results.scripting_calls_during_auto, 0);
  results.contexts = [...new Set((await notes()).map((n) => n.context))];
  await driver.send("Target.closeTarget", { targetId: bg.targetId });
  results.assertions = "Automatic checks, notification wording/ownership/dedupe/lifetime and address-only behaviour passed.";
} catch (error) {
  results.error = error.stack;
  process.exitCode = 1;
} finally {
  driver.close();
  server.close();
  writeFileSync(join(out, "notify-results.json"), JSON.stringify(results, null, 2));
  console.log(JSON.stringify({ chrome: results.chrome, assertions: results.assertions, error: results.error?.slice(0, 1200) }, null, 2));
}
