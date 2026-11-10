// Small CDP pipe driver used only by browser verification, never shipped as executable extension code.
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export function startChrome(executable, profile, { scale = 1 } = {}) {
  const proc = spawn(
    executable,
    [
      "--headless=new",
      `--force-device-scale-factor=${scale}`,
      "--window-size=1280,1000",
      "--host-resolver-rules=MAP *.webguard.local 127.0.0.1",
      `--user-data-dir=${profile}`,
      "--remote-debugging-pipe",
      "--enable-unsafe-extension-debugging",
      "--no-first-run",
      "about:blank",
    ],
    { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] },
  );
  let seq = 0,
    buffer = "";
  const pending = new Map(),
    events = [];
  proc.stdio[4].on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    let i;
    while ((i = buffer.indexOf("\0")) >= 0) {
      const msg = JSON.parse(buffer.slice(0, i));
      buffer = buffer.slice(i + 1);
      if (msg.id && pending.has(msg.id)) {
        const p = pending.get(msg.id);
        clearTimeout(p.timer);
        pending.delete(msg.id);
        msg.error
          ? p.reject(new Error(msg.error.message))
          : p.resolve(msg.result);
      } else if (msg.method) events.push(msg);
    }
  });
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = ++seq;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error("CDP timeout: " + method));
      }, 30000);
      pending.set(id, { resolve, reject, timer });
      proc.stdio[3].write(
        JSON.stringify({ id, method, params, sessionId }) + "\0",
      );
    });
  async function attach(targetId) {
    const { sessionId } = await send("Target.attachToTarget", {
      targetId,
      flatten: true,
    });
    await send("Runtime.enable", {}, sessionId);
    return {
      targetId,
      sessionId,
      async ev(expression) {
        const r = await send(
          "Runtime.evaluate",
          { expression, awaitPromise: true, returnByValue: true },
          sessionId,
        );
        if (r.exceptionDetails)
          throw new Error(
            r.exceptionDetails.exception?.description ||
              r.exceptionDetails.text,
          );
        return r.result.value;
      },
      async size(width, height = 600) {
        await send(
          "Emulation.setDeviceMetricsOverride",
          { width, height, deviceScaleFactor: 1, mobile: false },
          sessionId,
        );
      },
      async shot(path, full = false) {
        const { data } = await send(
          "Page.captureScreenshot",
          { format: "png", captureBeyondViewport: full },
          sessionId,
        );
        writeFileSync(path, Buffer.from(data, "base64"));
      },
      errors() {
        return events
          .filter(
            (e) =>
              e.sessionId === sessionId &&
              (e.method === "Runtime.exceptionThrown" ||
                (e.method === "Runtime.consoleAPICalled" &&
                  e.params.type === "error")),
          )
          .map(
            (e) =>
              e.params.exceptionDetails?.exception?.description ||
              e.params.exceptionDetails?.text ||
              JSON.stringify(e.params.args),
          );
      },
    };
  }
  async function open(url, width = 360, height = 600) {
    const { targetId } = await send("Target.createTarget", {
      url: "about:blank",
    });
    const page = await attach(targetId);
    await page.size(width, height);
    await send("Page.navigate", { url }, page.sessionId);
    return page;
  }
  return {
    send,
    attach,
    open,
    events,
    proc,
    close() {
      for (const p of pending.values()) clearTimeout(p.timer);
      proc.kill();
    },
  };
}
export async function until(fn, message, ms = 20000) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    const result = await fn();
    if (result) return result;
    await sleep(80);
  }
  throw new Error("Timed out: " + message);
}
