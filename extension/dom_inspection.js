import { prepareUrl } from "./api.js";
import { extractDom } from "./dom_extractor.js";
export const DOM_SCHEMA = "dom-v1";
export const unavailable = (reason = "permission", state = "unavailable") => ({
  schema_version: DOM_SCHEMA,
  state,
  reason,
});
// Validate only the allowlisted structural envelope before sending it to the loopback API.
export function validateSnapshot(value) {
  if (
    !value ||
    value.schema_version !== DOM_SCHEMA ||
    !["inspected", "partial"].includes(value.state) ||
    !value.features
  )
    return false;
  if (JSON.stringify(value).length > 32768) return false;
  const f = value.features;
  for (const [key, v] of Object.entries(f)) {
    if (key.endsWith("_count") && (!Number.isInteger(v) || v < 0 || v > 5000))
      return false;
  }
  if (!Array.isArray(f.credential_forms) || f.credential_forms.length > 32)
    return false;
  const origin = (s) => {
    try {
      const u = new URL(s);
      return (
        ["http:", "https:"].includes(u.protocol) &&
        u.origin === s &&
        s.length <= 256
      );
    } catch {
      return false;
    }
  };
  if (!origin(value.page_origin)) return false;
  for (const key of ["link_origins", "iframe_origins", "resource_origins"])
    if (
      !Array.isArray(f[key]) ||
      f[key].length > 32 ||
      f[key].some(
        (r) =>
          !r ||
          typeof r !== "object" ||
          Array.isArray(r) ||
          !origin(r.origin) ||
          !Number.isInteger(r.count) ||
          r.count < 0 ||
          r.count > 5000,
      )
    )
      return false;
  if (
    f.credential_forms.some(
      (r) => !r || typeof r !== "object" || Array.isArray(r),
    )
  )
    return false;
  for (const [key, total] of [
    ["link_origins", f.link_count],
    ["iframe_origins", f.iframe_count],
    ["resource_origins", f.resource_count],
  ]) {
    const rows = f[key];
    if (
      rows.some((r) =>
        Object.keys(r).some((k) => !["origin", "count"].includes(k)),
      ) ||
      new Set(rows.map((r) => r.origin)).size !== rows.length ||
      rows.reduce((n, r) => n + r.count, 0) > total
    )
      return false;
  }
  if (
    f.credential_forms.reduce((n, r) => n + r.password_count, 0) >
    f.password_count
  )
    return false;
  const counts = [
    "form_count",
    "password_count",
    "orphan_password_count",
    "hidden_password_count",
    "link_count",
    "placeholder_link_count",
    "unusual_link_count",
    "iframe_count",
    "inaccessible_frame_count",
    "accessible_frame_form_count",
    "script_count",
    "resource_count",
  ];
  const bools = ["title_present", "title_has_host", "truncated"];
  const keys = [
    ...counts,
    ...bools,
    "credential_forms",
    "link_origins",
    "iframe_origins",
    "resource_origins",
    "title_length",
    "meta_refresh",
  ];
  if (
    Object.keys(value).some(
      (k) =>
        !["schema_version", "state", "page_origin", "features"].includes(k),
    ) ||
    Object.keys(f).length !== keys.length ||
    Object.keys(f).some((k) => !keys.includes(k))
  )
    return false;
  if (
    counts.some((k) => !Number.isInteger(f[k]) || f[k] < 0 || f[k] > 5000) ||
    bools.some((k) => typeof f[k] !== "boolean")
  )
    return false;
  if (
    !Number.isInteger(f.title_length) ||
    f.title_length < 0 ||
    f.title_length > 10000
  )
    return false;
  if (
    !Array.isArray(f.meta_refresh) ||
    f.meta_refresh.length > 8 ||
    f.meta_refresh.some(
      (r) =>
        !r ||
        typeof r !== "object" ||
        Array.isArray(r) ||
        Object.keys(r).some((k) => !["origin", "delay_seconds"].includes(k)) ||
        !origin(r.origin) ||
        !Number.isFinite(r.delay_seconds) ||
        r.delay_seconds < 0 ||
        r.delay_seconds > 86400,
    )
  )
    return false;
  for (const form of f.credential_forms) {
    const allowed = [
      "action_origin",
      "action_scheme",
      "method",
      "password_count",
      "hidden_password_count",
      "has_action",
      "action_same_page",
    ];
    if (
      Object.keys(form).length !== allowed.length ||
      Object.keys(form).some((k) => !allowed.includes(k)) ||
      !["get", "post", "dialog"].includes(form.method) ||
      !["http", "https", "other", "invalid"].includes(form.action_scheme)
    )
      return false;
    if (
      !Number.isInteger(form.password_count) ||
      form.password_count < 0 ||
      form.password_count > 5000 ||
      !Number.isInteger(form.hidden_password_count) ||
      form.hidden_password_count < 0 ||
      form.hidden_password_count > form.password_count
    )
      return false;
    if (
      typeof form.has_action !== "boolean" ||
      typeof form.action_same_page !== "boolean"
    )
      return false;
    if (["http", "https"].includes(form.action_scheme)) {
      if (
        !origin(form.action_origin) ||
        !form.action_origin.startsWith(form.action_scheme + ":")
      )
        return false;
    } else if (form.action_origin !== null) return false;
  }
  if (
    f.hidden_password_count > f.password_count ||
    f.orphan_password_count > f.password_count ||
    f.placeholder_link_count > f.link_count ||
    f.unusual_link_count > f.link_count ||
    f.inaccessible_frame_count > f.iframe_count
  )
    return false;
  return true;
}
export async function inspectTab(api, tabId, url, { timeoutMs = 1500 } = {}) {
  if (tabId < 0 || !prepareUrl(url).ok || !api.scripting)
    return { dom: unavailable("unsupported") };
  let timer;
  try {
    const before = await api.tabs.get(tabId);
    if (!before?.url) return { dom: unavailable("permission") };
    if (prepareUrl(before.url).url !== prepareUrl(url).url)
      return { dom: unavailable("navigation_changed"), changed: true };
    const result = await Promise.race([
      api.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        world: "ISOLATED",
        func: extractDom,
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
      }),
    ]);
    const after = await api.tabs.get(tabId);
    if (!after?.url) return { dom: unavailable("permission") };
    if (prepareUrl(after.url).url !== prepareUrl(url).url)
      return { dom: unavailable("navigation_changed"), changed: true };
    const main = result?.find((r) => r.frameId === 0),
      snapshot = main?.result?.snapshot;
    if (!validateSnapshot(snapshot))
      return { dom: unavailable("schema", "failed") };
    return {
      dom: snapshot,
      documentId: main.documentId,
      navigationStart: main.result.navigation_start,
    };
  } catch (error) {
    return {
      dom: unavailable(
        error.message === "timeout"
          ? "timeout"
          : /permission|access|cannot/i.test(error.message)
            ? "permission"
            : "extraction",
        error.message === "timeout" ? "failed" : "unavailable",
      ),
    };
  } finally {
    clearTimeout(timer);
  }
}
