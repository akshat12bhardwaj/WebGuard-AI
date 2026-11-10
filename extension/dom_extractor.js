// Self-contained: Chrome serializes this function into the isolated page world.
// No form values, page text, HTML, cookies or complete resource URLs leave this function.
export function extractDom() {
  const MAX_NODES = 5000,
    MAX_ORIGINS = 16;
  let frameBudget = 512;
  const f = {
    form_count: 0,
    password_count: 0,
    orphan_password_count: 0,
    hidden_password_count: 0,
    credential_forms: [],
    link_count: 0,
    placeholder_link_count: 0,
    unusual_link_count: 0,
    link_origins: [],
    iframe_count: 0,
    inaccessible_frame_count: 0,
    iframe_origins: [],
    accessible_frame_form_count: 0,
    script_count: 0,
    resource_count: 0,
    resource_origins: [],
    title_present: !!document.title.trim(),
    title_length: Math.min(document.title.length, 10000),
    title_has_host: document.title
      .toLowerCase()
      .includes(location.hostname.toLowerCase()),
    meta_refresh: [],
    truncated: false,
  };
  const origins = { link: new Map(), iframe: new Map(), resource: new Map() },
    forms = new Map();
  function resolve(raw) {
    try {
      if (String(raw).length > 2048) {
        f.truncated = true;
        return null;
      }
      const u = new URL(raw, document.baseURI);
      if (u.origin.length > 256) {
        f.truncated = true;
        return null;
      }
      return u;
    } catch {
      return null;
    }
  }
  function add(kind, u) {
    if (
      !u ||
      !["http:", "https:"].includes(u.protocol) ||
      u.origin.length > 256
    )
      return;
    const map = origins[kind];
    if (!map.has(u.origin) && map.size >= MAX_ORIGINS) {
      f.truncated = true;
      return;
    }
    map.set(u.origin, (map.get(u.origin) || 0) + 1);
  }
  const walker = document.createTreeWalker(
    document.documentElement,
    NodeFilter.SHOW_ELEMENT,
  );
  let node = walker.currentNode,
    visited = 0;
  while (node) {
    if (++visited > MAX_NODES) {
      f.truncated = true;
      break;
    }
    const tag = node.tagName;
    if (tag === "FORM") f.form_count++;
    if (tag === "INPUT" && node.type === "password") {
      if (f.password_count >= 128) {
        f.truncated = true;
        break;
      }
      f.password_count++;
      const style = getComputedStyle(node),
        hidden =
          node.hidden ||
          style.display === "none" ||
          ["hidden", "collapse"].includes(style.visibility) ||
          style.opacity === "0" ||
          !node.getClientRects().length;
      if (hidden) f.hidden_password_count++;
      if (!node.form) f.orphan_password_count++;
      else {
        let entry = forms.get(node.form);
        if (!entry && forms.size < 32) {
          entry = { password_count: 0, hidden_password_count: 0 };
          forms.set(node.form, entry);
        }
        if (entry) {
          entry.password_count++;
          if (hidden) entry.hidden_password_count++;
        } else f.truncated = true;
      }
    }
    if (tag === "A") {
      f.link_count++;
      const raw = (node.getAttribute("href") || "").trim();
      if (
        !raw ||
        raw === "#" ||
        /^javascript:\s*(void\s*\(\s*0\s*\)|;)$/i.test(raw)
      )
        f.placeholder_link_count++;
      const u = resolve(raw);
      if (u && !["http:", "https:", "mailto:", "tel:"].includes(u.protocol))
        f.unusual_link_count++;
      add("link", u);
    }
    if (tag === "IFRAME") {
      f.iframe_count++;
      add("iframe", resolve(node.getAttribute("src") || ""));
      try {
        const frame = node.contentDocument;
        if (!frame) f.inaccessible_frame_count++;
        else {
          const fw = frame.createTreeWalker(
            frame.documentElement,
            NodeFilter.SHOW_ELEMENT,
          );
          let child = fw.currentNode;
          while (child && frameBudget > 0) {
            frameBudget--;
            if (child.tagName === "FORM") f.accessible_frame_form_count++;
            child = fw.nextNode();
          }
          if (child) f.truncated = true;
        }
      } catch {
        f.inaccessible_frame_count++;
      }
    }
    if (tag === "SCRIPT") f.script_count++;
    const attr =
      tag === "SCRIPT" || tag === "IMG"
        ? "src"
        : tag === "LINK"
          ? "href"
          : null;
    if (attr && node.getAttribute(attr)) {
      f.resource_count++;
      add("resource", resolve(node.getAttribute(attr)));
    }
    if (
      tag === "META" &&
      (node.getAttribute("http-equiv") || "").toLowerCase() === "refresh"
    ) {
      const raw = node.getAttribute("content") || "",
        match = raw.match(
          /^\s*(\d+(?:\.\d+)?)\s*;\s*url\s*=\s*['"]?(.*?)['"]?\s*$/i,
        );
      if (match) {
        const u = resolve(match[2]);
        if (
          u &&
          ["http:", "https:"].includes(u.protocol) &&
          u.origin.length <= 256
        ) {
          if (f.meta_refresh.length < 8)
            f.meta_refresh.push({
              origin: u.origin,
              delay_seconds: Math.min(86400, Number(match[1])),
            });
          else f.truncated = true;
        }
      }
    }
    node = walker.nextNode();
  }
  for (const [form, counts] of forms) {
    const raw = form.getAttribute("action"),
      u = resolve(raw || location.href);
    const method = (form.getAttribute("method") || "get").toLowerCase();
    f.credential_forms.push({
      ...counts,
      has_action: raw !== null && raw.trim() !== "",
      method: ["get", "post", "dialog"].includes(method) ? method : "get",
      action_scheme: !u
        ? "invalid"
        : u.protocol === "http:"
          ? "http"
          : u.protocol === "https:"
            ? "https"
            : "other",
      action_origin:
        u && ["http:", "https:"].includes(u.protocol) && u.origin.length <= 256
          ? u.origin
          : null,
      action_same_page:
        !!u && u.origin === location.origin && u.pathname === location.pathname,
    });
  }
  for (const kind of ["link", "iframe", "resource"])
    f[kind + "_origins"] = [...origins[kind]]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([origin, count]) => ({ origin, count }));
  const partial =
    f.truncated ||
    f.inaccessible_frame_count > 0 ||
    f.credential_forms.some((form) =>
      ["other", "invalid"].includes(form.action_scheme),
    );
  return {
    snapshot: {
      schema_version: "dom-v1",
      state: partial ? "partial" : "inspected",
      page_origin: location.origin,
      features: f,
    },
    navigation_start: performance.timeOrigin,
  };
}
