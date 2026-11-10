"""DOM rules r1. Structural warnings, not a claim that a site is phishing."""
from __future__ import annotations

from urllib.parse import urlsplit

import tldextract

from backend.dom_schema import DOM_SCHEMA, DomSnapshot
from backend.evidence import RuleFinding

# Private suffixes matter: unrelated tenants on github.io must not count as one site.
_PSL = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def site(origin: str) -> str:
    host = (urlsplit(origin).hostname or "").lower().rstrip(".")
    p = _PSL(host)
    return p.top_domain_under_public_suffix or host


def evaluate(snapshot: DomSnapshot, url: str) -> dict:
    state = snapshot.state
    if snapshot.schema_version != DOM_SCHEMA:
        state = "incompatible"
    def origin_key(raw):
        parsed = urlsplit(raw)
        return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    if state in ("inspected", "partial") and origin_key(snapshot.page_origin) != origin_key(url):
        state = "unavailable"
    if state == "inspected" and snapshot.features and (snapshot.features.truncated or snapshot.features.inaccessible_frame_count or
                                           any(f.action_scheme in ("other", "invalid") for f in snapshot.features.credential_forms)):
        state = "partial"
    result = {"schema_version": DOM_SCHEMA, "state": state, "rules": [], "summary": {}}
    if state not in ("inspected", "partial"):
        return result
    f = snapshot.features
    same_site = site(snapshot.page_origin)
    external = [form for form in f.credential_forms if form.password_count and form.method != "dialog" and form.action_origin and site(form.action_origin) != same_site]
    insecure = [form for form in f.credential_forms if form.password_count and form.method != "dialog" and form.action_scheme == "http"]
    fast_external_refresh = any(site(r.origin) != same_site and r.delay_seconds <= 10 for r in f.meta_refresh)
    visible_passwords = f.password_count > f.hidden_password_count
    rules = [
        RuleFinding("DOM_PASSWORD_HTTP", "fired" if insecure else "not_fired", "high",
                    "Password form uses an insecure connection", "A password form destination uses HTTP." if insecure else ""),
        RuleFinding("DOM_CROSS_SITE_FORM", "fired" if external else "not_fired", "info",
                    "Login form uses another website", "May be a legitimate sign-in or payment service." if external else ""),
        RuleFinding("DOM_CREDENTIAL_REDIRECT", "fired" if fast_external_refresh and visible_passwords else "not_fired", "medium",
                    "Page redirects while requesting a password", "A rapid cross-site refresh appears alongside visible password entry."),
        RuleFinding("DOM_HIDDEN_PASSWORD", "fired" if f.hidden_password_count else "not_fired", "info",
                    "Hidden password entry", "Hidden fields are common in legitimate multi-step forms; this alone does not raise risk."),
        RuleFinding("DOM_STRUCTURAL_COMBINATION", "fired" if external and fast_external_refresh and f.hidden_password_count else "not_fired", "medium",
                    "Several page signals need attention", "External credential submission, hidden password entry and a rapid cross-site refresh appear together."),
    ]
    def counts(origins):
        own = sum(r.count for r in origins if site(r.origin) == same_site)
        other = sum(r.count for r in origins if site(r.origin) != same_site)
        return {"same_site": own, "cross_site": other, "ratio": other / (own + other) if own + other else None}
    result["rules"] = [r.__dict__ for r in rules]
    result["features"] = f.model_dump()
    result["summary"] = {"credential_form_count": len(f.credential_forms), "cross_site_credential_forms": len(external),
                         "links": counts(f.link_origins), "frames": counts(f.iframe_origins),
                         "resources": counts(f.resource_origins), "coverage_limited": f.truncated or state == "partial"}
    return result
