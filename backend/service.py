"""Collect evidence for one URL: model (via ml.predict), threat intelligence, then rules.

No feature or inference code is duplicated here; the website itself is never fetched.
"""
from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pandas as pd
import shap

from backend import rules, threat_intel
from backend.evidence import Evidence, ModelEvidence, TIResult
from ml.feature_extraction import (
    extract_features,
    get_host,
    normalize_url,
    site_domain,
)
from ml.predict import load_bundle, predict


class Analyzer:
    def __init__(self, bundle: dict | None = None, lookups: dict | None = None):
        try:
            self.bundle = bundle or load_bundle()
            self.explainer = shap.TreeExplainer(self.bundle["raw_model"])
        except (OSError, KeyError) as exc:
            self.bundle, self.explainer, self.load_error = None, None, f"{type(exc).__name__}: {exc}"
        self.lookups = lookups if lookups is not None else {
            "PhishTank": threat_intel.check_phishtank, "URLhaus": threat_intel.check_urlhaus,
            "Google Safe Browsing": threat_intel.check_safe_browsing,
            threat_intel.OPENPHISH_SOURCE: threat_intel.check_openphish_local}

    def model_evidence(self, url: str) -> ModelEvidence:
        if self.bundle is None:
            return ModelEvidence(False, error=self.load_error)
        try:
            p = predict(self.bundle, url)
            X = pd.DataFrame([extract_features(url)])[self.bundle["features"]].astype(float)
            sv = self.explainer.shap_values(X)[0]
            top = sorted(zip(self.bundle["features"], X.iloc[0], sv), key=lambda t: -abs(t[2]))[:5]
            return ModelEvidence(True, p["model_probability_phishing"], self.bundle["calibration"],
                                 dict(self.bundle["thresholds"]), p["model_version"], p["out_of_training_range"],
                                 [{"feature": f, "value": float(v), "shap_log_odds": round(float(s), 4)} for f, v, s in top])
        except Exception as exc:  # noqa: BLE001 - a model failure must not hide the other evidence
            return ModelEvidence(False, error=type(exc).__name__)

    def collect(self, raw_url: str) -> tuple[Evidence, list[str]]:
        """Returns (evidence, model caveats). Raises InvalidURLError for invalid input."""
        url = normalize_url(raw_url)
        host = get_host(url)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        if _private(host):  # never send internal addresses to third parties
            ti = [TIResult(name, "not_configured", "skipped: private/local host", now) for name in self.lookups]
        else:
            with ThreadPoolExecutor(max_workers=len(self.lookups) or 1) as pool:
                ti = list(pool.map(lambda f: f(url), self.lookups.values()))
        ev = Evidence(url, host, site_domain(host), now, self.model_evidence(url), ti, rules.evaluate(url, ti))
        if not ev.model.available:
            ev.errors.append(f"model unavailable: {ev.model.error}")
        f = extract_features(url)
        sub = "host has a subdomain; 93% false alarms on legitimate subdomain hosts in external testing"
        ip = "IP-address host; no legitimate IP hosts in the training data"
        caveats = [c for c, on in ((sub, f["subdomain_count"] > 0), (ip, f["is_ip"] == 1)) if on]
        return ev, caveats


def _private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return host == "localhost" or host.endswith((".local", ".internal", ".lan")) or "." not in host
