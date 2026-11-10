"""DIAGNOSTIC (not an unbiased estimate): brand-rule behaviour and final categories on the frozen external set.

The external set was already used to find the D36 problem, so these numbers are diagnosis only; the rules were
designed from documented conventions and synthetic fixtures (tests/test_phase4.py), not tuned on these hosts.
Offline: threat intelligence not checked (lookups={}).
Usage: python -m ml.brand_rule_diagnostic
Writes: reports/phase4/brand_rule_diagnostic.{json,md}
"""
from __future__ import annotations

import pandas as pd

from backend.fusion import fuse
from backend.service import Analyzer
from ml.external_data import EXTERNAL
from ml.utils import ROOT, save_json

OUT = ROOT / "reports" / "phase4"
BEFORE = {"tranco_subdomain": {"BRAND_IN_HOST_MISMATCH": 154}, "tranco_apex": {"BRAND_IN_HOST_MISMATCH": 7},
          "openphish": {"BRAND_IN_HOST_MISMATCH": 4}}  # phase-3 rules, recorded in docs/DECISIONS.md D36


def main() -> None:
    ext = pd.read_csv(EXTERNAL, keep_default_na=False)
    a = Analyzer(lookups={})
    res, rows = {"note": "diagnostic only; external set already used for diagnosis", "before_phase3_rules": BEFORE}, []
    for g in ("tranco_apex", "tranco_subdomain", "openphish"):
        fires, cats, examples = {}, [], {}
        for url in ext.loc[ext["subset"] == g, "url"]:
            ev, cav = a.collect(url)
            for r in ev.rules:
                if r.status == "fired" and r.rule_id.startswith("BRAND"):
                    fires[r.rule_id] = fires.get(r.rule_id, 0) + 1
                    examples.setdefault(r.rule_id, ev.host)
            cats.append(fuse(ev, cav).category)
        share = pd.Series(cats).value_counts(normalize=True).round(4).to_dict()
        res[g] = {"n": len(cats), "brand_rule_fires": fires, "example_host": examples, "final_category_share": share}
        rows.append({"group": g, "n": len(cats), **{k: fires.get(k, 0) for k in
                     ("BRAND_IN_HOST_MISMATCH", "BRAND_IN_SUBDOMAIN", "BRAND_IN_PATH")},
                     "before: BRAND_IN_HOST_MISMATCH": BEFORE[g]["BRAND_IN_HOST_MISMATCH"],
                     "final high_risk": share.get("high_risk", 0.0),
                     "final caution+": round(sum(v for k, v in share.items() if k in ("caution", "high_risk", "dangerous")), 4)})
    OUT.mkdir(parents=True, exist_ok=True)
    save_json(res, OUT / "brand_rule_diagnostic.json")
    (OUT / "brand_rule_diagnostic.md").write_text(
        "DIAGNOSTIC ONLY (frozen external set already used to find the problem; TI not checked).\n\n"
        + pd.DataFrame(rows).to_markdown(index=False), encoding="utf-8")
    print(pd.DataFrame(rows).to_string(index=False))


if __name__ == "__main__":
    main()
