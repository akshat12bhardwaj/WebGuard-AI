"""Raw model vs final API assessment on the same hosts (baseline bundle; offline: no TI lookups).

Threat intelligence is skipped on purpose (lookups={}): 14k live calls would exceed PhishTank's limit and
URLhaus has no key. Final results here therefore show model + rules + guard only, all with TI 'not checked'.
Usage: python -m ml.fusion_report
Writes: reports/exp03/fusion_report.{json,md}
"""
from __future__ import annotations

import pandas as pd

from backend.fusion import fuse
from backend.service import Analyzer
from ml.external_data import EXTERNAL
from ml.utils import PROCESSED, ROOT, get_logger, save_json

OUT = ROOT / "reports" / "exp03"
log = get_logger("fusion_report")


def main() -> None:
    ext = pd.read_csv(EXTERNAL, keep_default_na=False)
    new = pd.read_csv(PROCESSED / "exp03_new_test.csv", keep_default_na=False)
    groups = {g: ext.loc[ext["subset"] == g, "url"].tolist() for g in ("tranco_apex", "tranco_subdomain", "openphish")}
    groups["new_legit_subdomain_test"] = new["URL"].tolist()
    a = Analyzer(lookups={})
    th = a.bundle["thresholds"]
    res, rows = {"thresholds": th, "ti": "not checked (offline)"}, []
    for g, urls in groups.items():
        recs = []
        for u in urls:
            ev, cav = a.collect(u)
            p = ev.model.probability
            recs.append({"raw_alert": p >= th["alert"], "raw_high": p >= th["high"],
                         **{f"final_{cap}": fuse(ev, cav, cap).category for cap in ("below_high", "below_alert")}})
        d = pd.DataFrame(recs)
        r = {"n": len(d), "raw_flag_rate_alert": round(float(d["raw_alert"].mean()), 4),
             "raw_flag_rate_high": round(float(d["raw_high"].mean()), 4)}
        for cap in ("below_high", "below_alert"):
            share = d[f"final_{cap}"].value_counts(normalize=True).round(4).to_dict()
            r[f"final_{cap}"] = share
            r[f"final_{cap}_caution_or_worse"] = round(sum(v for k, v in share.items() if k in ("caution", "high_risk", "dangerous")), 4)
        res[g] = r
        rows.append({"group": g, "n": r["n"], "raw @alert": r["raw_flag_rate_alert"], "raw @high": r["raw_flag_rate_high"],
                     "final caution+ (current guard)": r["final_below_high_caution_or_worse"],
                     "final high_risk (current guard)": r["final_below_high"].get("high_risk", 0.0),
                     "final caution+ (cap below alert)": r["final_below_alert_caution_or_worse"],
                     "final high_risk (cap below alert)": r["final_below_alert"].get("high_risk", 0.0)})
        log.info("%s: %s", g, rows[-1])
    save_json(res, OUT / "fusion_report.json")
    (OUT / "fusion_report.md").write_text(
        "Rates = share of hosts. Legitimate groups: lower is better. OpenPhish: higher is better (detection).\n"
        "TI not checked (offline), so every final result here has low confidence.\n\n"
        + pd.DataFrame(rows).to_markdown(index=False), encoding="utf-8")


if __name__ == "__main__":
    main()
