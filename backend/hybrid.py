"""URL + DOM policy r2. No averaging, probability changes or lowering existing risk."""
from dataclasses import replace

from backend.fusion import FusionResult

ASSESSMENT_VERSION = "url-dom-r2"


def combine(base: FusionResult, dom: dict, thresholds: dict) -> FusionResult:
    if dom["state"] not in ("inspected", "partial") or base.category == "dangerous":
        return base
    fired = [r for r in dom["rules"] if r["status"] == "fired"]
    floor = "high_risk" if any(r["severity"] == "high" for r in fired) else (
        "caution" if any(r["severity"] == "medium" for r in fired) else None)
    order = {"unknown": -1, "low_risk": 0, "caution": 1, "high_risk": 2, "dangerous": 3}
    if floor is None or order[floor] <= order[base.category]:
        return base
    boundary = thresholds.get("high" if floor == "high_risk" else "alert")
    # Same integer category floors as existing fusion; defaults apply only to missing model metadata.
    boundary = round(100 * boundary) if isinstance(boundary, (int, float)) and 0 < boundary < .95 else (57 if floor == "high_risk" else 37)
    score = max(boundary, base.risk_score if base.category != "unknown" else 0)
    return replace(base, category=floor, risk_score=score, safety_score=100-score, confidence="low",
                   decision_basis="URL assessment and webpage structural warning",
                   notes=[*base.notes, "Page structure raised the assessment; structural signals do not prove phishing."])
