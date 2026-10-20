"""PROVISIONAL evidence fusion: the implementation manual's Ch. 14 policy plus one evidence-based guard.

1. Any critical rule (verified TI listing) -> 'dangerous', risk 95. Overrides the model.
2. Else level = max(model level, rule level); no averaging of unlike scores.
     model level = probability vs the validation-chosen thresholds (alert -> caution, high -> high_risk)
     rule level  = high rule -> high_risk; medium rule -> caution; low/info -> none
   risk score = round(100 * probability) placed inside the level's band (0..A-1, A..H-1, H..94).
3. Never 'safe': the lowest category is 'low_risk'.
4. Guard (docs/DECISIONS.md D21): where the model is known to be unreliable (hosts with a subdomain:
   93% false alarms on legitimate ones externally; IP hosts: none legitimate in training), the MODEL's
   contribution is capped just below the high threshold and confidence is 'low'. Rule floors still apply.
Constants are design choices awaiting review, not validated values.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from backend.evidence import CHECKED, Evidence

CONFIRMED_RISK = 95
LEVELS = ("low_risk", "caution", "high_risk")


@dataclass
class FusionResult:
    risk_score: int
    safety_score: int | None  # None when unknown
    category: str  # dangerous | high_risk | caution | low_risk | unknown
    confidence: str  # high | medium | low
    decision_basis: str
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def fuse(ev: Evidence, model_caveats: list[str], guard_cap: str = "below_high") -> FusionResult:
    """guard_cap: where a caveated model score is capped - "below_high" (current, D21) or "below_alert" (proposal D32)."""
    fired = [r for r in ev.rules if r.status == "fired"]
    notes = [f"{t.source} not checked: {t.status}" for t in ev.threat_intel if t.status not in CHECKED]
    critical = [r for r in fired if r.severity == "critical"]
    if critical:
        return FusionResult(CONFIRMED_RISK, 100 - CONFIRMED_RISK, "dangerous", "high",
                            "Threat intelligence: " + ", ".join(r.title for r in critical), notes)

    m = ev.model
    th = m.thresholds or {}
    sev = {r.severity for r in fired}
    rule_lvl = 2 if "high" in sev else 1 if "medium" in sev else 0
    if not m.available and rule_lvl == 0:
        return FusionResult(50, None, "unknown", "low", "Model unavailable and no strong rule fired", notes)

    # Levels come from the exact probability vs the stored thresholds (same comparison as the evaluation scripts);
    # the integer risk score is only placed inside the chosen level's band.
    model_lvl = (2 if m.probability >= th["high"] else 1 if m.probability >= th["alert"] else 0) if m.available else 0
    unreliable = m.available and bool(model_caveats)
    if unreliable:
        cap = 1 if guard_cap == "below_high" else 0
        model_lvl = min(model_lvl, cap)
        notes += [f"Model unreliable here ({c}); its level is capped at '{LEVELS[cap]}'." for c in model_caveats]
    lvl = max(model_lvl, rule_lvl)
    a, h = round(100 * th["alert"]), round(100 * th["high"])
    bands = ((0, a - 1), (a, h - 1), (h, CONFIRMED_RISK - 1))
    base = round(100 * m.probability) if m.available else 0
    if unreliable:
        base = min(base, bands[model_lvl][1])  # a capped model must not inflate the score either
    lo, hi = bands[lvl]
    risk = min(max(base, lo), hi)
    basis = "Rule engine" if rule_lvl > model_lvl else "ML model (hostname features)"
    checked = sum(t.status in CHECKED for t in ev.threat_intel)
    if not m.available or checked == 0 or m.out_of_training_range or unreliable:
        confidence = "low"
    else:
        margin = min(abs(m.probability - th["alert"]), abs(m.probability - th["high"]))
        confidence = "high" if margin >= 0.15 else "medium"
    return FusionResult(risk, 100 - risk, LEVELS[lvl], confidence, basis, notes)
