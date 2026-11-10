"""Structured evidence passed between the model, rules, threat intelligence and (later) fusion.

The five ideas stay separate: ML probability (ModelEvidence), threat-intelligence results (TIResult),
rule findings (RuleFinding), the final score (FusionResult, backend/fusion.py) and its confidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

# match: confirmed listing | no_match: source checked, URL not listed (NOT proof of safety)
# unverified: reported but not confirmed | error / rate_limited / not_configured / invalid_input: not checked
TIStatus = Literal["match", "no_match", "unverified", "error", "rate_limited", "not_configured", "invalid_input"]
CHECKED = ("match", "no_match", "unverified")


@dataclass
class TIResult:
    source: str
    status: TIStatus
    detail: str = ""
    checked_at: str = ""
    cached: bool = False
    reference: str = ""  # e.g. PhishTank detail page or URLhaus reference


@dataclass
class RuleFinding:
    rule_id: str
    status: Literal["fired", "not_fired", "not_evaluated"]  # not_evaluated = required evidence missing
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    explanation: str = ""


@dataclass
class ModelEvidence:
    available: bool
    probability: float | None = None  # calibrated P(phishing host) on PhiUSIIL; not a risk score
    calibration: str | None = None
    thresholds: dict = field(default_factory=dict)
    model_version: str | None = None
    out_of_training_range: list[str] = field(default_factory=list)
    top_shap: list[dict] = field(default_factory=list)  # log-odds of the raw model
    error: str = ""


@dataclass
class Evidence:
    url: str
    host: str
    registered_domain: str
    collected_at: str
    model: ModelEvidence
    threat_intel: list[TIResult]
    rules: list[RuleFinding]
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
