// Shared mocked API v1.0 responses for the extension tests (shape as in docs/API_CONTRACT.md).
const SCORE = { dangerous: 95, high_risk: 70, caution: 45, low_risk: 17, unknown: 50 };
export function apiResponse(category = "low_risk", url = "https://www.example.com/") {
  const host = new URL(url).hostname.replace(/^www\./, "");
  return {
    api_version: "1.0",
    assessment: { risk_score: SCORE[category], safety_score: category === "unknown" ? null : 100 - SCORE[category], category,
      confidence: "high", decision_basis: "ML model (hostname features)", notes: [] },
    evidence: { url, host, registered_domain: host, collected_at: "2026-10-20T10:00:00+00:00",
      model: { available: true, probability: 0.17, thresholds: { alert: 0.3662, high: 0.5671 }, top_shap: [] },
      threat_intel: [{ source: "PhishTank", status: "no_match", detail: "" }], rules: [], errors: [] },
    disclaimer: "Not proof that a site is safe.",
  };
}
