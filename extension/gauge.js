// Horizontal band meter shared by the popup and the report. Bands are the backend's own score bands
// (report_model.scoreBands); only the active band is lit and a tick sits at the backend's risk score. No score -> no tick.
export const BAND_ORDER = ["low_risk", "caution", "high_risk", "dangerous"];

/** Pure geometry: band extents (score units = % of the meter) and the clamped marker position. */
export function gaugeGeometry({ score, category, bands }) {
  const edges = [0, bands.alert, bands.high, bands.dangerous, 100];
  const segments = BAND_ORDER.map((cat, i) => ({
    category: cat, from: edges[i], to: edges[i + 1], active: cat === category,
  }));
  const marker = typeof score === "number" ? Math.min(Math.max(score, 0), 100) : null;
  return { segments, marker };
}

/** Fill a .meter element: four <i> band segments, then <b class="mark">. */
export function renderGauge(meter, opts) {
  const g = gaugeGeometry(opts);
  g.segments.forEach((s, i) => {
    meter.children[i].style.flexBasis = `${s.to - s.from}%`;
    meter.children[i].className = s.active ? "on" : "";
  });
  meter.removeAttribute("style"); // .meter[style] means a tick is shown
  if (g.marker !== null) meter.style.setProperty("--x", `${g.marker}%`);
  return g;
}
