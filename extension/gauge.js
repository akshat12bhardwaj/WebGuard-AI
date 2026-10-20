// Segmented semicircular risk gauge (SVG), shared by the popup and the report. Bands are the backend's own score bands
// (report_model.scoreBands); the marker sits at the backend's risk score. No score -> no marker.
const SVG = "http://www.w3.org/2000/svg";
export const BAND_ORDER = ["low_risk", "caution", "high_risk", "dangerous"];
const CX = 120, CY = 118, R = 96, GAP = 1.2; // GAP in score units between segments

const point = (v, r = R) => {
  const t = Math.PI * (1 - v / 100);
  return [+(CX + r * Math.cos(t)).toFixed(2), +(CY - r * Math.sin(t)).toFixed(2)];
};
const arc = (from, to) => {
  const [x1, y1] = point(from), [x2, y2] = point(to);
  return `M${x1} ${y1} A${R} ${R} 0 0 1 ${x2} ${y2}`;
};

/** Pure geometry: band paths, tick labels and the score marker. */
export function gaugeGeometry({ score, category, bands }) {
  const edges = [0, bands.alert, bands.high, bands.dangerous, 100];
  const segments = BAND_ORDER.map((cat, i) => ({
    category: cat, from: edges[i], to: edges[i + 1], active: cat === category,
    d: arc(edges[i] + (i ? GAP / 2 : 0), edges[i + 1] - (i < 3 ? GAP / 2 : 0)),
  }));
  const ticks = [bands.alert, bands.high].map((v) => { // band boundaries; the readout already says /100
    const [x, y] = point(v, R + 17);
    return { value: v, x, y };
  });
  const marker = typeof score === "number" ? (([x, y]) => ({ x, y }))(point(Math.min(Math.max(score, 0), 100))) : null;
  return { segments, ticks, marker };
}

const node = (name, attrs) => {
  const n = document.createElementNS(SVG, name);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  return n;
};

/** Draw into an <svg viewBox="0 0 240 132">. */
export function renderGauge(svg, { score, category, bands }) {
  const g = gaugeGeometry({ score, category, bands });
  const kids = [];
  for (const s of g.segments) kids.push(node("path", { d: s.d, class: `seg cat-${s.category}${s.active ? " on" : ""}` }));
  for (const t of g.ticks) {
    const label = node("text", { x: t.x, y: t.y + 4, class: "tick", "text-anchor": "middle" });
    label.textContent = String(t.value);
    kids.push(label);
  }
  if (g.marker) kids.push(node("circle", { cx: g.marker.x, cy: g.marker.y, r: 9, class: `marker cat-${category}` }));
  const title = svg.querySelector("title"); // the accessible label stays; callers update its text
  svg.replaceChildren(...(title ? [title] : []), ...kids);
  return g;
}
