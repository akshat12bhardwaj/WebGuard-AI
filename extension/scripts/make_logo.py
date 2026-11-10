"""Build the WebGuard AI logo (SVG) and toolbar icons (PNG) from the supplied shield artwork.

Source: docs/brand/shield_source.png (447 x 447, kept unchanged). The shield outline below was measured on that image
and fitted with cubic Beziers (max deviation 1.2 px of 447). Same silhouette, split halves and 45-degree long shadow;
colours re-mapped from red/yellow/orange to the product's navy and teal.
Run from the repository root:  python extension/scripts/make_logo.py
"""
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw

OUT = Path(__file__).resolve().parents[1] / "icons"
FIELD, SHADOW, LEFT, RIGHT, RIM = "#0F1B2B", "#0A1320", "#5FE3CF", "#22B4C2", "#2A3E57"  # rim: edge on dark toolbars
SQUARE = (18, 18, 428, 428, 72)  # x0, y0, x1, y1, corner radius (source pixels)
LEFT_HALF = [((223, 84), (151, 84), (104, 122), (104, 134)), ((104, 134), (104, 134), (104, 230), (104, 230)),
             ((104, 230), (104, 296), (205, 362), (223, 362))]


def mirror(segs):
    return [tuple((446 - x, y) for x, y in seg) for seg in segs]


def sample(segs, n=48):
    pts = []
    for p0, p1, p2, p3 in segs:
        for i in range(n + 1):
            t = i / n
            u = 1 - t
            pts.append(tuple(u**3 * a + 3 * u * u * t * b + 3 * u * t * t * c + t**3 * d for a, b, c, d in zip(p0, p1, p2, p3)))
    return pts


def hull(points):
    pts = sorted(set(points))
    def half(seq):
        out = []
        for p in seq:
            while len(out) >= 2 and (out[-1][0] - out[-2][0]) * (p[1] - out[-2][1]) - (out[-1][1] - out[-2][1]) * (p[0] - out[-2][0]) <= 0:
                out.pop()
            out.append(p)
        return out[:-1]
    return half(pts) + half(pts[::-1])


LEFT_PTS = sample(LEFT_HALF)
RIGHT_PTS = sample(mirror(LEFT_HALF))
SHIELD = LEFT_PTS + RIGHT_PTS[::-1]
SHADOW_PTS = hull([(round(x, 2), round(y, 2)) for x, y in SHIELD] + [(x + 600, y + 600) for x, y in SHIELD])


def path(segs):
    (x0, y0) = segs[0][0]
    return f"M{x0} {y0} " + " ".join(f"C{b[0]} {b[1]} {c[0]} {c[1]} {d[0]} {d[1]}" for _, b, c, d in segs) + " Z"


def svg() -> str:
    x0, y0, x1, y1, r = SQUARE
    shadow = " ".join(f"{x:.1f},{y:.1f}" for x, y in SHADOW_PTS)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="{x0} {y0} {x1 - x0} {y1 - y0}" role="img" aria-label="WebGuard AI">
  <defs><clipPath id="sq"><rect x="{x0}" y="{y0}" width="{x1 - x0}" height="{y1 - y0}" rx="{r}"/></clipPath></defs>
  <rect x="{x0}" y="{y0}" width="{x1 - x0}" height="{y1 - y0}" rx="{r}" fill="{FIELD}"/>
  <polygon points="{shadow}" fill="{SHADOW}" clip-path="url(#sq)"/>
  <path d="{path(LEFT_HALF)}" fill="{LEFT}"/>
  <path d="{path(mirror(LEFT_HALF))}" fill="{RIGHT}"/>
  <rect x="{x0 + 5}" y="{y0 + 5}" width="{x1 - x0 - 10}" height="{y1 - y0 - 10}" rx="{r - 5}" fill="none" stroke="{RIM}" stroke-width="10"/>
</svg>
"""


def png(size: int) -> Image.Image:
    k = 8  # supersampling
    x0, y0, x1, _, r = SQUARE
    s = size * k / (x1 - x0)
    tr = lambda pts: [((x - x0) * s, (y - y0) * s) for x, y in pts]
    im = Image.new("RGBA", (size * k, size * k), (0, 0, 0, 0))
    mask = Image.new("L", im.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, size * k - 1, size * k - 1], radius=r * s, fill=255)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, size * k, size * k], fill=FIELD)
    d.polygon(tr(SHADOW_PTS), fill=SHADOW)
    d.polygon(tr(LEFT_PTS), fill=LEFT)
    d.polygon(tr(RIGHT_PTS), fill=RIGHT)
    w = max(10 * s, k)  # at least 1 output pixel
    ImageDraw.Draw(im).rounded_rectangle([w / 2, w / 2, size * k - 1 - w / 2, size * k - 1 - w / 2], radius=r * s - w / 2, outline=RIM, width=round(w))
    im.putalpha(ImageChops.multiply(im.getchannel("A"), mask))
    return im.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    (OUT / "logo.svg").write_text(svg(), encoding="utf-8")
    for n in (16, 32, 48, 128):
        png(n).save(OUT / f"icon{n}.png")
    print("wrote", sorted(p.name for p in OUT.iterdir()))
