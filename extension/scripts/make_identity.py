"""Render the consumer identity to local toolbar PNGs. Original brand source is untouched."""
from pathlib import Path

from PIL import Image, ImageDraw


def render(size):
    scale = 8
    image = Image.new("RGBA", (40 * scale, 44 * scale))
    draw = ImageDraw.Draw(image)
    points = [(20, 2), (37, 10), (37, 23), (34, 30), (27, 37), (20, 42), (13, 37), (6, 30), (3, 23), (3, 10)]
    points = [(x * scale, y * scale) for x, y in points]
    draw.polygon(points, fill="#111111")
    draw.line(points + [points[0]], fill="#f5f5f5", width=2 * scale, joint="curve")
    draw.line([(x * scale, y * scale) for x, y in [(10, 15), (15, 29), (20, 20), (25, 29), (30, 15)]],
              fill="#f5f5f5", width=2 * scale)
    draw.line([(20 * scale, 3 * scale), (20 * scale, 12 * scale)], fill="#f5f5f5", width=2 * scale)
    canvas = Image.new("RGBA", (44 * scale, 44 * scale))
    canvas.alpha_composite(image, (2 * scale, 0))
    return canvas.resize((size, size), Image.Resampling.LANCZOS)


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "icons"
    for size in (16, 32, 48, 128):
        render(size).save(target / f"icon{size}.png")
