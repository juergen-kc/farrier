#!/usr/bin/env python3
"""Draws Farrier's app icon (a horseshoe on a dark teal tile) as Packaging/AppIcon.png (1024x1024).

Needs Pillow. scripts/build-app.sh turns the PNG into AppIcon.icns with sips and iconutil (macOS).
Regenerate after changing the design:  python3 scripts/make-icon.py
"""
import math
import pathlib

from PIL import Image, ImageDraw, ImageFilter

S = 4096                      # drawn at 4x, then scaled down for smooth edges
OUT = pathlib.Path(__file__).resolve().parent.parent / "Packaging" / "AppIcon.png"


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def main():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # The tile: macOS icon grid, 824/1024 of the canvas, corner radius ~22.5% of the tile, vertical gradient.
    margin = S * 100 // 1024
    tile = S - 2 * margin
    gradient = Image.new("RGBA", (S, S))
    gd = ImageDraw.Draw(gradient)
    top, bottom = (31, 64, 74), (12, 27, 34)
    for y in range(S):
        gd.line([(0, y), (S, y)], fill=lerp(top, bottom, y / S) + (255,))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([margin, margin, margin + tile, margin + tile], radius=int(tile * 0.225), fill=255)

    # A soft drop shadow under the tile.
    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).rounded_rectangle([margin, margin + S // 80, margin + tile, margin + tile + S // 80],
                                             radius=int(tile * 0.225), fill=(0, 0, 0, 110))
    img = Image.alpha_composite(img, shadow.filter(ImageFilter.GaussianBlur(S // 60)))
    img.paste(gradient, (0, 0), mask)

    # The horseshoe: a thick arc open at the bottom, with flat heels and nail holes.
    d = ImageDraw.Draw(img)
    cx, cy = S / 2, S * 0.49
    rx, ry = tile * 0.27, tile * 0.30          # centre line of the shoe
    width = tile * 0.13
    start, end = 122, 418                      # degrees, 0 = right, clockwise in image coordinates (opening at the bottom)
    steel_hi, steel_lo = (236, 240, 242), (150, 163, 170)

    def point(angle, r_scale):
        a = math.radians(angle)
        return cx + (rx + r_scale) * math.cos(a), cy + (ry + r_scale) * math.sin(a)

    # Build the outline as a polygon (outer edge one way, inner edge back), so the heels come out flat.
    steps = 240
    outer = [point(start + (end - start) * i / steps, width / 2) for i in range(steps + 1)]
    inner = [point(end - (end - start) * i / steps, -width / 2) for i in range(steps + 1)]
    shoe = Image.new("L", (S, S), 0)
    ImageDraw.Draw(shoe).polygon(outer + inner, fill=255)
    metal = Image.new("RGBA", (S, S))
    md = ImageDraw.Draw(metal)
    y0, y1 = cy - ry - width, cy + ry + width
    for y in range(int(y0), int(y1) + 1):
        md.line([(0, y), (S, y)], fill=lerp(steel_hi, steel_lo, (y - y0) / (y1 - y0)) + (255,))
    img.paste(metal, (0, 0), shoe)

    # Nail holes: small slots along the centre line, four per branch.
    hole = (40, 58, 66, 255)
    for angle in [145, 172, 199, 226, 314, 341, 368, 395]:
        x, y = point(angle, 0)
        a = math.radians(angle)
        # Along the shoe (tangent), like the slots in a real horseshoe's fuller.
        dx, dy = -math.sin(a) * width * 0.16, math.cos(a) * width * 0.16
        d.line([(x - dx, y - dy), (x + dx, y + dy)], fill=hole, width=int(width * 0.17))

    img = img.resize((1024, 1024), Image.LANCZOS)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
