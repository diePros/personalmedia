#!/usr/bin/env python3
"""Generates the PNG icons from the design in icon.svg / favicon.svg.

Pillow cannot rasterise SVG, so the same shapes are drawn here in a 512-unit
coordinate system (keep both in sync). Run: python3 static/icons/generate.py
Needs Pillow only.
"""
from pathlib import Path

from PIL import Image, ImageDraw

ACCENT = (0x1D, 0x4E, 0xD8)
WHITE = (255, 255, 255)
FOLD = (0xBF, 0xDB, 0xFE)
OUT = Path(__file__).resolve().parent
SS = 4  # supersampling factor for anti-aliasing


def full(draw, k, scale, fold):
    """Sheet with folded corner + padlock (icon.svg geometry)."""

    def p(x, y):
        return (256 + (x - 256) * scale) * k, (256 + (y - 256) * scale) * k

    draw.polygon([p(136, 88), p(312, 88), p(376, 152), p(376, 424), p(136, 424)], fill=WHITE)
    if fold:
        draw.polygon([p(312, 88), p(312, 152), p(376, 152)], fill=FOLD)
    # Shackle: two posts plus a semicircle of radius 24 centred at (256, 268).
    w = 14 * scale * k
    for x in (232, 280):
        draw.line([p(x, 268), p(x, 290)], fill=ACCENT, width=round(w))
    cx, cy = p(256, 268)
    r = 24 * scale * k
    o = r + w / 2  # PIL strokes inward from the bbox; SVG strokes centred
    draw.arc([cx - o, cy - o, cx + o, cy + o], 180, 360, fill=ACCENT, width=round(w))
    x0, y0 = p(216, 290)
    x1, y1 = p(296, 364)
    draw.rounded_rectangle([x0, y0, x1, y1], radius=10 * scale * k, fill=ACCENT)
    hx, hy = p(256, 322)
    hr = 9 * scale * k
    draw.ellipse([hx - hr, hy - hr, hx + hr, hy + hr], fill=WHITE)


def simple(draw, k):
    """Simplified sheet + lock for 16/32 px (favicon.svg geometry, no fold)."""
    draw.rounded_rectangle([144 * k, 72 * k, 368 * k, 440 * k], radius=12 * k, fill=WHITE)
    w = round(20 * k)
    for x in (226, 286):
        draw.line([(x * k, 256 * k), (x * k, 276 * k)], fill=ACCENT, width=w)
    o = 30 * k + w / 2
    draw.arc([256 * k - o, 256 * k - o, 256 * k + o, 256 * k + o], 180, 360, fill=ACCENT, width=w)
    draw.rounded_rectangle([208 * k, 276 * k, 304 * k, 372 * k], radius=12 * k, fill=ACCENT)
    draw.ellipse([244 * k, 304 * k, 268 * k, 328 * k], fill=WHITE)


def render(size, kind, name):
    big = size * SS
    k = big / 512
    if kind == "rounded":  # transparent corners
        img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([0, 0, big - 1, big - 1], radius=112 * k, fill=ACCENT)
    else:  # full-bleed background (apple-touch, maskable)
        img = Image.new("RGBA", (big, big), ACCENT + (255,))
        d = ImageDraw.Draw(img)
    if kind == "simple":
        simple(d, k)
    else:
        # Maskable: sheet corners must stay inside the 40%-radius safe circle.
        full(d, k, 0.85 if kind == "maskable" else 1.0, fold=True)
    img = img.resize((size, size), Image.LANCZOS)
    if kind in ("maskable", "bleed"):
        img = img.convert("RGB")
    img.save(OUT / name, optimize=True)


render(512, "rounded", "icon-512.png")
render(192, "rounded", "icon-192.png")
render(512, "maskable", "icon-maskable-512.png")
render(180, "bleed", "apple-touch-icon.png")
render(32, "simple", "favicon-32.png")
render(16, "simple", "favicon-16.png")
