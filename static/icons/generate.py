#!/usr/bin/env python3
"""Generates the PWA icons (PM monogram on the theme color).

Run from anywhere: python3 static/icons/generate.py
Needs Pillow and DejaVu Sans Bold.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
BG = "#1d4ed8"  # --accent in app.css, also the manifest theme_color
FG = "#ffffff"
OUT = Path(__file__).resolve().parent


def icon(size: int, content_ratio: float, name: str) -> None:
    """Draws "PM" so its box fits `content_ratio` of the icon's width."""
    img = Image.new("RGB", (size, size), BG)
    draw = ImageDraw.Draw(img)
    target = size * content_ratio
    font_size = size
    while True:
        font = ImageFont.truetype(FONT, font_size)
        box = draw.textbbox((0, 0), "PM", font=font)
        w, h = box[2] - box[0], box[3] - box[1]
        if max(w, h) <= target:
            break
        font_size -= 1
    x = (size - w) / 2 - box[0]
    y = (size - h) / 2 - box[1]
    draw.text((x, y), "PM", font=font, fill=FG)
    img.save(OUT / name, optimize=True)


icon(192, 0.62, "icon-192.png")
icon(512, 0.62, "icon-512.png")
# Maskable: everything inside the central 80% safe zone (here 56%).
icon(512, 0.56, "icon-maskable-512.png")
