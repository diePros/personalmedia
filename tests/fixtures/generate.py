#!/usr/bin/env python3
"""Regenerates the extraction test fixtures in this directory (needs Pillow, DejaVu fonts)."""
import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def render(text):
    font = ImageFont.truetype(FONT, 64)
    img = Image.new("L", (1400, 220), 255)
    ImageDraw.Draw(img).text((40, 60), text, font=font, fill=0)
    return img


def minimal_text_pdf(path, text_winansi: bytes):
    # Second line keeps the layer above the 50 chars/page threshold that triggers OCR.
    stream = (
        b"BT /F1 16 Tf 72 700 Td (" + text_winansi + b") Tj "
        b"0 -40 Td (Dieser Vertrag wird von beiden Parteien unterzeichnet.) Tj ET"
    )
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    with open(path, "wb") as f:
        f.write(out)


minimal_text_pdf(os.path.join(HERE, "text.pdf"), "Mietvertrag Kündigungsfrist".encode("cp1252"))
render("Versicherungsnummer 12345").save(os.path.join(HERE, "scanned.pdf"), resolution=300)
render("Versicherungsnummer 12345").save(os.path.join(HERE, "scan.png"))
with open(os.path.join(HERE, "corrupt.pdf"), "wb") as f:
    f.write(b"%PDF-" + bytes((i * 37 + 11) % 256 for i in range(512)))
open(os.path.join(HERE, "empty.pdf"), "wb").close()
# JPEG scan pages for the scanner tests: one grayscale, one RGB.
render("Versicherungsnummer 12345").save(os.path.join(HERE, "scan1.jpg"), quality=85)
render("Kuendigungsfrist 67890").convert("RGB").save(os.path.join(HERE, "scan2.jpg"), quality=85)
