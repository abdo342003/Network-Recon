"""Generate a placeholder logo and .ico using Pillow.

Run from the project root venv python to produce `assets/logo.png` and `assets/app.ico`.
"""
from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except Exception as exc:
    raise SystemExit("Pillow is required. Install with pip install pillow") from exc

ROOT = Path(__file__).resolve().parent
OUT_PNG = ROOT / "logo.png"
OUT_ICO = ROOT / "app.ico"


def make_logo() -> None:
    size = (512, 512)
    img = Image.new("RGBA", size, (14, 28, 48, 255))
    draw = ImageDraw.Draw(img)
    draw.ellipse((56, 56, 456, 456), fill=(30, 115, 190, 255))
    draw.ellipse((130, 130, 382, 382), fill=(14, 28, 48, 255))
    draw.ellipse((196, 196, 316, 316), fill=(30, 115, 190, 255))

    try:
        font = ImageFont.truetype("arial.ttf", 120)
    except Exception:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), "NR", font=font)
    w = bbox[2] - bbox[0]
    h = bbox[3] - bbox[1]
    draw.text(((size[0] - w) / 2, (size[1] - h) / 2 - 10), "NR", font=font, fill=(255, 255, 255, 255))

    OUT_PNG.parent.mkdir(parents=True, exist_ok=True)
    img.save(OUT_PNG)
    icon_sizes = [(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)]
    icons = [img.resize(s, Image.LANCZOS).convert("RGBA") for s in icon_sizes]
    icons[0].save(OUT_ICO, format="ICO", sizes=icon_sizes)
    print(f"Wrote {OUT_PNG} and {OUT_ICO}")


if __name__ == "__main__":
    make_logo()
