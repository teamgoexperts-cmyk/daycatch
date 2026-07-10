"""One-off generator for branded placeholder images used by seed_menu.py.

Run once locally (needs Pillow), then commit the JPEGs under seed_images/.
NOT a runtime dependency — the deployed app never imports PIL.

    pip install Pillow
    python generate_seed_images.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont


# (slug, category, display name, palette token)
ITEMS: list[tuple[str, str, str, str]] = [
    # Fresh Fish — sea / teal palette
    ("fresh-seer-fish", "Fresh Fish", "Seer Fish", "sea"),
    ("fresh-pomfret", "Fresh Fish", "Silver Pomfret", "sea"),
    ("fresh-mackerel", "Fresh Fish", "Indian Mackerel", "sea"),
    ("fresh-tiger-prawns", "Fresh Fish", "Tiger Prawns", "sea"),
    ("fresh-red-snapper", "Fresh Fish", "Red Snapper", "sea"),
    # Frozen Fish — ice / cool blue palette
    ("frozen-basa", "Frozen Fish", "Basa Fillets", "ice"),
    ("frozen-tilapia", "Frozen Fish", "Tilapia", "ice"),
    ("frozen-squid", "Frozen Fish", "Squid Rings", "ice"),
    ("frozen-prawn", "Frozen Fish", "Prawn", "ice"),
    ("frozen-salmon", "Frozen Fish", "Salmon Steaks", "ice"),
    # Accessories — warm beige palette
    ("acc-cleaning-knife", "Accessories", "Fish Cleaning Knife", "warm"),
    ("acc-tandoori-marinade", "Accessories", "Tandoori Marinade", "warm"),
    ("acc-fish-masala", "Accessories", "Fish Curry Masala", "warm"),
    ("acc-fish-tongs", "Accessories", "Stainless Fish Tongs", "warm"),
    ("acc-lemon-pepper", "Accessories", "Lemon Pepper Seasoning", "warm"),
]

PALETTES = {
    "sea":  {"bg": "#E6F4F7", "accent": "#0E7C8B", "ring": "#B9E2EA"},
    "ice":  {"bg": "#EEF4FB", "accent": "#2E5C9A", "ring": "#CFE0F4"},
    "warm": {"bg": "#FAF1E2", "accent": "#A65B22", "ring": "#EBD3AC"},
}
BRAND = "#E63946"
INK = "#1F2937"
MUTED = "#6B7280"

SIZE = 600
OUT = Path(__file__).resolve().parent / "seed_images"


def _font(size: int) -> ImageFont.ImageFont:
    # Pillow ships DejaVuSans; falls back gracefully if missing.
    for name in ("DejaVuSans-Bold.ttf", "arialbd.ttf", "arial.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def _wrap(draw: ImageDraw.ImageDraw, text: str, font, max_w: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if draw.textlength(trial, font=font) <= max_w:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def draw_card(name: str, category: str, palette: str) -> Image.Image:
    pal = PALETTES[palette]
    img = Image.new("RGB", (SIZE, SIZE), pal["bg"])
    draw = ImageDraw.Draw(img)

    # Soft outer ring of category colour (gives the card depth).
    ring_box = (40, 40, SIZE - 40, SIZE - 40)
    draw.ellipse(ring_box, fill=pal["ring"])
    # Inner plate, slightly smaller.
    plate_box = (80, 80, SIZE - 80, SIZE - 80)
    draw.ellipse(plate_box, fill="#FFFFFF")
    # Brand-coloured accent crescent on top-right of the plate.
    accent_box = (SIZE - 240, 80, SIZE - 80, 240)
    draw.ellipse(accent_box, fill=BRAND)
    img = img.filter(ImageFilter.GaussianBlur(0.6))
    draw = ImageDraw.Draw(img)

    # Category label (small, uppercase).
    cat_font = _font(22)
    cat = category.upper()
    cat_w = draw.textlength(cat, font=cat_font)
    draw.text(((SIZE - cat_w) / 2, 270), cat, fill=MUTED, font=cat_font)

    # Item name, wrapped, centred.
    name_font = _font(40)
    lines = _wrap(draw, name, name_font, SIZE - 140)
    y = 320
    for line in lines:
        w = draw.textlength(line, font=name_font)
        draw.text(((SIZE - w) / 2, y), line, fill=INK, font=name_font)
        y += 50

    return img


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for slug, category, name, palette in ITEMS:
        img = draw_card(name, category, palette)
        path = OUT / f"{slug}.jpg"
        img.save(path, "JPEG", quality=85, optimize=True)
        print(f"  wrote {path.name}  ({path.stat().st_size // 1024} KB)")
    print(f"\n{len(ITEMS)} images written to {OUT}")


if __name__ == "__main__":
    main()
