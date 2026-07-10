"""Seed the master menu with fresh fish, frozen fish and accessories.

Idempotent — skips items whose (category, name) already exist. Images live
in the database as bytea (image_data), with image_url pointing at the
public /menu-items/{id}/image endpoint that serves those bytes.

    python seed_menu.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from database import SessionLocal
from models import MenuItem


SEED_DIR = Path(__file__).resolve().parent / "seed_images"


# (category, name, price ₹, weight_kg per unit, description, image)
# Accessories have no meaningful per-unit weight — we keep that None.
ITEMS: list[tuple[str, str, float, Optional[float], str, str]] = [
    # Fresh fish — priced per kg, weight is the typical pack size we ship.
    ("fresh_fish", "Seer Fish",        650.0, 0.5,
     "Surmai steaks, cleaned and cut. Firm meaty fish that holds its shape on the tava.",
     "fresh-seer-fish.jpg"),
    ("fresh_fish", "Silver Pomfret",   850.0, 0.4,
     "Whole silver pomfret, scaled and gutted. Sweet, delicate flesh — classic Goan and coastal favourite.",
     "fresh-pomfret.jpg"),
    ("fresh_fish", "Indian Mackerel",  280.0, 0.25,
     "Bangda, gutted and ready to fry. Oily, full-flavoured fish — perfect with chilli-garlic masala.",
     "fresh-mackerel.jpg"),
    ("fresh_fish", "Tiger Prawns",     720.0, 0.5,
     "Headless tiger prawns, deveined. Plump and sweet — great for curry, koliwada or grill.",
     "fresh-tiger-prawns.jpg"),
    ("fresh_fish", "Red Snapper",      580.0, 0.6,
     "Whole red snapper, cleaned. Mild sweet flesh that takes well to tandoor or shallow fry.",
     "fresh-red-snapper.jpg"),
    # Frozen fish — IQF, priced per kg.
    ("frozen_fish", "Basa Fillets",    450.0, 0.5,
     "Boneless, skinless basa fillets. Mild flavour, cooks in minutes — weeknight friendly.",
     "frozen-basa.jpg"),
    ("frozen_fish", "Tilapia",         380.0, 0.5,
     "Cleaned tilapia, IQF frozen. Versatile white fish for fry, curry or steamed preparations.",
     "frozen-tilapia.jpg"),
    ("frozen_fish", "Squid Rings",     520.0, 0.5,
     "Pre-cut calamari rings, cleaned. Perfect for koliwada, salt-and-pepper squid or pasta.",
     "frozen-squid.jpg"),
    ("frozen_fish", "Prawn (PUD)",     680.0, 0.5,
     "Peeled and deveined prawns, IQF. Drop straight into curries or stir-fries — no prep.",
     "frozen-prawn.jpg"),
    ("frozen_fish", "Salmon Steaks",  1200.0, 0.3,
     "Atlantic salmon steaks, individually wrapped. Buttery and rich — pan-sear with lemon.",
     "frozen-salmon.jpg"),
    # Accessories — no weight (sold per piece / per pouch).
    ("accessories", "Fish Cleaning Knife",      450.0, None,
     "Curved 6-inch stainless blade. Comfortable grip for scaling, gutting and filleting.",
     "acc-cleaning-knife.jpg"),
    ("accessories", "Tandoori Marinade",        180.0, None,
     "Ready masala paste — yogurt, kashmiri chilli, ginger-garlic, garam masala. 200 g pouch.",
     "acc-tandoori-marinade.jpg"),
    ("accessories", "Fish Curry Masala",        220.0, None,
     "House blend of coriander, kokum, kashmiri chilli and tamarind. 100 g jar — coastal style.",
     "acc-fish-masala.jpg"),
    ("accessories", "Stainless Fish Tongs",     350.0, None,
     "Long-handled tongs with non-slip grip. Safe lifting from pan or fryer — dishwasher-friendly.",
     "acc-fish-tongs.jpg"),
    ("accessories", "Lemon Pepper Seasoning",   160.0, None,
     "Bright, citrusy rub for grilled fish and prawns. Cracked black pepper + dried lemon. 80 g.",
     "acc-lemon-pepper.jpg"),
]


def _read_bytes(filename: str) -> bytes:
    path = SEED_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(
            f"Missing seed image: {path}. Run generate_seed_images.py first."
        )
    return path.read_bytes()


def main() -> None:
    db = SessionLocal()
    try:
        inserted = updated = skipped = 0
        for category, name, price, weight_kg, desc, image_file in ITEMS:
            data = _read_bytes(image_file)
            existing = (
                db.query(MenuItem)
                .filter(MenuItem.category == category, MenuItem.name == name)
                .first()
            )
            if existing:
                # Refresh image + description + price + weight on re-seed so
                # iterating the seed data updates rather than duplicates.
                changed = False
                if existing.description != desc:
                    existing.description = desc
                    changed = True
                if float(existing.price) != float(price):
                    existing.price = price
                    changed = True
                old_w = float(existing.weight_kg) if existing.weight_kg is not None else None
                if old_w != weight_kg:
                    existing.weight_kg = weight_kg
                    changed = True
                if existing.image_data != data:
                    existing.image_data = data
                    existing.image_mime = "image/jpeg"
                    existing.image_url = f"/menu-items/{existing.id}/image"
                    changed = True
                if changed:
                    db.commit()
                    updated += 1
                    print(f"  ~ updated  {category:<14} {name}")
                else:
                    skipped += 1
                    print(f"  · skipped  {category:<14} {name}  (unchanged)")
                continue

            item = MenuItem(
                category=category,
                name=name,
                price=price,
                weight_kg=weight_kg,
                description=desc,
                image_data=data,
                image_mime="image/jpeg",
                is_active=True,
            )
            db.add(item)
            db.flush()  # populate item.id before referencing it in image_url
            item.image_url = f"/menu-items/{item.id}/image"
            db.commit()
            inserted += 1
            print(f"  + inserted {category:<14} {name}  (id={item.id})")

        print(f"\nDone. inserted={inserted} updated={updated} skipped={skipped}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
