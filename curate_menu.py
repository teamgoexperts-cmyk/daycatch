"""One-off: trim the master menu to exactly 3 real items per customer-facing
category and give each a real Unsplash photo (stored in-DB as image_data).

- Keeps 9 curated items (the "best per category" picks), deletes everything
  else in fresh_fish / frozen_fish / accessories. Leaves fish_and_chips alone.
- order_items snapshot name/price/weight and there are no FK constraints, so
  deleting masters does not corrupt existing order history.

    venv/Scripts/python curate_menu.py
"""

from __future__ import annotations

import urllib.request

from database import SessionLocal
from models import MenuItem
from sqlalchemy import text

UA = "Mozilla/5.0 (compatible; DayCatchSeed/1.0)"

# id -> (primary unsplash photo base, fallback). Picks are the top relevant
# results from the matching Unsplash search page.
IMAGES: dict[int, tuple[str, str]] = {
    6:  ("photo-1682457569891-53e4f6ef9271", "photo-1601314002592-b8734bca6604"),  # Seer Fish (raw fish loin)
    7:  ("photo-1633244079780-709af26ae3ad", "photo-1638186617501-6ae552889806"),  # Silver Pomfret (whole)
    9:  ("photo-1548587468-971ebe4c8c3b",    "photo-1565680018434-b513d5e5fd47"),  # Tiger Prawns
    11: ("photo-1772285253181-b1257afb3698", "photo-1628280738974-24e582b9904a"),  # Basa Fillets
    13: ("photo-1734771219838-61863137b117", "photo-1682264895449-f75b342cbab6"),  # Squid Rings (fried calamari)
    15: ("photo-1599084993091-1cb5c0721cc6", "photo-1641898378373-0ef528eec4be"),  # Salmon Steaks
    16: ("photo-1596633609591-e4e1e9e06b7f", "photo-1574906328425-c7a4cb49bfa8"),  # Fish Cleaning Knife
    18: ("photo-1716816211590-c15a328a5ff0", "photo-1606914469633-bd39206ea739"),  # Fish Curry Masala
    19: ("photo-1592771584685-c3c2edcd5c31", "photo-1622303001920-f5f9de43209d"),  # Stainless Fish Tongs
}

KEEP = set(IMAGES)
DELETE = [1, 2, 4, 5, 8, 10, 12, 14, 17, 20]

PARAMS = "?w=800&h=800&fit=crop&crop=entropy&q=80&fm=jpg"


def fetch(base: str) -> bytes:
    url = f"https://images.unsplash.com/{base}{PARAMS}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    data = urllib.request.urlopen(req, timeout=30).read()
    if data[:2] != b"\xff\xd8" or len(data) < 8000:
        raise ValueError(f"not a usable jpeg ({len(data)} bytes)")
    return data


def fetch_with_fallback(primary: str, fallback: str) -> bytes:
    try:
        return fetch(primary)
    except Exception as e:  # noqa: BLE001 — fall back on any download/validation failure
        print(f"    primary failed ({e}); trying fallback")
        return fetch(fallback)


def main() -> None:
    db = SessionLocal()
    try:
        # 1) Download all 9 images up front so we never half-apply on a network blip.
        blobs: dict[int, bytes] = {}
        for item_id, (primary, fallback) in IMAGES.items():
            blobs[item_id] = fetch_with_fallback(primary, fallback)
            print(f"  downloaded id={item_id}  ({len(blobs[item_id]) // 1024} KB)")

        # 2) Apply images to the 9 kept items.
        for item_id, data in blobs.items():
            item = db.get(MenuItem, item_id)
            if item is None:
                raise RuntimeError(f"expected kept item id={item_id} is missing")
            item.image_data = data
            item.image_mime = "image/jpeg"
            item.image_url = f"/menu-items/{item.id}/image"
            item.is_active = True
            print(f"  ~ image set  {item.category:<12} {item.name}")

        # 3) Delete the surplus + test rows.
        res = db.execute(
            text("delete from daycatch.menu_items where id = any(:ids)"),
            {"ids": DELETE},
        )
        print(f"  - deleted {res.rowcount} surplus/test rows")

        db.commit()

        # 4) Report final state.
        rows = (
            db.query(MenuItem)
            .filter(MenuItem.category.in_(["fresh_fish", "frozen_fish", "accessories"]))
            .order_by(MenuItem.category, MenuItem.id)
            .all()
        )
        print("\nFinal customer-facing menu:")
        for r in rows:
            print(f"  {r.id:>3} {r.category:<12} {r.name:<22} {r.image_url}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
