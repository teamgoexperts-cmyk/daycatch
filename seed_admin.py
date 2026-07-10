"""Seed an admin user so they can sign in to the portal.

The portal's /auth/session matches a row by (phone, role), where `phone` is the
Firebase `phone_number` claim in `+91XXXXXXXXXX` form. So we store exactly that.
Idempotent — re-running ensures the row exists and is active, never duplicates
(there's a unique constraint on (phone, role)).

    python seed_admin.py                 # seeds +919999999999 as admin
    python seed_admin.py 9876543210      # seeds a different number
    python seed_admin.py 9876543210 Priya Nair

NOTE: this only creates the DB row. The admin still signs in via Firebase Phone
Auth, so the number must be able to receive an OTP — either a real SIM, or a
Firebase *test* phone number (Authentication -> Sign-in method -> Phone ->
Test phone numbers) with a fixed code.
"""

from __future__ import annotations

import re
import sys

from database import SessionLocal
from models import User

PHONE_RE = re.compile(r"^\+91\d{10}$")


def normalize_phone(raw: str) -> str:
    """Accept '9999999999', '+919999999999' or '919999999999' -> '+919999999999'."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 10:
        digits = "91" + digits
    phone = "+" + digits
    if not PHONE_RE.match(phone):
        raise SystemExit(f"Not a valid Indian phone number: {raw!r}")
    return phone


def main() -> None:
    raw = sys.argv[1] if len(sys.argv) > 1 else "9999999999"
    first = sys.argv[2] if len(sys.argv) > 2 else "Admin"
    last = sys.argv[3] if len(sys.argv) > 3 else None
    phone = normalize_phone(raw)

    db = SessionLocal()
    try:
        existing = (
            db.query(User)
            .filter(User.phone == phone, User.role == "admin")
            .first()
        )
        if existing:
            changed = False
            if not existing.is_active:
                existing.is_active = True
                changed = True
            if existing.first_name is None and first:
                existing.first_name = first
                changed = True
            if changed:
                db.commit()
                print(f"~ updated admin {phone} (id={existing.id}) -> active")
            else:
                print(f"· admin {phone} already exists (id={existing.id}) — no change")
            return

        user = User(
            phone=phone,
            role="admin",
            first_name=first,
            last_name=last,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"+ inserted admin {phone} (id={user.id})")
    finally:
        db.close()


if __name__ == "__main__":
    main()
