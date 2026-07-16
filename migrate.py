"""On-demand schema migration for DayCatch.

Run it whenever the models change:

    python migrate.py

`Base.metadata.create_all` only adds *missing* tables — it does not alter
existing ones. For column changes on a live table, add an explicit ALTER in
`migrate_columns()` below. Idempotent: safe to re-run.

Users are NOT seeded here. They live in the database and are managed there
directly (or via admin onboarding later) — not in .env.
"""

from sqlalchemy import text

from database import DATABASE_URL, engine
from models import SCHEMA, Base


def create_schema_and_tables() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        with engine.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"'))
        print(f'[migrate] schema "{SCHEMA}" ensured')
    Base.metadata.create_all(bind=engine)
    print(f"[migrate] tables up to date: {', '.join(Base.metadata.tables)}")


def migrate_columns() -> None:
    """Hand-written ALTERs for changes create_all can't apply on its own.

    create_all only creates *missing tables*, never new columns on an existing
    table — so column changes live here, each guarded to stay idempotent.
    """
    if DATABASE_URL.startswith("sqlite"):
        return
    with engine.begin() as conn:
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".users ADD COLUMN IF NOT EXISTS first_name VARCHAR'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".users ADD COLUMN IF NOT EXISTS last_name VARCHAR'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".shops ADD COLUMN IF NOT EXISTS radius NUMERIC(7, 2)'))
        # Distributor full postal address (free text, separate from the short
        # map-derived 'location' label). Backfill existing shops with a
        # placeholder so the field is never empty for already-onboarded
        # distributors — they'll replace it when they next edit their shop.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".shops ADD COLUMN IF NOT EXISTS address VARCHAR'))
        conn.execute(text(f"UPDATE \"{SCHEMA}\".shops SET address = 'address needed' WHERE address IS NULL OR address = ''"))
        # Kiosks gained a service radius (dine-in pre-order reach), mirroring shops.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".kiosks ADD COLUMN IF NOT EXISTS radius NUMERIC(7, 2)'))
        # Kiosk full postal address, mirroring shops.address. Backfill existing
        # kiosks with a placeholder so the field is never empty.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".kiosks ADD COLUMN IF NOT EXISTS address VARCHAR'))
        conn.execute(text(f"UPDATE \"{SCHEMA}\".kiosks SET address = 'address needed' WHERE address IS NULL OR address = ''"))
        conn.execute(text(f"ALTER TABLE \"{SCHEMA}\".kiosks ADD COLUMN IF NOT EXISTS open_24h BOOLEAN NOT NULL DEFAULT TRUE"))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".kiosks ADD COLUMN IF NOT EXISTS opening_time VARCHAR(5)'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".kiosks ADD COLUMN IF NOT EXISTS closing_time VARCHAR(5)'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".kiosks ADD COLUMN IF NOT EXISTS open_days JSONB'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".users ADD COLUMN IF NOT EXISTS address VARCHAR'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".users ADD COLUMN IF NOT EXISTS lat NUMERIC(10, 7)'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".users ADD COLUMN IF NOT EXISTS lon NUMERIC(10, 7)'))
        # Menu item image bytes (persistent, unlike Railway's ephemeral disk).
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".menu_items ADD COLUMN IF NOT EXISTS image_data BYTEA'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".menu_items ADD COLUMN IF NOT EXISTS image_mime VARCHAR'))
        # Per-unit weight in kg for fish items — drives the admin sourcing
        # rollup. Snapshotted onto order_items at place-order time so later
        # weight edits don't retroactively skew historical orders.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".menu_items  ADD COLUMN IF NOT EXISTS weight_kg          NUMERIC(8, 3)'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".menu_items  ADD COLUMN IF NOT EXISTS variants           JSONB'))
        # Kiosk (fish_and_chips) prep time in minutes; drives dine-in timing.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".menu_items  ADD COLUMN IF NOT EXISTS prep_time_minutes  INTEGER'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".order_items ADD COLUMN IF NOT EXISTS weight_kg_snapshot NUMERIC(8, 3)'))
        # Kiosk-pickup orders share the orders table with delivery orders;
        # one of distributor_user_id / kiosk_user_id is set per row.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".orders ADD COLUMN IF NOT EXISTS kiosk_user_id INTEGER'))
        conn.execute(text(f'CREATE INDEX IF NOT EXISTS ix_{SCHEMA}_orders_kiosk_user_id ON "{SCHEMA}".orders (kiosk_user_id)'))
        # distributor_user_id used to be NOT NULL — relax it so kiosk-only
        # orders can be inserted without a distributor.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".orders ALTER COLUMN distributor_user_id DROP NOT NULL'))
        # Per-order delivery date (12-PM-IST cutoff is applied at create
        # time). Index makes admin's "Tomorrow / Day after tomorrow" tabs
        # cheap. Backfill existing rows so the column is meaningful for
        # historical orders before this migration.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".orders ADD COLUMN IF NOT EXISTS delivery_date DATE'))
        conn.execute(text(f'CREATE INDEX IF NOT EXISTS ix_{SCHEMA}_orders_delivery_date ON "{SCHEMA}".orders (delivery_date)'))
        conn.execute(text(f"""
            UPDATE "{SCHEMA}".orders
               SET delivery_date = ((created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Kolkata')::date + 1)
             WHERE delivery_date IS NULL
        """))
        # Backfill: every customer with an inline user.address (the legacy
        # single-address column) gets a matching default row in addresses,
        # but only if they don't already have one. Idempotent.
        conn.execute(text(f"""
            INSERT INTO "{SCHEMA}".addresses
                (user_id, address, lat, lon, is_default, created_at)
            SELECT u.id, u.address, u.lat, u.lon, TRUE, NOW()
              FROM "{SCHEMA}".users u
             WHERE u.role = 'customer'
               AND u.address IS NOT NULL
               AND u.lat IS NOT NULL
               AND u.lon IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM "{SCHEMA}".addresses a WHERE a.user_id = u.id
               )
        """))
        # Razorpay payment fields. Orders now begin life at checkout with
        # payment_status='created' and only become visible to fulfillment once
        # captured. Existing orders predate online payments, so backfill them
        # as 'paid' (they have no razorpay_order_id) to keep them visible.
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".orders ADD COLUMN IF NOT EXISTS razorpay_order_id   VARCHAR'))
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".orders ADD COLUMN IF NOT EXISTS razorpay_payment_id VARCHAR'))
        conn.execute(text(f"ALTER TABLE \"{SCHEMA}\".orders ADD COLUMN IF NOT EXISTS payment_status VARCHAR NOT NULL DEFAULT 'created'"))
        conn.execute(text(f'CREATE INDEX IF NOT EXISTS ix_{SCHEMA}_orders_razorpay_order_id ON "{SCHEMA}".orders (razorpay_order_id)'))
        conn.execute(text(f'CREATE INDEX IF NOT EXISTS ix_{SCHEMA}_orders_payment_status ON "{SCHEMA}".orders (payment_status)'))
        conn.execute(text(f"UPDATE \"{SCHEMA}\".orders SET payment_status = 'paid' WHERE razorpay_order_id IS NULL AND payment_status = 'created'"))
        # Kiosk dine-in: expected-ready timestamp (now + max prep at checkout).
        conn.execute(text(f'ALTER TABLE "{SCHEMA}".orders ADD COLUMN IF NOT EXISTS dining_at TIMESTAMP'))
        # Migrate a legacy single 'name' column into first_name, then drop it.
        conn.execute(text(f"""
            DO $$
            BEGIN
              IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = '{SCHEMA}' AND table_name = 'users'
                  AND column_name = 'name'
              ) THEN
                UPDATE "{SCHEMA}".users
                   SET first_name = name
                 WHERE first_name IS NULL AND name IS NOT NULL;
                ALTER TABLE "{SCHEMA}".users DROP COLUMN name;
              END IF;
            END $$;
        """))
    print("[migrate] ensured first_name/last_name (legacy 'name' migrated + dropped)")


def main() -> None:
    create_schema_and_tables()
    migrate_columns()
    print("[migrate] done")


if __name__ == "__main__":
    main()
