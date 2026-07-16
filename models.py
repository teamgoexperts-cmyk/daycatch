"""SQLAlchemy ORM models for DayCatch."""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Integer,
    JSON,
    LargeBinary,
    MetaData,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import declarative_base

# DayCatch lives in its own Postgres schema so it never collides with other
# apps sharing the same database (e.g. a pre-existing public.users table).
SCHEMA = "daycatch"
Base = declarative_base(metadata=MetaData(schema=SCHEMA))


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    phone = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False, index=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    # Customer-only fields (nullable for other roles): pinned delivery address.
    address = Column(String, nullable=True)
    lat = Column(Numeric(10, 7), nullable=True)
    lon = Column(Numeric(10, 7), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (UniqueConstraint("phone", "role", name="uq_phone_role"),)


class OtpChallenge(Base):
    """Short-lived phone OTP codes stored in Postgres (Railway)."""

    __tablename__ = "otp_challenges"

    id = Column(Integer, primary_key=True)
    phone = Column(String, nullable=False, index=True)
    role = Column(String, nullable=False, index=True)
    code = Column(String(6), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class MenuItem(Base):
    __tablename__ = "menu_items"

    id = Column(Integer, primary_key=True)
    # one of: fresh_fish, frozen_fish, accessories, fish_and_chips
    category = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)
    price = Column(Numeric(10, 2), nullable=False)
    description = Column(Text, nullable=True)
    # Typical weight per unit, in kilograms. Admin sources by aggregate
    # weight, so capturing this on the master menu is what drives the
    # admin rollup. Nullable so accessories (and any old rows) stay valid.
    weight_kg = Column(Numeric(8, 3), nullable=True)
    # Optional sellable sizes for the same product, e.g. 1 kg, 500 g, 250 g.
    # The first variant mirrors price/weight_kg so older app flows keep working.
    variants = Column(JSON, nullable=True)
    # Preparation time in minutes — only meaningful for kiosk (fish_and_chips)
    # items. The kiosk cart sets the dining time to now + the MAX prep time
    # across the ordered items. Nullable; treated as 0 when unset.
    prep_time_minutes = Column(Integer, nullable=True)
    # image_url is the canonical reference for the client. It can point at
    # /media/<file>.jpg (legacy on-disk uploads, ephemeral on Railway) or at
    # /menu-items/<id>/image which is served from the bytes in image_data
    # below. image_data/image_mime are nullable so legacy rows still work.
    image_url = Column(String, nullable=True)
    image_data = Column(LargeBinary, nullable=True)
    image_mime = Column(String, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class MenuCategorySetting(Base):
    __tablename__ = "menu_category_settings"

    category = Column(String, primary_key=True)
    weight_enabled = Column(Boolean, default=False, nullable=False)
    prep_enabled = Column(Boolean, default=False, nullable=False)


class UploadedImage(Base):
    """Admin-uploaded image bytes, stored in the DB so they survive deploys.

    Railway's filesystem is ephemeral, so the old approach of writing uploads
    to disk and pointing image_url at /media/<file> lost the image on the next
    restart. Uploads now land here and are referenced as /uploaded-images/<id>,
    mirroring how seeded items embed their bytes in MenuItem.image_data.
    """

    __tablename__ = "uploaded_images"

    id = Column(Integer, primary_key=True)
    data = Column(LargeBinary, nullable=False)
    mime = Column(String, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class Shop(Base):
    __tablename__ = "shops"

    id = Column(Integer, primary_key=True)
    # owner: the distributor's users.id — one shop per distributor
    user_id = Column(Integer, nullable=False, unique=True, index=True)
    name = Column(String, nullable=False)
    location = Column(String, nullable=True)  # short map-derived area label
    address = Column(String, nullable=True)  # full postal address (free text)
    lat = Column(Numeric(10, 7), nullable=True)
    lon = Column(Numeric(10, 7), nullable=True)
    radius = Column(Numeric(7, 2), nullable=True)  # service radius in km
    shop_status = Column(String, nullable=False, default="inactive")  # active | inactive (admin-controlled)
    operation_status = Column(String, nullable=False, default="closed")  # open | closed
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class DistributorMenuItem(Base):
    """A distributor's selection from the master menu, with their own price
    and availability. Linked to MenuItem by master_item_id."""

    __tablename__ = "distributor_menu_items"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)  # distributor
    master_item_id = Column(Integer, nullable=False, index=True)
    price = Column(Numeric(10, 2), nullable=False)
    is_available = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("user_id", "master_item_id", name="uq_distributor_menu_item"),
    )


class Kiosk(Base):
    """A kiosk-owner's dine-in point. Customers come to the kiosk to dine (no
    delivery) but can pre-order. The service radius bounds which customers are
    offered this kiosk — i.e. how far away a customer can be and still see it as
    a pre-order option."""

    __tablename__ = "kiosks"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, unique=True, index=True)  # kiosk owner
    name = Column(String, nullable=False)
    location = Column(String, nullable=True)  # short map-derived area label
    address = Column(String, nullable=True)  # full postal address (free text)
    lat = Column(Numeric(10, 7), nullable=True)
    lon = Column(Numeric(10, 7), nullable=True)
    # Service radius in km — the reach within which customers are offered this
    # kiosk for pre-order pickup/dine-in. Nullable until the owner sets it.
    radius = Column(Numeric(7, 2), nullable=True)
    shop_status = Column(String, nullable=False, default="inactive")    # admin-controlled
    operation_status = Column(String, nullable=False, default="closed")  # owner-controlled
    open_24h = Column(Boolean, default=True, nullable=False)
    opening_time = Column(String(5), nullable=True)  # HH:MM local kiosk time
    closing_time = Column(String(5), nullable=True)  # HH:MM local kiosk time
    open_days = Column(JSON, nullable=True)  # 0=Mon ... 6=Sun
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    @property
    def hours_label(self):
        days = self.open_days if isinstance(self.open_days, list) else list(range(7))
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        days_label = "All week" if len(days) == 7 else ", ".join(day_names[d] for d in days if isinstance(d, int) and 0 <= d <= 6)
        if self.open_24h:
            return f"Open 24 hours ({days_label})"
        if self.opening_time and self.closing_time:
            return f"{self.opening_time}-{self.closing_time} ({days_label})"
        return "Hours not set"


class KioskMenuItem(Base):
    """A kiosk's pick from the master fish_and_chips category, with own
    price + availability. No weight — these are prepared dine-in items."""

    __tablename__ = "kiosk_menu_items"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)  # kiosk owner
    master_item_id = Column(Integer, nullable=False, index=True)
    price = Column(Numeric(10, 2), nullable=False)
    is_available = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("user_id", "master_item_id", name="uq_kiosk_menu_item"),
    )


class Address(Base):
    """A customer's saved delivery address. A customer can have many; one is
    flagged is_default. Orders snapshot the address text so deletion is safe.
    """

    __tablename__ = "addresses"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)  # customer
    label = Column(String, nullable=True)  # optional: "Home", "Office", ...
    address = Column(String, nullable=False)
    lat = Column(Numeric(10, 7), nullable=False)
    lon = Column(Numeric(10, 7), nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class Order(Base):
    """An order placed by a customer for delivery from one distributor's shop.
    All shop / address / item details are snapshotted so historical orders
    stay correct even if the source rows are edited or deleted later.
    """

    __tablename__ = "orders"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)       # customer
    # Fulfilled by either a distributor (delivery) OR a kiosk (pickup).
    # Existing delivery orders set distributor_user_id; kiosk pickup
    # orders set kiosk_user_id. Both columns nullable so a row uses one.
    distributor_user_id = Column(Integer, nullable=True, index=True)
    kiosk_user_id = Column(Integer, nullable=True, index=True)
    shop_id = Column(Integer, nullable=False, index=True)
    shop_name = Column(String, nullable=False)                  # snapshot
    address_id = Column(Integer, nullable=True)                 # original ref
    delivery_address = Column(String, nullable=False)           # snapshot
    delivery_lat = Column(Numeric(10, 7), nullable=False)
    delivery_lon = Column(Numeric(10, 7), nullable=False)
    subtotal = Column(Numeric(10, 2), nullable=False)
    # Razorpay payment. An order is created at checkout time with
    # payment_status "created" and stays INVISIBLE to distributors / kiosks /
    # admin until the payment is captured. It flips to "paid" by whichever
    # lands first — the app's post-payment confirm call or the Razorpay
    # webhook (the webhook is the source of truth so a crashed app can't lose
    # a paid order). "failed" marks a declined / abandoned attempt.
    razorpay_order_id = Column(String, nullable=True, index=True)
    razorpay_payment_id = Column(String, nullable=True)
    payment_status = Column(
        String, nullable=False, default="created", index=True
    )  # created | paid | failed
    # pending | accepted | ready | delivered | cancelled
    status = Column(String, nullable=False, default="pending", index=True)
    # When the order should be delivered. Computed at place-order time using
    # the 12-PM-IST cutoff (see app._compute_delivery_date). Indexed because
    # admin filters by it.
    delivery_date = Column(Date, nullable=True, index=True)
    # Kiosk dine-in only: when the order is expected to be ready (now + the max
    # prep time across its items, computed at checkout). Null for fish/accessories.
    dining_at = Column(DateTime, nullable=True)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class OrderItem(Base):
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True)
    order_id = Column(Integer, nullable=False, index=True)
    master_item_id = Column(Integer, nullable=False)            # original ref
    name_snapshot = Column(String, nullable=False)
    price_snapshot = Column(Numeric(10, 2), nullable=False)
    # Snapshotted weight per unit at order time, so later edits on the
    # master MenuItem don't retroactively shift the admin rollup. Nullable
    # for items that have no recorded weight (e.g. accessories).
    weight_kg_snapshot = Column(Numeric(8, 3), nullable=True)
    quantity = Column(Integer, nullable=False)
    line_total = Column(Numeric(10, 2), nullable=False)
