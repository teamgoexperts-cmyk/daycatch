import math
import os
import re
import secrets
import urllib.error
import urllib.request
import hashlib
import requests
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional
from zoneinfo import ZoneInfo

import razorpay
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from database import get_db
from migrate import create_schema_and_tables, migrate_columns
from models import (
    Address,
    DistributorMenuItem,
    Kiosk,
    KioskMenuItem,
    MenuCategorySetting,
    MenuItem,
    Order,
    OrderItem,
    OtpChallenge,
    Shop,
    UploadedImage,
    User,
    Coupon,
    CouponUsage,
)

load_dotenv()

# ============ Config ============
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = "HS256"
JWT_TTL_HOURS = int(os.getenv("JWT_TTL_HOURS", "720"))  # 720h = 30 days
# Always allow the public site + local Vite, then merge any extra CORS_ORIGINS.
_FRONTEND_ORIGINS = [
    "https://daycatch.in",
    "https://www.daycatch.in",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
_env_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if _env_origins == ["*"]:
    CORS_ORIGINS = ["*"]
else:
    CORS_ORIGINS = list(dict.fromkeys(_FRONTEND_ORIGINS + _env_origins))
OTP_TTL_MINUTES = int(os.getenv("OTP_TTL_MINUTES", "10"))
# Dev: log OTP to server console and return it in the API response (no SMS provider).
DEV_LOG_OTP = os.getenv("DEV_LOG_OTP", "true").lower() in ("1", "true", "yes")

import json as _json

# Razorpay. KEY_ID is public (sent to the app to open checkout); KEY_SECRET
# signs/creates orders and verifies payment signatures; WEBHOOK_SECRET verifies
# the separate webhook callback (a DIFFERENT secret from KEY_SECRET).
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "").strip()
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "").strip()

# Resend (https://resend.com) powers the customer-site contact form. The API key
# is secret (Railway env). RESEND_FROM must be a verified-domain sender once the
# domain is set up in Resend; the sandbox default only delivers to the Resend
# account owner. Enquiries are emailed to ENQUIRY_TO.
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
# Sender on the verified deepship.dev domain; overridable via env.
RESEND_FROM = os.getenv("RESEND_FROM", "DayCatch <support@deepship.dev>").strip()
ENQUIRY_TO = os.getenv("ENQUIRY_TO", "vinod.mallolu@gmail.com").strip()

ROLES = ("admin", "distributor", "kiosk", "customer")
Role = Literal["admin", "distributor", "kiosk", "customer"]
PHONE_RE = re.compile(r"^\+91\d{10}$")
TIME_RE = re.compile(r"^\d{2}:\d{2}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MOBILE_RE = re.compile(r"^\+91[6-9]\d{9}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z\s'-]{0,49}$")


# ============ Razorpay & Easebuzz Payments ============
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")

EASEBUZZ_KEY = os.getenv("EASEBUZZ_KEY", "")
EASEBUZZ_SALT = os.getenv("EASEBUZZ_SALT", "")
EASEBUZZ_ENV = os.getenv("EASEBUZZ_ENV", "production")
EASEBUZZ_SURL = os.getenv("EASEBUZZ_SURL", "https://daycatch-rkmr.onrender.com/payment/success")
EASEBUZZ_FURL = os.getenv("EASEBUZZ_FURL", "https://daycatch-rkmr.onrender.com/payment/failure")

_razorpay_client = (
    razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET
    else None
)


def check_payments_configured() -> bool:
    return bool(_razorpay_client is not None) or bool(EASEBUZZ_KEY and EASEBUZZ_SALT)


def _require_payments():
    if not check_payments_configured():
        raise HTTPException(503, "Payments are not configured.")


def _initiate_easebuzz_payment(order_id: int, amount: float, user: User) -> dict:
    txnid = f"DC_{order_id}_{int(datetime.now().timestamp())}"
    amt_str = f"{amount:.2f}"
    productinfo = f"DayCatch Order {order_id}"
    firstname = user.first_name or "Customer"
    email = "customer@daycatch.in"
    raw_phone = re.sub(r"\D", "", user.phone or "")
    phone = raw_phone[-10:] if len(raw_phone) >= 10 else raw_phone
    
    # Hash sequence: key|txnid|amount|productinfo|firstname|email|udf1|udf2|udf3|udf4|udf5|udf6|udf7|udf8|udf9|udf10|salt
    hash_str = f"{EASEBUZZ_KEY}|{txnid}|{amt_str}|{productinfo}|{firstname}|{email}|||||||||||{EASEBUZZ_SALT}"
    hash_val = hashlib.sha512(hash_str.encode("utf-8")).hexdigest()
    
    payload = {
        "key": EASEBUZZ_KEY,
        "txnid": txnid,
        "amount": amt_str,
        "productinfo": productinfo,
        "firstname": firstname,
        "email": email,
        "phone": phone,
        "surl": EASEBUZZ_SURL,
        "furl": EASEBUZZ_FURL,
        "hash": hash_val,
        "udf1": "", "udf2": "", "udf3": "", "udf4": "", "udf5": "",
        "udf6": "", "udf7": "", "udf8": "", "udf9": "", "udf10": ""
    }
    
    url = (
        "https://pay.easebuzz.in/payment/initiateLink"
        if EASEBUZZ_ENV == "production"
        else "https://testpay.easebuzz.in/payment/initiateLink"
    )
    
    import pprint
    print("--- EASEBUZZ REQUEST ---")
    print(f"URL: {url}")
    pprint.pprint(payload)
    
    try:
        r = requests.post(url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
        res = r.json()
        print("--- EASEBUZZ RESPONSE ---")
        pprint.pprint(res)
        if res.get("status") == 1:
            access_key = res.get("data")
            base_pay_url = (
                "https://pay.easebuzz.in/pay/"
                if EASEBUZZ_ENV == "production"
                else "https://testpay.easebuzz.in/pay/"
            )
            return {
                "easebuzz_access_key": access_key,
                "easebuzz_payment_url": f"{base_pay_url}{access_key}"
            }
        else:
            raise HTTPException(400, f"Easebuzz initiation failed: {res.get('message') or res.get('data')}")
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(400, f"Error calling Easebuzz API: {str(e)}")


def _create_checkout_session(order: Order, amount_paise: int, final_amount: float, user: User, db: Session) -> CheckoutOut:
    _require_payments()
    
    if EASEBUZZ_KEY and EASEBUZZ_SALT:
        try:
            eb = _initiate_easebuzz_payment(order.id, final_amount, user)
            order.razorpay_order_id = eb["easebuzz_access_key"]
            db.commit()
            return CheckoutOut(
                order_id=order.id,
                amount=amount_paise,
                currency="INR",
                key_id=EASEBUZZ_KEY,
                easebuzz_access_key=eb["easebuzz_access_key"],
                easebuzz_payment_url=eb["easebuzz_payment_url"],
            )
        except Exception as e:
            db.rollback()
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(502, f"Could not start Easebuzz payment: {e}")
    else:
        client = _razorpay_client
        try:
            rzp_order = client.order.create(
                {
                    "amount": amount_paise,
                    "currency": "INR",
                    "receipt": f"daycatch_order_{order.id}",
                    "payment_capture": 1,
                    "notes": {
                        "daycatch_order_id": str(order.id),
                        "customer_user_id": str(user.id),
                    },
                }
            )
        except Exception as e:
            db.rollback()
            raise HTTPException(502, f"Could not start Razorpay payment: {e}")
            
        order.razorpay_order_id = rzp_order["id"]
        db.commit()
        return CheckoutOut(
            order_id=order.id,
            razorpay_order_id=rzp_order["id"],
            amount=amount_paise,
            currency="INR",
            key_id=RAZORPAY_KEY_ID,
        )


# ============ Helpers ============
def normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 10:
        return "+91" + digits
    if len(digits) == 12 and digits.startswith("91"):
        return "+" + digits
    return raw or ""


def _clock_skew_note(client_time_ms: Optional[int]) -> str:
    """Human-readable skew between the client's clock and the server's, for
    auth debugging. A large value points at a wrong device clock — the most
    common cause of 'OTP / sign-in expired' for a single user."""
    if not client_time_ms:
        return "clock_skew_s=-"
    server_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    return f"clock_skew_s={(server_ms - client_time_ms) / 1000.0:.1f}"


def make_session_token(phone: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": phone,
            "role": role,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=JWT_TTL_HOURS)).timestamp()),
        },
        JWT_SECRET,
        algorithm=JWT_ALG,
    )


# ============ Schemas ============
class OtpSendIn(BaseModel):
    phone: str
    role: Role


class OtpSendOut(BaseModel):
    message: str
    dev_otp: Optional[str] = None  # only when DEV_LOG_OTP is enabled


class OtpVerifyIn(BaseModel):
    phone: str
    role: Role
    otp: str
    client_time_ms: Optional[int] = None


class SessionOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role
    phone: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class MeOut(BaseModel):
    phone: str
    role: Role
    first_name: Optional[str] = None
    last_name: Optional[str] = None


# ============ App ============
app = FastAPI(title="DayCatch Auth API", version="0.2.0")


@app.on_event("startup")
def ensure_schema_columns() -> None:
    create_schema_and_tables()
    migrate_columns()

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["*"],
    # Local Vite + the public site (static host calls Render cross-origin).
    allow_origin_regex=r"https://([a-z0-9-]+\.)*daycatch\.in|http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============ Routes ============
def _session_for_phone(phone: str, role: Role, db: Session) -> SessionOut:
    """Look up (or create) the user and issue a DayCatch session JWT."""
    user = db.query(User).filter(User.phone == phone, User.role == role).first()
    if user is None and role == "customer":
        user = User(phone=phone, role="customer", is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
    if not user or not user.is_active:
        raise HTTPException(403, "No active account for this phone and role.")
    return SessionOut(
        access_token=make_session_token(phone, role),
        role=role,
        phone=phone,
        first_name=user.first_name,
        last_name=user.last_name,
    )


@app.post("/auth/otp/send", response_model=OtpSendOut)
def send_otp(body: OtpSendIn, db: Session = Depends(get_db)) -> OtpSendOut:
    """Generate a one-time code for phone sign-in. In dev mode the code is
    logged and returned in the response (no SMS provider required)."""
    phone = normalize_phone(body.phone)
    if not PHONE_RE.match(phone):
        raise HTTPException(400, "Enter a valid Indian phone number (+91, 10 digits).")

    code = f"{secrets.randbelow(900000) + 100000:06d}"
    expires = datetime.now(timezone.utc) + timedelta(minutes=OTP_TTL_MINUTES)

    db.query(OtpChallenge).filter(
        OtpChallenge.phone == phone, OtpChallenge.role == body.role
    ).delete()
    db.add(OtpChallenge(phone=phone, role=body.role, code=code, expires_at=expires))
    db.commit()

    if DEV_LOG_OTP:
        print(f"[auth/otp/send] phone={phone} role={body.role} code={code} expires_in={OTP_TTL_MINUTES}m")

    return OtpSendOut(
        message="OTP sent.",
        dev_otp=code if DEV_LOG_OTP else None,
    )


@app.post("/auth/otp/verify", response_model=SessionOut)
def verify_otp(body: OtpVerifyIn, db: Session = Depends(get_db)) -> SessionOut:
    """Verify the OTP and return a DayCatch session JWT."""
    skew = _clock_skew_note(body.client_time_ms)
    phone = normalize_phone(body.phone)
    if not PHONE_RE.match(phone):
        raise HTTPException(400, "Enter a valid Indian phone number (+91, 10 digits).")
    otp = (body.otp or "").strip()
    if not re.fullmatch(r"\d{6}", otp):
        raise HTTPException(400, "Enter the 6-digit code.")

    now = datetime.now(timezone.utc)
    challenge = (
        db.query(OtpChallenge)
        .filter(
            OtpChallenge.phone == phone,
            OtpChallenge.role == body.role,
            OtpChallenge.code == otp,
        )
        .first()
    )
    if not challenge:
        print(f"[auth/otp/verify] failed phone={phone} role={body.role} {skew}")
        raise HTTPException(401, "Invalid or expired code. Request a new one.")
    expires = challenge.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < now:
        print(f"[auth/otp/verify] failed phone={phone} role={body.role} {skew}")
        raise HTTPException(401, "Invalid or expired code. Request a new one.")

    db.delete(challenge)
    db.commit()
    print(f"[auth/otp/verify] ok phone={phone} role={body.role} {skew}")
    return _session_for_phone(phone, body.role, db)


# ============ Client diagnostics ============
class ClientLogIn(BaseModel):
    event: str  # e.g. "sendOtp" | "verifyOtp"
    code: Optional[str] = None
    message: Optional[str] = None
    phone: Optional[str] = None
    role: Optional[str] = None
    platform: Optional[str] = None  # ios | android | web
    os_version: Optional[str] = None
    device: Optional[str] = None  # manufacturer + model (Android discriminator)
    app_version: Optional[str] = None
    tz: Optional[str] = None  # client IANA timezone
    device_time_ms: Optional[int] = None  # client wall-clock (epoch ms)
    elapsed_ms: Optional[int] = None  # ms from OTP-sent to this verify attempt


@app.post("/client-log", status_code=204)
def client_log(body: ClientLogIn) -> Response:
    """Unauthenticated diagnostics sink. Sign-in failures happen before any
    token exists, so the client posts them here."""
    phone = normalize_phone(body.phone or "") or "-"
    msg = (body.message or "")[:300]
    elapsed = (
        f"{body.elapsed_ms / 1000.0:.1f}" if body.elapsed_ms is not None else "-"
    )
    print(
        f"[client-log] event={body.event} code={body.code} phone={phone} "
        f"role={body.role} platform={body.platform} os={body.os_version} "
        f"device={body.device!r} app={body.app_version} tz={body.tz} "
        f"{_clock_skew_note(body.device_time_ms)} elapsed_s={elapsed} msg={msg!r}"
    )
    return Response(status_code=204)


# ============ Bearer auth ============
bearer = HTTPBearer(auto_error=True)


def current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        raise HTTPException(401, "Invalid or expired token.")
    phone = payload.get("sub")
    role = payload.get("role")
    user = db.query(User).filter(User.phone == phone, User.role == role).first()
    if not user or not user.is_active:
        raise HTTPException(403, "Account is inactive.")
    return user


@app.get("/auth/me", response_model=MeOut)
def me(user: User = Depends(current_user)) -> MeOut:
    return MeOut(
        phone=user.phone,
        role=user.role,
        first_name=user.first_name,
        last_name=user.last_name,
    )


@app.get("/health")
def health() -> dict:
    return {"ok": True}


# ============ Customer site: contact / enquiry ============
class EnquiryIn(BaseModel):
    name: str
    email: str
    message: str


@app.post("/enquiry", status_code=202)
def submit_enquiry(body: EnquiryIn) -> dict:
    """Public contact-form endpoint for the marketing site. Emails the enquiry
    to ENQUIRY_TO via Resend. No auth — guard against abuse at the edge if
    needed."""
    name = body.name.strip()
    email = body.email.strip()
    message = body.message.strip()
    if not name or not message:
        raise HTTPException(400, "Name and message are required.")
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Enter a valid email address.")
    if not RESEND_API_KEY:
        raise HTTPException(503, "Email is not configured. Please try later.")

    payload = {
        "from": RESEND_FROM,
        "to": [ENQUIRY_TO],
        "reply_to": email,
        "subject": f"New DayCatch enquiry from {name}",
        "text": f"Name: {name}\nEmail: {email}\n\n{message}",
    }
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=_json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            # Cloudflare fronts the Resend API and blocks the default
            # "Python-urllib" agent (403, error 1010). A normal UA passes.
            "User-Agent": "Mozilla/5.0 (compatible; DayCatch/1.0; +https://daycatch.in)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="ignore")
        print(f"[enquiry] Resend HTTP {e.code}: {body_text}")
        raise HTTPException(502, "Could not send your message. Please try again.")
    except Exception as e:  # noqa: BLE001 — network/timeout etc.
        print(f"[enquiry] Resend send failed: {type(e).__name__}: {e}")
        raise HTTPException(502, "Could not send your message. Please try again.")
    return {"ok": True}


# ============ Admin: manage distributors & kiosk owners ============
# Admins manage the OTHER two roles only — never other admins. ManageableRole
# rejects "admin" on input, and every query is scoped to MANAGEABLE_ROLES, so
# admin rows are invisible to (and untouchable by) these endpoints.
MANAGEABLE_ROLES = ("distributor", "kiosk")
ManageableRole = Literal["distributor", "kiosk"]


def admin_required(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Admin access required.")
    return user


class AdminUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    phone: str
    role: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: bool


class AdminUserIn(BaseModel):
    phone: str
    role: ManageableRole
    first_name: str
    last_name: str


class AdminUserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None
    phone: Optional[str] = None


@app.get("/admin/users", response_model=list[AdminUserOut])
def admin_list_users(
    role: Optional[ManageableRole] = None,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[User]:
    q = db.query(User).filter(User.role.in_(MANAGEABLE_ROLES))
    if role:
        q = q.filter(User.role == role)
    return q.order_by(User.created_at.desc()).all()


@app.post("/admin/users", response_model=AdminUserOut, status_code=201)
def admin_create_user(
    body: AdminUserIn,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> User:
    phone = normalize_phone(body.phone)
    if not MOBILE_RE.match(phone):
        raise HTTPException(400, "Enter a valid 10-digit mobile number.")
    first, last = body.first_name.strip(), body.last_name.strip()
    if not first or not last:
        raise HTTPException(400, "First and last name are required.")
    if not NAME_RE.match(first) or not NAME_RE.match(last):
        raise HTTPException(400, "Names may contain only letters, spaces, - and '.")
    if db.query(User).filter(User.phone == phone, User.role == body.role).first():
        raise HTTPException(409, "That phone already has this role.")
    user = User(phone=phone, role=body.role, first_name=first, last_name=last)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.patch("/admin/users/{user_id}", response_model=AdminUserOut)
def admin_update_user(
    user_id: int,
    body: AdminUserUpdate,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> User:
    user = (
        db.query(User)
        .filter(User.id == user_id, User.role.in_(MANAGEABLE_ROLES))
        .first()
    )
    if not user:
        raise HTTPException(404, "User not found.")
    if body.phone is not None:
        # Phone is the owner's login credential. Changing it means they must
        # sign in with the new number going forward; any active session keyed
        # to the old number will fall through to a 403 and force re-login.
        phone = normalize_phone(body.phone)
        if not MOBILE_RE.match(phone):
            raise HTTPException(400, "Enter a valid 10-digit mobile number.")
        if phone != user.phone:
            clash = (
                db.query(User)
                .filter(User.phone == phone, User.role == user.role, User.id != user.id)
                .first()
            )
            if clash:
                raise HTTPException(409, "That phone already has this role.")
            user.phone = phone
    if body.first_name is not None:
        user.first_name = body.first_name.strip() or None
    if body.last_name is not None:
        user.last_name = body.last_name.strip() or None
    if body.is_active is not None:
        user.is_active = body.is_active
    db.commit()
    db.refresh(user)
    return user


# ============ Admin: shop activation ============
# Admins approve distributor shops by flipping shop_status active/inactive.
# Distributors control operation_status (open/closed) separately, but a blocked
# shop is force-closed so customers can't see it as serving.

class AdminShopOut(BaseModel):
    id: int
    user_id: int
    owner_name: Optional[str] = None
    owner_phone: str
    name: str
    location: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius: Optional[float] = None
    shop_status: str
    operation_status: str


class AdminShopUpdate(BaseModel):
    shop_status: Literal["active", "inactive"]


def _admin_shop_dto(shop, user) -> AdminShopOut:
    parts = [user.first_name, user.last_name] if user else []
    owner_name = " ".join(p for p in parts if p) or None
    return AdminShopOut(
        id=shop.id,
        user_id=shop.user_id,
        owner_name=owner_name,
        owner_phone=user.phone if user else "",
        name=shop.name,
        location=shop.location,
        address=shop.address,
        lat=float(shop.lat) if shop.lat is not None else None,
        lon=float(shop.lon) if shop.lon is not None else None,
        radius=float(shop.radius) if shop.radius is not None else None,
        shop_status=shop.shop_status,
        operation_status=shop.operation_status,
    )


@app.get("/admin/shops", response_model=list[AdminShopOut])
def admin_list_shops(
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Shop, User)
        .join(User, User.id == Shop.user_id)
        # Inactive first so pending approvals surface at the top.
        .order_by(Shop.shop_status.asc(), Shop.name.asc())
        .all()
    )
    return [_admin_shop_dto(shop, user) for shop, user in rows]


@app.patch("/admin/shops/{shop_id}", response_model=AdminShopOut)
def admin_update_shop_status(
    shop_id: int,
    body: AdminShopUpdate,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
):
    shop = db.query(Shop).filter(Shop.id == shop_id).first()
    if not shop:
        raise HTTPException(404, "Shop not found.")
    shop.shop_status = body.shop_status
    # Blocking a shop also forces it closed so it disappears from customer view.
    if body.shop_status == "inactive":
        shop.operation_status = "closed"
    db.commit()
    db.refresh(shop)
    user = db.query(User).filter(User.id == shop.user_id).first()
    return _admin_shop_dto(shop, user)


# ============ Menu items (catalog) ============
CATEGORIES = (
    "fresh_fish",
    "frozen_fish",
    "dry_fish",
    "accessories",
    "pickles",
    "fish_and_chips",
)
Category = Literal[
    "fresh_fish",
    "frozen_fish",
    "dry_fish",
    "accessories",
    "pickles",
    "fish_and_chips",
]
DEFAULT_CATEGORY_FIELD_SETTINGS = {
    category: {
        "weight_enabled": True,
        "prep_enabled": category == "fish_and_chips",
    }
    for category in CATEGORIES
}

# Sentinel shop-name snapshots for central-admin orders (no distributor / kiosk).
# Accessories, dry fish and pickles all ship from DayCatch, so the admin
# fulfilment views key off the shop name to keep their queues separate.
ACCESSORIES_SHOP_NAME = "DayCatch Accessories"
DRY_FISH_SHOP_NAME = "DayCatch Dry Fish"
PICKLES_SHOP_NAME = "DayCatch Pickles"

UPLOAD_DIR = Path(__file__).resolve().parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
app.mount("/media", StaticFiles(directory=UPLOAD_DIR), name="media")

ALLOWED_IMAGE_EXT = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
ALLOWED_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB


class MenuItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    category: str
    name: str
    price: float
    description: Optional[str] = None
    image_url: Optional[str] = None
    # Typical weight per unit, kg. Null for accessories.
    weight_kg: Optional[float] = None
    variants: Optional[list[dict]] = None
    # Prep time in minutes — kiosk (fish_and_chips) items only. Null elsewhere.
    prep_time_minutes: Optional[int] = None
    is_active: bool


class MenuCategorySettingOut(BaseModel):
    category: Category
    weight_enabled: bool
    prep_enabled: bool


class MenuCategorySettingUpdate(BaseModel):
    category: Category
    weight_enabled: Optional[bool] = None
    prep_enabled: Optional[bool] = None


class MenuItemIn(BaseModel):
    category: Category
    name: str
    price: float
    description: Optional[str] = None
    image_url: Optional[str] = None
    weight_kg: Optional[float] = None
    variants: Optional[list[dict]] = None
    prep_time_minutes: Optional[int] = None


class MenuItemUpdate(BaseModel):
    category: Optional[Category] = None
    name: Optional[str] = None
    price: Optional[float] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    weight_kg: Optional[float] = None
    variants: Optional[list[dict]] = None
    prep_time_minutes: Optional[int] = None
    is_active: Optional[bool] = None


def _normalize_menu_variants(raw: Optional[list[dict]]) -> Optional[list[dict]]:
    if raw is None:
        return None
    variants = []
    for index, row in enumerate(raw, start=1):
        label = str(row.get("label") or "").strip()
        try:
            price = float(row.get("price"))
            weight_kg = float(row.get("weight_kg"))
        except (TypeError, ValueError):
            raise HTTPException(400, f"Variant {index} needs a valid price and weight.")
        if price < 0:
            raise HTTPException(400, f"Variant {index} price must be zero or more.")
        if weight_kg <= 0:
            raise HTTPException(400, f"Variant {index} weight must be greater than zero.")
        if not label:
            grams = round(weight_kg * 1000)
            label = f"{grams} g" if weight_kg < 1 else f"{weight_kg:g} kg"
        variants.append(
            {
                "label": label,
                "price": round(price, 2),
                "weight_kg": round(weight_kg, 3),
            }
        )
    return variants or None


def _default_variant_label(weight_kg: float) -> str:
    grams = round(weight_kg * 1000)
    return f"{grams} g" if weight_kg < 1 else f"{weight_kg:g} kg"


def _menu_item_variants(item: MenuItem) -> Optional[list[dict]]:
    if item.variants:
        return item.variants
    if item.weight_kg is None:
        return None
    weight_kg = float(item.weight_kg)
    return [
        {
            "label": _default_variant_label(weight_kg),
            "price": round(float(item.price), 2),
            "weight_kg": round(weight_kg, 3),
        }
    ]


def _menu_item_out(item: MenuItem) -> MenuItemOut:
    return MenuItemOut(
        id=item.id,
        category=item.category,
        name=item.name,
        price=float(item.price),
        description=item.description,
        image_url=item.image_url,
        weight_kg=float(item.weight_kg) if item.weight_kg is not None else None,
        variants=_menu_item_variants(item),
        prep_time_minutes=item.prep_time_minutes,
        is_active=item.is_active,
    )


def _menu_category_setting_out(
    category: str, setting: Optional[MenuCategorySetting] = None
) -> MenuCategorySettingOut:
    defaults = DEFAULT_CATEGORY_FIELD_SETTINGS[category]
    return MenuCategorySettingOut(
        category=category,
        weight_enabled=(
            setting.weight_enabled if setting is not None else defaults["weight_enabled"]
        ),
        prep_enabled=(
            setting.prep_enabled if setting is not None else defaults["prep_enabled"]
        ),
    )


@app.get("/admin/menu-category-settings", response_model=list[MenuCategorySettingOut])
def admin_list_menu_category_settings(
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[MenuCategorySettingOut]:
    rows = {
        row.category: row
        for row in db.query(MenuCategorySetting)
        .filter(MenuCategorySetting.category.in_(CATEGORIES))
        .all()
    }
    return [_menu_category_setting_out(category, rows.get(category)) for category in CATEGORIES]


@app.patch("/admin/menu-category-settings", response_model=MenuCategorySettingOut)
def admin_update_menu_category_setting(
    body: MenuCategorySettingUpdate,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> MenuCategorySettingOut:
    setting = (
        db.query(MenuCategorySetting)
        .filter(MenuCategorySetting.category == body.category)
        .first()
    )
    if setting is None:
        defaults = DEFAULT_CATEGORY_FIELD_SETTINGS[body.category]
        setting = MenuCategorySetting(
            category=body.category,
            weight_enabled=defaults["weight_enabled"],
            prep_enabled=defaults["prep_enabled"],
        )
        db.add(setting)
    if body.weight_enabled is not None:
        setting.weight_enabled = body.weight_enabled
    if body.prep_enabled is not None:
        setting.prep_enabled = body.prep_enabled
    db.commit()
    db.refresh(setting)
    return _menu_category_setting_out(body.category, setting)


@app.post("/admin/upload")
def admin_upload(
    file: UploadFile = File(...),
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> dict:
    ext = ALLOWED_IMAGE_EXT.get(file.content_type)
    suffix = Path(file.filename or "").suffix.lower()
    if not ext or suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(400, "Only JPEG, PNG or WebP image files are allowed.")
    data = file.file.read(MAX_IMAGE_BYTES + 1)
    if len(data) > MAX_IMAGE_BYTES:
        raise HTTPException(400, "Image too large (max 5 MB).")
    # Persist the bytes in the DB rather than on disk: Railway's filesystem is
    # ephemeral, so a /media/<file> URL would 404 after the next deploy. The
    # returned /uploaded-images/<id> URL is served from the row below and
    # survives restarts, matching how seeded items embed their image bytes.
    img = UploadedImage(data=data, mime=file.content_type)
    db.add(img)
    db.commit()
    db.refresh(img)
    return {"url": f"/uploaded-images/{img.id}"}


# Public: serve admin-uploaded image bytes from the DB (see UploadedImage).
@app.get("/uploaded-images/{image_id}")
def uploaded_image(image_id: int, db: Session = Depends(get_db)) -> Response:
    img = db.query(UploadedImage).filter(UploadedImage.id == image_id).first()
    if not img:
        raise HTTPException(404, "Image not found.")
    return Response(
        content=bytes(img.data),
        media_type=img.mime or "application/octet-stream",
        # URL is id-keyed and bytes are immutable, so cache hard for a week.
        headers={"Cache-Control": "public, max-age=604800"},
    )


# Public image-from-DB endpoint. Items seeded (or uploaded) with image_data
# set point their image_url at /menu-items/{id}/image, so the existing
# `<img src={image_url}>` UI continues to work unchanged.
@app.get("/menu-items/{item_id}/image")
def menu_item_image(item_id: int, db: Session = Depends(get_db)) -> Response:
    item = db.query(MenuItem).filter(MenuItem.id == item_id).first()
    if not item or not item.image_data:
        raise HTTPException(404, "Image not found.")
    return Response(
        content=bytes(item.image_data),
        media_type=item.image_mime or "application/octet-stream",
        # Browser-cached for a week; the URL is id-keyed, so updates need a
        # new id (or a cache buster) — fine for seeded content.
        headers={"Cache-Control": "public, max-age=604800"},
    )


@app.get("/admin/menu-items", response_model=list[MenuItemOut])
def admin_list_menu_items(
    category: Optional[Category] = None,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[MenuItemOut]:
    q = db.query(MenuItem)
    if category:
        q = q.filter(MenuItem.category == category)
    return [_menu_item_out(item) for item in q.order_by(MenuItem.category, MenuItem.name).all()]


@app.post("/admin/menu-items", response_model=MenuItemOut, status_code=201)
def admin_create_menu_item(
    body: MenuItemIn,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> MenuItemOut:
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Name is required.")
    if body.price < 0:
        raise HTTPException(400, "Price must be zero or more.")
    variants = _normalize_menu_variants(body.variants)
    price = variants[0]["price"] if variants else body.price
    weight_kg = variants[0]["weight_kg"] if variants else body.weight_kg
    item = MenuItem(
        category=body.category,
        name=name,
        price=price,
        description=(body.description or "").strip() or None,
        image_url=body.image_url or None,
        weight_kg=weight_kg,
        variants=variants,
        prep_time_minutes=body.prep_time_minutes,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return _menu_item_out(item)


@app.patch("/admin/menu-items/{item_id}", response_model=MenuItemOut)
def admin_update_menu_item(
    item_id: int,
    body: MenuItemUpdate,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> MenuItemOut:
    item = db.query(MenuItem).filter(MenuItem.id == item_id).first()
    if not item:
        raise HTTPException(404, "Item not found.")
    if body.category is not None:
        item.category = body.category
    if body.name is not None:
        name = body.name.strip()
        if not name:
            raise HTTPException(400, "Name cannot be empty.")
        item.name = name
    if body.price is not None:
        if body.price < 0:
            raise HTTPException(400, "Price must be zero or more.")
        item.price = body.price
    if "variants" in body.model_fields_set:
        variants = _normalize_menu_variants(body.variants)
        item.variants = variants
        if variants:
            item.price = variants[0]["price"]
            item.weight_kg = variants[0]["weight_kg"]
    if body.description is not None:
        item.description = body.description.strip() or None
    if body.image_url is not None:
        item.image_url = body.image_url or None
    if "weight_kg" in body.model_fields_set:
        # Pydantic gives us 0 explicitly if the admin clears the field; persist
        # null if the value is exactly 0 so the rollup shows it as "no weight".
        item.weight_kg = body.weight_kg if body.weight_kg and body.weight_kg > 0 else None
    if "prep_time_minutes" in body.model_fields_set:
        # 0 clears it (treated as "no prep time" → contributes 0 to dining time).
        item.prep_time_minutes = (
            body.prep_time_minutes
            if body.prep_time_minutes and body.prep_time_minutes > 0
            else None
        )
    if body.is_active is not None:
        item.is_active = body.is_active
    db.commit()
    db.refresh(item)
    return _menu_item_out(item)


@app.delete("/admin/menu-items/{item_id}", status_code=204)
def admin_delete_menu_item(
    item_id: int,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> Response:
    item = db.query(MenuItem).filter(MenuItem.id == item_id).first()
    if not item:
        raise HTTPException(404, "Item not found.")
    # Distributor / kiosk selections of this master are just picks — drop them
    # so they don't dangle. Existing order_items snapshot name/price/weight, so
    # historical orders stay correct and are intentionally left untouched.
    db.query(DistributorMenuItem).filter(
        DistributorMenuItem.master_item_id == item_id
    ).delete(synchronize_session=False)
    db.query(KioskMenuItem).filter(
        KioskMenuItem.master_item_id == item_id
    ).delete(synchronize_session=False)
    db.delete(item)
    db.commit()
    return Response(status_code=204)


class CouponIn(BaseModel):
    code: str
    coupon_type: str  # welcome | one_time | regular
    discount_type: str  # percentage | flat
    discount_value: float
    max_discount: Optional[float] = None
    min_bill_amount: Optional[float] = None
    applicable_categories: Optional[list[str]] = None
    applicable_products: Optional[list[int]] = None
    start_date: date
    end_date: date
    is_active: Optional[bool] = True


class CouponOut(BaseModel):
    id: int
    code: str
    coupon_type: str
    discount_type: str
    discount_value: float
    max_discount: Optional[float] = None
    min_bill_amount: Optional[float] = None
    applicable_categories: Optional[list[str]] = None
    applicable_products: Optional[list[int]] = None
    start_date: date
    end_date: date
    kiosk_user_id: Optional[int] = None
    is_active: bool
    created_at: datetime


# ============ Admin: coupons ============
@app.get("/admin/coupons", response_model=list[CouponOut])
def list_admin_coupons(
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[CouponOut]:
    coupons = db.query(Coupon).order_by(Coupon.id.desc()).all()
    return coupons


@app.post("/admin/coupons", response_model=CouponOut, status_code=201)
def create_admin_coupon(
    body: CouponIn,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> CouponOut:
    existing = db.query(Coupon).filter(Coupon.code == body.code.upper()).first()
    if existing:
        raise HTTPException(400, "Coupon code already exists.")
    coupon = Coupon(
        code=body.code.upper(),
        coupon_type=body.coupon_type,
        discount_type=body.discount_type,
        discount_value=body.discount_value,
        max_discount=body.max_discount,
        min_bill_amount=body.min_bill_amount,
        applicable_categories=body.applicable_categories,
        applicable_products=body.applicable_products,
        start_date=body.start_date,
        end_date=body.end_date,
        kiosk_user_id=None,
        is_active=body.is_active if body.is_active is not None else True,
    )
    db.add(coupon)
    db.commit()
    db.refresh(coupon)
    return coupon


@app.patch("/admin/coupons/{coupon_id}", response_model=CouponOut)
def update_admin_coupon(
    coupon_id: int,
    body: CouponIn,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> CouponOut:
    coupon = db.query(Coupon).filter(Coupon.id == coupon_id).first()
    if not coupon:
        raise HTTPException(404, "Coupon not found.")
    
    if body.code.upper() != coupon.code:
        existing = db.query(Coupon).filter(Coupon.code == body.code.upper()).first()
        if existing:
            raise HTTPException(400, "Coupon code already exists.")
            
    coupon.code = body.code.upper()
    coupon.coupon_type = body.coupon_type
    coupon.discount_type = body.discount_type
    coupon.discount_value = body.discount_value
    coupon.max_discount = body.max_discount
    coupon.min_bill_amount = body.min_bill_amount
    coupon.applicable_categories = body.applicable_categories
    coupon.applicable_products = body.applicable_products
    coupon.start_date = body.start_date
    coupon.end_date = body.end_date
    if body.is_active is not None:
        coupon.is_active = body.is_active
    db.commit()
    db.refresh(coupon)
    return coupon


@app.delete("/admin/coupons/{coupon_id}", status_code=204)
def delete_admin_coupon(
    coupon_id: int,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> None:
    coupon = db.query(Coupon).filter(Coupon.id == coupon_id).first()
    if not coupon:
        raise HTTPException(404, "Coupon not found.")
    db.delete(coupon)
    db.commit()


# ============ Distributor: shop ============
ShopStatus = Literal["active", "inactive"]
OperationStatus = Literal["open", "closed"]


def _valid_hhmm(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    if not TIME_RE.match(value):
        raise HTTPException(400, "Time must be in HH:MM format.")
    hh, mm = [int(part) for part in value.split(":")]
    if hh > 23 or mm > 59:
        raise HTTPException(400, "Time must be a valid 24-hour clock time.")
    return value


def _minutes(value: str) -> int:
    hh, mm = [int(part) for part in value.split(":")]
    return hh * 60 + mm


def _normalize_open_days(raw: Optional[list[int]]) -> list[int]:
    if raw is None:
        return list(range(7))
    days: list[int] = []
    for value in raw:
        try:
            day = int(value)
        except (TypeError, ValueError):
            raise HTTPException(400, "Open days must be numbers from 0 to 6.")
        if day < 0 or day > 6:
            raise HTTPException(400, "Open days must be numbers from 0 to 6.")
        if day not in days:
            days.append(day)
    if not days:
        raise HTTPException(400, "Select at least one open day.")
    return sorted(days)


def _kiosk_open_days(k: Kiosk) -> list[int]:
    if isinstance(k.open_days, list) and k.open_days:
        return _normalize_open_days(k.open_days)
    return list(range(7))


def _kiosk_days_label(k: Kiosk) -> str:
    days = _kiosk_open_days(k)
    if len(days) == 7:
        return "All week"
    names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    return ", ".join(names[d] for d in days)


def _kiosk_in_hours(k: Kiosk, now_utc: Optional[datetime] = None) -> bool:
    now = (now_utc or datetime.now(timezone.utc)).astimezone(_IST)
    if now.weekday() not in _kiosk_open_days(k):
        return False
    if k.open_24h:
        return True
    if not k.opening_time or not k.closing_time:
        return False
    start = _minutes(k.opening_time)
    end = _minutes(k.closing_time)
    current = now.hour * 60 + now.minute
    if start == end:
        return False
    if start < end:
        return start <= current < end
    return current >= start or current < end


def _effective_kiosk_operation_status(k: Kiosk) -> str:
    if k.shop_status != "active" or k.operation_status != "open":
        return "closed"
    return "open" if _kiosk_in_hours(k) else "closed"


def _kiosk_hours_label(k: Kiosk) -> str:
    days_label = _kiosk_days_label(k)
    if k.open_24h:
        return f"Open 24 hours ({days_label})"
    if k.opening_time and k.closing_time:
        return f"{k.opening_time}-{k.closing_time} ({days_label})"
    return "Hours not set"


def distributor_required(user: User = Depends(current_user)) -> User:
    if user.role != "distributor":
        raise HTTPException(403, "Distributor access required.")
    return user


class ShopOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    location: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius: Optional[float] = None
    shop_status: str
    operation_status: str


class ShopIn(BaseModel):
    name: str
    location: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius: Optional[float] = None


class ShopUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius: Optional[float] = None
    operation_status: Optional[OperationStatus] = None


@app.get("/distributor/shop", response_model=Optional[ShopOut])
def get_my_shop(
    user: User = Depends(distributor_required),
    db: Session = Depends(get_db),
) -> Optional[Shop]:
    return db.query(Shop).filter(Shop.user_id == user.id).first()


@app.put("/distributor/shop", response_model=ShopOut)
def upsert_my_shop(
    body: ShopIn,
    user: User = Depends(distributor_required),
    db: Session = Depends(get_db),
) -> Shop:
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Shop name is required.")
    shop = db.query(Shop).filter(Shop.user_id == user.id).first()
    if shop is None:
        shop = Shop(user_id=user.id)
        db.add(shop)
    shop.name = name
    shop.location = (body.location or "").strip() or None
    shop.address = (body.address or "").strip() or None
    shop.lat = body.lat
    shop.lon = body.lon
    shop.radius = body.radius
    # Creating or editing shop details requires admin (re-)approval, so the
    # shop drops to inactive + closed until an admin activates it.
    shop.shop_status = "inactive"
    shop.operation_status = "closed"
    db.commit()
    db.refresh(shop)
    return shop


@app.patch("/distributor/shop", response_model=ShopOut)
def patch_my_shop(
    body: ShopUpdate,
    user: User = Depends(distributor_required),
    db: Session = Depends(get_db),
) -> Shop:
    shop = db.query(Shop).filter(Shop.user_id == user.id).first()
    if shop is None:
        raise HTTPException(404, "Set up your shop first.")
    data = body.model_dump(exclude_unset=True)
    if "name" in data:
        name = (data.pop("name") or "").strip()
        if not name:
            raise HTTPException(400, "Shop name cannot be empty.")
        shop.name = name
    if "operation_status" in data:
        op = data.pop("operation_status")
        # Can only be "open" while the shop is active.
        shop.operation_status = op if shop.shop_status == "active" else "closed"
    if "address" in data:
        shop.address = (data.pop("address") or "").strip() or None
    for field, value in data.items():
        setattr(shop, field, value)
    db.commit()
    db.refresh(shop)
    return shop


# ============ Distributor: menu (inherited from master, with overrides) ============
# Distributors only sell from the fish categories; accessories and fish & chips
# are admin-only and never appear in the distributor menu.
DISTRIBUTOR_CATEGORIES = ("fresh_fish", "frozen_fish")


class DistributorMenuRow(BaseModel):
    """One row per active master item, merged with this distributor's price
    and availability override. Defaults to the master price and 'available'
    when no override row exists yet."""
    master_id: int
    name: str
    category: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    master_price: float
    price: float
    is_available: bool


class DistributorMenuUpdate(BaseModel):
    price: Optional[float] = None
    is_available: Optional[bool] = None


def _row_from(master: MenuItem, override: Optional[DistributorMenuItem]) -> DistributorMenuRow:
    return DistributorMenuRow(
        master_id=master.id,
        name=master.name,
        category=master.category,
        description=master.description,
        image_url=master.image_url,
        master_price=float(master.price),
        price=float(override.price) if override is not None else float(master.price),
        is_available=override.is_available if override is not None else True,
    )


@app.get("/distributor/menu-items", response_model=list[DistributorMenuRow])
def list_my_menu(
    user: User = Depends(distributor_required),
    db: Session = Depends(get_db),
) -> list[DistributorMenuRow]:
    masters = (
        db.query(MenuItem)
        .filter(
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category.in_(DISTRIBUTOR_CATEGORIES),
        )
        .order_by(MenuItem.category, MenuItem.name)
        .all()
    )
    mine = {
        di.master_item_id: di
        for di in db.query(DistributorMenuItem)
        .filter(DistributorMenuItem.user_id == user.id)
        .all()
    }
    return [_row_from(m, mine.get(m.id)) for m in masters]


@app.patch("/distributor/menu-items/{master_item_id}", response_model=DistributorMenuRow)
def upsert_my_menu_item(
    master_item_id: int,
    body: DistributorMenuUpdate,
    user: User = Depends(distributor_required),
    db: Session = Depends(get_db),
) -> DistributorMenuRow:
    master = (
        db.query(MenuItem)
        .filter(
            MenuItem.id == master_item_id,
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category.in_(DISTRIBUTOR_CATEGORIES),
        )
        .first()
    )
    if not master:
        raise HTTPException(404, "Master menu item not found or inactive.")
    item = (
        db.query(DistributorMenuItem)
        .filter(
            DistributorMenuItem.user_id == user.id,
            DistributorMenuItem.master_item_id == master_item_id,
        )
        .first()
    )
    if item is None:
        # First override for this item — seed with the master price + available.
        item = DistributorMenuItem(
            user_id=user.id,
            master_item_id=master_item_id,
            price=master.price,
            is_available=True,
        )
        db.add(item)
    if body.price is not None:
        if body.price < 0:
            raise HTTPException(400, "Price must be zero or more.")
        item.price = body.price
    if body.is_available is not None:
        item.is_available = body.is_available
    db.commit()
    db.refresh(item)
    return _row_from(master, item)


# ============ Customer: profile + geofenced menu ============
def customer_required(user: User = Depends(current_user)) -> User:
    if user.role != "customer":
        raise HTTPException(403, "Customer access required.")
    return user


class CustomerProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    phone: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


class CustomerProfileUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


class CustomerMenuShop(BaseModel):
    id: int
    name: str
    location: Optional[str] = None
    distance_km: float
    # "open" | "closed" — the customer can browse either way, but the UI
    # surfaces a "currently closed" banner when this is "closed".
    operation_status: str
    open_24h: Optional[bool] = None
    opening_time: Optional[str] = None
    closing_time: Optional[str] = None
    open_days: Optional[list[int]] = None
    hours_label: Optional[str] = None


class CustomerMenuItem(BaseModel):
    master_id: int
    name: str
    category: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    price: float
    # Typical weight per unit, kg. Surfaced so the mobile app can show
    # "500 g" next to the price for fish items.
    weight_kg: Optional[float] = None
    variants: Optional[list[dict]] = None
    # Prep time in minutes — kiosk (fish_and_chips) items. The kiosk cart uses
    # the max across ordered items to compute the dining time (now + max).
    prep_time_minutes: Optional[int] = None


class CustomerMenuResponse(BaseModel):
    serving: bool
    shop: Optional[CustomerMenuShop] = None
    items: list[CustomerMenuItem] = []


# Delivery is rostered by IST day: orders placed before 12 PM IST go out
# tomorrow; anything after the cutoff slips to day-after-tomorrow.
_IST = ZoneInfo("Asia/Kolkata")
_DELIVERY_CUTOFF_HOUR_IST = 12


def _utc_aware(dt: datetime) -> datetime:
    """Tag a naive datetime as UTC.

    Order.created_at is stored as a naive UTC value (Column(DateTime, ...)
    without timezone=True). Without a tz marker, Pydantic serializes it as
    "2026-05-30T06:00:00" — which JS's `new Date()` parses as the viewer's
    LOCAL time rather than UTC. That meant the IST formatter on the admin
    site got the wrong instant. Stamping UTC here makes the JSON correct.
    """
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _compute_delivery_date(now_utc: Optional[datetime] = None) -> date:
    """Cutoff-aware delivery date based on the current IST wall-clock time."""
    now = (now_utc or datetime.now(timezone.utc)).astimezone(_IST)
    days = 1 if now.hour < _DELIVERY_CUTOFF_HOUR_IST else 2
    return now.date() + timedelta(days=days)


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    r = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


@app.get("/customer/me", response_model=CustomerProfileOut)
def customer_me(user: User = Depends(customer_required)) -> User:
    return user


@app.put("/customer/profile", response_model=CustomerProfileOut)
def update_customer_profile(
    body: CustomerProfileUpdate,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> User:
    if body.first_name is not None:
        user.first_name = body.first_name.strip() or None
    if body.last_name is not None:
        user.last_name = body.last_name.strip() or None
    if body.address is not None:
        user.address = body.address.strip() or None
    if body.lat is not None:
        user.lat = body.lat
    if body.lon is not None:
        user.lon = body.lon
    db.commit()
    db.refresh(user)
    return user


@app.get("/customer/menu", response_model=CustomerMenuResponse)
def customer_menu(
    lat: float,
    lon: float,
    user: User = Depends(customer_required),  # noqa: ARG001
    db: Session = Depends(get_db),
) -> CustomerMenuResponse:
    # Any admin-approved shop with a pinned location and a service radius.
    # We deliberately don't filter on operation_status here — customers can
    # browse the menu of a covering shop even when it's currently closed;
    # the UI shows a "closed" banner using shop.operation_status.
    shops = (
        db.query(Shop)
        .filter(
            Shop.shop_status == "active",
            Shop.lat.is_not(None),
            Shop.lon.is_not(None),
            Shop.radius.is_not(None),
        )
        .all()
    )
    candidates: list[tuple[float, Shop]] = []
    for s in shops:
        d = _haversine_km(lat, lon, float(s.lat), float(s.lon))
        if d <= float(s.radius):
            candidates.append((d, s))
    if not candidates:
        return CustomerMenuResponse(serving=False)

    # Pick the closest serving shop.
    candidates.sort(key=lambda x: x[0])
    distance, shop = candidates[0]

    masters = (
        db.query(MenuItem)
        .filter(
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category.in_(DISTRIBUTOR_CATEGORIES),
        )
        .order_by(MenuItem.category, MenuItem.name)
        .all()
    )
    overrides = {
        di.master_item_id: di
        for di in db.query(DistributorMenuItem)
        .filter(DistributorMenuItem.user_id == shop.user_id)
        .all()
    }
    items: list[CustomerMenuItem] = []
    for m in masters:
        di = overrides.get(m.id)
        is_avail = di.is_available if di is not None else True
        if not is_avail:
            continue
        price = float(di.price) if di is not None else float(m.price)
        items.append(
            CustomerMenuItem(
                master_id=m.id,
                name=m.name,
                category=m.category,
                description=m.description,
                image_url=m.image_url,
                price=price,
                weight_kg=(
                    float(m.weight_kg) if m.weight_kg is not None else None
                ),
                variants=_menu_item_variants(m),
            )
        )

    return CustomerMenuResponse(
        serving=True,
        shop=CustomerMenuShop(
            id=shop.id,
            name=shop.name,
            location=shop.location,
            distance_km=round(distance, 2),
            operation_status=shop.operation_status,
        ),
        items=items,
    )


# ============ Customer: storefront (fish delivery / kiosk dine-in / accessories) ============
# Independent sections, each with its own cart on the client:
#   • fish        — closest covering DISTRIBUTOR (delivery), fresh + frozen
#   • dry_fish    — ALWAYS available; shipped by central admin, no serviceability.
#                   Shown under the Fish section on the client, but its own cart.
#   • kiosk       — closest covering KIOSK (dine-in pre-order), fish & chips
#   • accessories — ALWAYS available; shipped by central admin, no serviceability
class StorefrontSection(BaseModel):
    # A covering vendor exists for this location. Always True for accessories /
    # dry fish (central admin ships anywhere).
    serving: bool
    # The covering distributor (fish) or kiosk (kiosk). None for shipped sections.
    shop: Optional[CustomerMenuShop] = None
    items: list[CustomerMenuItem] = []


class StorefrontResponse(BaseModel):
    fish: StorefrontSection
    # Always-available dried/salted fish, shipped by central admin. Surfaced as a
    # sub-tab under Fish on the client, but checked out through its own cart.
    dry_fish: StorefrontSection
    kiosk: StorefrontSection
    accessories: StorefrontSection
    # Always-available pickles, shipped by central admin — its own top-level
    # section sitting next to accessories, with its own cart.
    pickles: StorefrontSection


def _store_item(m: MenuItem, price: float) -> CustomerMenuItem:
    return CustomerMenuItem(
        master_id=m.id,
        name=m.name,
        category=m.category,
        description=m.description,
        image_url=m.image_url,
        price=price,
        weight_kg=float(m.weight_kg) if m.weight_kg is not None else None,
        variants=_menu_item_variants(m),
        prep_time_minutes=m.prep_time_minutes,
    )


def _closest_covering_shop(
    lat: float, lon: float, db: Session
) -> Optional[tuple[float, Shop]]:
    shops = (
        db.query(Shop)
        .filter(
            Shop.shop_status == "active",
            Shop.lat.is_not(None),
            Shop.lon.is_not(None),
            Shop.radius.is_not(None),
        )
        .all()
    )
    best: Optional[tuple[float, Shop]] = None
    for s in shops:
        d = _haversine_km(lat, lon, float(s.lat), float(s.lon))
        if d <= float(s.radius) and (best is None or d < best[0]):
            best = (d, s)
    return best


def _closest_covering_kiosk(
    lat: float, lon: float, db: Session
) -> Optional[tuple[float, Kiosk]]:
    kiosks = (
        db.query(Kiosk)
        .filter(
            Kiosk.shop_status == "active",
            Kiosk.lat.is_not(None),
            Kiosk.lon.is_not(None),
            Kiosk.radius.is_not(None),
        )
        .all()
    )
    best: Optional[tuple[float, Kiosk]] = None
    for k in kiosks:
        d = _haversine_km(lat, lon, float(k.lat), float(k.lon))
        if d <= float(k.radius) and (best is None or d < best[0]):
            best = (d, k)
    return best


@app.get("/customer/storefront", response_model=StorefrontResponse)
def customer_storefront(
    lat: float,
    lon: float,
    user: User = Depends(customer_required),  # noqa: ARG001
    db: Session = Depends(get_db),
) -> StorefrontResponse:
    # --- Fish: closest covering distributor (delivery) ---
    fish = StorefrontSection(serving=False)
    shop_hit = _closest_covering_shop(lat, lon, db)
    if shop_hit is not None:
        dist, shop = shop_hit
        overrides = {
            di.master_item_id: di
            for di in db.query(DistributorMenuItem)
            .filter(DistributorMenuItem.user_id == shop.user_id)
            .all()
        }
        masters = (
            db.query(MenuItem)
            .filter(
                MenuItem.is_active == True,  # noqa: E712
                MenuItem.category.in_(DISTRIBUTOR_CATEGORIES),
            )
            .order_by(MenuItem.category, MenuItem.name)
            .all()
        )
        items: list[CustomerMenuItem] = []
        for m in masters:
            di = overrides.get(m.id)
            if di is not None and not di.is_available:
                continue
            price = float(di.price) if di is not None else float(m.price)
            items.append(_store_item(m, price))
        fish = StorefrontSection(
            serving=True,
            shop=CustomerMenuShop(
                id=shop.id,
                name=shop.name,
                location=shop.location,
                distance_km=round(dist, 2),
                operation_status=shop.operation_status,
            ),
            items=items,
        )

    # --- Kiosk: closest covering kiosk (dine-in pre-order) ---
    kiosk = StorefrontSection(serving=False)
    kiosk_hit = _closest_covering_kiosk(lat, lon, db)
    if kiosk_hit is not None:
        dist, k = kiosk_hit
        koverrides = {
            ki.master_item_id: ki
            for ki in db.query(KioskMenuItem)
            .filter(KioskMenuItem.user_id == k.user_id)
            .all()
        }
        kmasters = (
            db.query(MenuItem)
            .filter(
                MenuItem.is_active == True,  # noqa: E712
                MenuItem.category.in_(KIOSK_CATEGORIES),
            )
            .order_by(MenuItem.name)
            .all()
        )
        kitems: list[CustomerMenuItem] = []
        for m in kmasters:
            ki = koverrides.get(m.id)
            if ki is not None and not ki.is_available:
                continue
            price = float(ki.price) if ki is not None else float(m.price)
            kitems.append(_store_item(m, price))
        kiosk = StorefrontSection(
            serving=True,
            shop=CustomerMenuShop(
                id=k.id,
                name=k.name,
                location=k.location,
                distance_km=round(dist, 2),
                operation_status=_effective_kiosk_operation_status(k),
                open_24h=k.open_24h,
                opening_time=k.opening_time,
                closing_time=k.closing_time,
                open_days=_kiosk_open_days(k),
                hours_label=_kiosk_hours_label(k),
            ),
            items=kitems,
        )

    # --- Dry fish: always available, shipped by central admin (own cart) ---
    dry_masters = (
        db.query(MenuItem)
        .filter(
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category == "dry_fish",
        )
        .order_by(MenuItem.name)
        .all()
    )
    dry_fish = StorefrontSection(
        serving=True,
        items=[_store_item(m, float(m.price)) for m in dry_masters],
    )

    # --- Accessories: always available, shipped by central admin ---
    acc_masters = (
        db.query(MenuItem)
        .filter(
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category == "accessories",
        )
        .order_by(MenuItem.name)
        .all()
    )
    accessories = StorefrontSection(
        serving=True,
        items=[_store_item(m, float(m.price)) for m in acc_masters],
    )

    # --- Pickles: always available, shipped by central admin (own cart) ---
    pickle_masters = (
        db.query(MenuItem)
        .filter(
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category == "pickles",
        )
        .order_by(MenuItem.name)
        .all()
    )
    pickles = StorefrontSection(
        serving=True,
        items=[_store_item(m, float(m.price)) for m in pickle_masters],
    )

    return StorefrontResponse(
        fish=fish,
        dry_fish=dry_fish,
        kiosk=kiosk,
        accessories=accessories,
        pickles=pickles,
    )


# ============ Customer: saved delivery addresses ============
class AddressOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    label: Optional[str] = None
    address: str
    lat: float
    lon: float
    is_default: bool


class AddressIn(BaseModel):
    label: Optional[str] = None
    address: str
    lat: float
    lon: float
    set_default: bool = False


def _address_dto(a: Address) -> AddressOut:
    return AddressOut(
        id=a.id,
        label=a.label,
        address=a.address,
        lat=float(a.lat),
        lon=float(a.lon),
        is_default=a.is_default,
    )


@app.get("/customer/addresses", response_model=list[AddressOut])
def list_addresses(
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> list[AddressOut]:
    rows = (
        db.query(Address)
        .filter(Address.user_id == user.id)
        # Default first, then most recently created — matches what the UI wants.
        .order_by(Address.is_default.desc(), Address.created_at.desc())
        .all()
    )
    return [_address_dto(a) for a in rows]


@app.post("/customer/addresses", response_model=AddressOut, status_code=201)
def create_address(
    body: AddressIn,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> AddressOut:
    text = body.address.strip()
    if not text:
        raise HTTPException(400, "Address is required.")
    # First address is default by definition; later additions need set_default.
    has_any = (
        db.query(Address.id).filter(Address.user_id == user.id).first() is not None
    )
    make_default = body.set_default or not has_any
    if make_default:
        db.query(Address).filter(Address.user_id == user.id).update(
            {Address.is_default: False}, synchronize_session=False
        )
    a = Address(
        user_id=user.id,
        label=(body.label or "").strip() or None,
        address=text,
        lat=body.lat,
        lon=body.lon,
        is_default=make_default,
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    return _address_dto(a)


@app.patch("/customer/addresses/{address_id}/default", response_model=AddressOut)
def set_default_address(
    address_id: int,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> AddressOut:
    a = (
        db.query(Address)
        .filter(Address.id == address_id, Address.user_id == user.id)
        .first()
    )
    if not a:
        raise HTTPException(404, "Address not found.")
    db.query(Address).filter(Address.user_id == user.id).update(
        {Address.is_default: False}, synchronize_session=False
    )
    a.is_default = True
    db.commit()
    db.refresh(a)
    return _address_dto(a)


@app.delete("/customer/addresses/{address_id}", status_code=204)
def delete_address(
    address_id: int,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> Response:
    a = (
        db.query(Address)
        .filter(Address.id == address_id, Address.user_id == user.id)
        .first()
    )
    if not a:
        raise HTTPException(404, "Address not found.")
    was_default = a.is_default
    db.delete(a)
    db.flush()
    # Promote the next-newest address to default if we just removed the default.
    if was_default:
        nxt = (
            db.query(Address)
            .filter(Address.user_id == user.id)
            .order_by(Address.created_at.desc())
            .first()
        )
        if nxt:
            nxt.is_default = True
    db.commit()
    return Response(status_code=204)


# ============ Customer: distributor serviceability ============
# Which of the customer's saved addresses a specific distributor delivers to.
# The cart uses this to show the distributor it's ordering from and to enable
# only the addresses that distributor can serve (the rest stay disabled), so a
# delivery to an out-of-range address is caught before checkout.
class AddressServiceability(BaseModel):
    address_id: int
    serves: bool


class ServiceabilityOut(BaseModel):
    shop_id: int
    shop_name: str
    addresses: list[AddressServiceability]


@app.get("/customer/distributor-serviceability", response_model=ServiceabilityOut)
def distributor_serviceability(
    shop_id: int,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> ServiceabilityOut:
    shop = (
        db.query(Shop)
        .filter(Shop.id == shop_id, Shop.shop_status == "active")
        .first()
    )
    if not shop:
        raise HTTPException(404, "Distributor not found.")
    addrs = db.query(Address).filter(Address.user_id == user.id).all()
    has_coverage = (
        shop.lat is not None and shop.lon is not None and shop.radius is not None
    )
    results: list[AddressServiceability] = []
    for a in addrs:
        serves = False
        if has_coverage and a.lat is not None and a.lon is not None:
            d = _haversine_km(
                float(a.lat), float(a.lon), float(shop.lat), float(shop.lon)
            )
            serves = d <= float(shop.radius)
        results.append(AddressServiceability(address_id=a.id, serves=serves))
    return ServiceabilityOut(
        shop_id=shop.id, shop_name=shop.name, addresses=results
    )


# ============ Customer: orders ============
class OrderItemIn(BaseModel):
    master_item_id: int
    quantity: int
    variant_label: Optional[str] = None


class OrderIn(BaseModel):
    # Saved delivery address (fish delivery, and the legacy accessories path).
    # Optional because accessories can ship to a typed postal address instead.
    address_id: int | None = None
    items: list[OrderItemIn]
    # The distributor the customer actually shopped from. When set, checkout
    # locks to this shop and only verifies it serves the address — it never
    # reassigns the cart to a different (closer) distributor. Optional for
    # backward compatibility with older clients.
    shop_id: int | None = None
    # Accessories only: ship to a free-text postal address with client-provided
    # coordinates, instead of a saved delivery address. Ignored by fish checkout.
    postal_address: str | None = None
    lat: float | None = None
    lon: float | None = None
    coupon_code: Optional[str] = None


def _selected_variant(
    item: MenuItem, variant_label: Optional[str]
) -> tuple[str, float, Optional[float]]:
    variants = _menu_item_variants(item) or []
    if not variants:
        return item.name, float(item.price), (
            float(item.weight_kg) if item.weight_kg is not None else None
        )
    label = (variant_label or variants[0].get("label") or "").strip()
    for row in variants:
        row_label = str(row.get("label") or "").strip()
        if row_label == label:
            price = float(row.get("price"))
            weight_kg = row.get("weight_kg")
            name = f"{item.name} - {row_label}" if row_label else item.name
            return name, price, float(weight_kg) if weight_kg is not None else None
    raise HTTPException(400, f'"{item.name}" variant is not available.')


class OrderItemOut(BaseModel):
    master_item_id: int
    name: str
    price: float
    quantity: int
    line_total: float
    # Snapshotted at order time; null for items with no recorded weight.
    weight_kg: Optional[float] = None
    # The master item's category (fresh_fish | frozen_fish | fish_and_chips |
    # accessories). Resolved live from the master, so it's null if the master
    # was since deleted. Used by the admin Orders tabs to split by category.
    category: Optional[str] = None


class OrderOut(BaseModel):
    id: int
    shop_id: int
    shop_name: str
    # Distributor's contact number so the customer can call about their order.
    # Resolved live from the User row — we don't snapshot it because it
    # makes sense to always show the current contact for the shop.
    distributor_phone: Optional[str] = None
    delivery_address: str
    delivery_lat: float
    delivery_lon: float
    subtotal: float
    status: str
    # created | paid | failed — customers currently only see "paid" orders,
    # but the field is surfaced so the app can show a payment confirmation pill.
    payment_status: str
    # fish (distributor delivery) | kiosk (dine-in) | accessories (shipped).
    kind: str
    delivery_date: Optional[date] = None
    # Kiosk dine-in only: expected-ready time.
    dining_at: Optional[datetime] = None
    coupon_code: Optional[str] = None
    discount_amount: float = 0.0
    total: float = 0.0
    created_at: datetime
    items: list[OrderItemOut]


def _order_kind(o: Order) -> str:
    if o.kiosk_user_id:
        return "kiosk"
    if o.distributor_user_id:
        return "fish"
    return "accessories"


def _order_dto(
    o: Order, items: list[OrderItem], distributor: Optional[User] = None
) -> OrderOut:
    return OrderOut(
        id=o.id,
        shop_id=o.shop_id,
        shop_name=o.shop_name,
        distributor_phone=distributor.phone if distributor else None,
        delivery_address=o.delivery_address,
        delivery_lat=float(o.delivery_lat),
        delivery_lon=float(o.delivery_lon),
        subtotal=float(o.subtotal),
        status=o.status,
        payment_status=o.payment_status,
        kind=_order_kind(o),
        delivery_date=o.delivery_date,
        dining_at=_utc_aware(o.dining_at) if o.dining_at is not None else None,
        coupon_code=o.coupon_code,
        discount_amount=float(o.discount_amount or 0.0),
        total=float(o.subtotal) - float(o.discount_amount or 0.0),
        created_at=_utc_aware(o.created_at),
        items=[
            OrderItemOut(
                master_item_id=i.master_item_id,
                name=i.name_snapshot,
                price=float(i.price_snapshot),
                quantity=i.quantity,
                line_total=float(i.line_total),
                weight_kg=(
                    float(i.weight_kg_snapshot)
                    if i.weight_kg_snapshot is not None
                    else None
                ),
            )
            for i in items
        ],
    )


class CouponValidateIn(BaseModel):
    coupon_code: str
    items: list[OrderItemIn]
    address_id: Optional[int] = None
    shop_id: Optional[int] = None
    is_kiosk: bool = False
    kiosk_user_id: Optional[int] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


class CouponValidateOut(BaseModel):
    coupon_code: str
    discount_amount: float
    subtotal: float
    final_amount: float


def _validate_coupon_for_lines(
    coupon: Coupon,
    user: User,
    subtotal: float,
    lines: list[OrderItem],
    is_kiosk_checkout: bool,
    kiosk_user_id: Optional[int],
    db: Session
) -> float:
    """Validates the coupon against calculated order lines and returns the discount amount.
    
    Raises HTTPException on validation errors.
    """
    # 1. Dates
    today = datetime.now(timezone.utc).astimezone(_IST).date()
    if today < coupon.start_date:
        raise HTTPException(400, f"This coupon is not active yet (starts on {coupon.start_date}).")
    if today > coupon.end_date:
        raise HTTPException(400, "This coupon has expired.")

    # 2. Kiosk check
    if coupon.kiosk_user_id is not None:
        if not is_kiosk_checkout or kiosk_user_id != coupon.kiosk_user_id:
            raise HTTPException(400, "This coupon is only valid at the issuing kiosk.")
            
    # 3. Type check (Welcome / One time)
    if coupon.coupon_type == "welcome":
        has_paid = db.query(Order).filter(Order.user_id == user.id, Order.payment_status == "paid").first()
        if has_paid:
            raise HTTPException(400, "Welcome coupons are only valid for your first order.")
    elif coupon.coupon_type == "one_time":
        has_used = db.query(CouponUsage).filter(CouponUsage.coupon_id == coupon.id, CouponUsage.user_id == user.id).first()
        if has_used:
            raise HTTPException(400, "This coupon has already been used.")

    # 4. Min bill amount
    if coupon.min_bill_amount is not None and subtotal < float(coupon.min_bill_amount):
        raise HTTPException(400, f"Minimum bill amount of Rs.{coupon.min_bill_amount} is required.")

    # 5. Calculate discount based on applicability scope (categories / products)
    app_cats = coupon.applicable_categories # e.g. ["fresh_fish"] or None
    app_prods = coupon.applicable_products # e.g. [1, 2, 3] or None
    
    has_restrictions = (app_cats and len(app_cats) > 0) or (app_prods and len(app_prods) > 0)
    
    if not has_restrictions:
        # Applies to the whole subtotal
        eligible_subtotal = subtotal
    else:
        # Filter lines
        eligible_subtotal = 0.0
        # Resolve master item details to check categories
        master_ids = [ln.master_item_id for ln in lines]
        masters = {
            m.id: m for m in db.query(MenuItem).filter(MenuItem.id.in_(master_ids)).all()
        }
        
        for ln in lines:
            m = masters.get(ln.master_item_id)
            if not m:
                continue
            is_eligible = False
            if app_prods and ln.master_item_id in app_prods:
                is_eligible = True
            elif app_cats and m.category in app_cats:
                is_eligible = True
                
            if is_eligible:
                eligible_subtotal += float(ln.line_total)
                
        if eligible_subtotal <= 0:
            raise HTTPException(400, "This coupon is not applicable to the items in your cart.")

    # 6. Compute discount
    if coupon.discount_type == "flat":
        discount = float(coupon.discount_value)
    else: # percentage
        discount = eligible_subtotal * (float(coupon.discount_value) / 100.0)
        if coupon.max_discount is not None:
            discount = min(discount, float(coupon.max_discount))
            
    discount = round(discount, 2)
    # cap at eligible subtotal or total subtotal
    discount = min(discount, subtotal)
    return discount


def _log_coupon_usage(user_id: int, coupon_code: str, order_id: int, db: Session) -> None:
    coupon = db.query(Coupon).filter(Coupon.code == coupon_code).first()
    if not coupon:
        return
    # check if usage is already logged (to stay idempotent)
    existing = db.query(CouponUsage).filter(
        CouponUsage.coupon_id == coupon.id,
        CouponUsage.user_id == user_id,
        CouponUsage.order_id == order_id
    ).first()
    if not existing:
        db.add(CouponUsage(coupon_id=coupon.id, user_id=user_id, order_id=order_id))
        db.commit()


def _apply_coupon_to_checkout(
    coupon_code: Optional[str],
    user: User,
    subtotal: float,
    lines: list[OrderItem],
    is_kiosk_checkout: bool,
    kiosk_user_id: Optional[int],
    db: Session
) -> tuple[Optional[str], float, float]:
    """Helper to apply coupon code to a checkout draft.
    
    Returns (coupon_code, discount_amount, final_amount).
    """
    discount_amount = 0.0
    applied_code = None
    if coupon_code:
        coupon = db.query(Coupon).filter(Coupon.code == coupon_code.upper(), Coupon.is_active == True).first()
        if not coupon:
            raise HTTPException(400, "Invalid coupon code.")
        discount_amount = _validate_coupon_for_lines(
            coupon, user, subtotal, lines, is_kiosk_checkout=is_kiosk_checkout, kiosk_user_id=kiosk_user_id, db=db
        )
        applied_code = coupon.code

    final_amount = max(0.0, subtotal - discount_amount)
    return applied_code, discount_amount, final_amount


class CheckoutOut(BaseModel):
    order_id: int
    amount: int  # in paise
    currency: str
    key_id: str  # public Key Id — safe to hand to the client
    razorpay_order_id: Optional[str] = None
    easebuzz_payment_url: Optional[str] = None
    easebuzz_access_key: Optional[str] = None


class ConfirmPaymentIn(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


def _build_order_draft(
    body: OrderIn, user: User, db: Session
) -> tuple[Shop, Address, float, list[OrderItem], Optional[date]]:
    """Validate a cart and compute the authoritative subtotal + line snapshots.

    Shared by checkout. The subtotal is computed *server-side* from current
    prices — the client never tells us the amount — so a tampered cart can't
    underpay. Raises HTTPException on any invalid line.
    """
    # 1) Resolve the chosen address and check it belongs to this customer.
    addr = (
        db.query(Address)
        .filter(Address.id == body.address_id, Address.user_id == user.id)
        .first()
    )
    if not addr:
        raise HTTPException(404, "Delivery address not found.")
    if not body.items:
        raise HTTPException(400, "Cart is empty.")
    for it in body.items:
        if it.quantity <= 0:
            raise HTTPException(400, "Item quantities must be positive.")

    # 2) Resolve the covering shop. If the client passed the distributor it
    #    actually shopped from (shop_id), lock to that shop and only verify it
    #    serves this address — we never silently reassign the cart to a closer
    #    distributor (its menu / prices would differ). Otherwise fall back to
    #    the closest covering shop. Either way the closed-shop gate applies.
    if body.shop_id is not None:
        shop = (
            db.query(Shop)
            .filter(
                Shop.id == body.shop_id,
                Shop.shop_status == "active",
                Shop.lat.is_not(None),
                Shop.lon.is_not(None),
                Shop.radius.is_not(None),
            )
            .first()
        )
        if shop is None:
            raise HTTPException(400, "This distributor is no longer available.")
        d = _haversine_km(
            float(addr.lat), float(addr.lon), float(shop.lat), float(shop.lon)
        )
        if d > float(shop.radius):
            raise HTTPException(
                400,
                "This distributor doesn't deliver to the selected address. "
                "Pick a different address or change your location.",
            )
    else:
        shops = (
            db.query(Shop)
            .filter(
                Shop.shop_status == "active",
                Shop.lat.is_not(None),
                Shop.lon.is_not(None),
                Shop.radius.is_not(None),
            )
            .all()
        )
        candidates: list[tuple[float, Shop]] = []
        for s in shops:
            d = _haversine_km(
                float(addr.lat), float(addr.lon), float(s.lat), float(s.lon)
            )
            if d <= float(s.radius):
                candidates.append((d, s))
        if not candidates:
            raise HTTPException(400, "No distributor serves this address.")
        candidates.sort(key=lambda x: x[0])
        shop = candidates[0][1]
    if shop.operation_status != "open":
        raise HTTPException(
            400, "This shop is currently closed. Try again when it reopens."
        )

    # 3) Look up the master items + the distributor's overrides.
    master_ids = [i.master_item_id for i in body.items]
    masters = {
        m.id: m
        for m in db.query(MenuItem)
        .filter(
            MenuItem.id.in_(master_ids),
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category.in_(DISTRIBUTOR_CATEGORIES),
        )
        .all()
    }
    overrides = {
        di.master_item_id: di
        for di in db.query(DistributorMenuItem)
        .filter(
            DistributorMenuItem.user_id == shop.user_id,
            DistributorMenuItem.master_item_id.in_(master_ids),
        )
        .all()
    }

    # 4) Validate every cart line — bail with 400 on any item that isn't on
    #    this shop's effective menu, so the client can clear / refresh cart.
    subtotal = 0.0
    lines: list[OrderItem] = []
    for it in body.items:
        m = masters.get(it.master_item_id)
        if not m:
            raise HTTPException(
                400, f"Item {it.master_item_id} is not available."
            )
        di = overrides.get(it.master_item_id)
        if di is not None and not di.is_available:
            raise HTTPException(400, f'"{m.name}" is currently out of stock.')
        variant_name, variant_price, variant_weight = _selected_variant(
            m, it.variant_label
        )
        price = float(di.price) if di is not None and not it.variant_label else variant_price
        line_total = round(price * it.quantity, 2)
        subtotal = round(subtotal + line_total, 2)
        lines.append(
            OrderItem(
                master_item_id=m.id,
                name_snapshot=variant_name,
                price_snapshot=price,
                weight_kg_snapshot=variant_weight,
                quantity=it.quantity,
                line_total=line_total,
            )
        )

    # Frozen fish carries no promised delivery date — the distributor simply
    # accepts and delivers. Fresh keeps the 12-PM-IST roster. (Fresh and frozen
    # are placed as separate orders, so a cart is single-category; a mixed cart
    # defensively falls back to the rostered date.)
    cats = {masters[i.master_item_id].category for i in body.items}
    delivery_date = None if cats == {"frozen_fish"} else _compute_delivery_date()
    return shop, addr, subtotal, lines, delivery_date


@app.post("/customer/orders/checkout", response_model=CheckoutOut, status_code=201)
def checkout_order(
    body: OrderIn,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> CheckoutOut:
    """Step 1 of payment-first ordering: validate the cart, persist the order
    in payment_status="created" (hidden from fulfillment), and open a Razorpay
    order with auto-capture. The app then opens checkout with the returned ids.
    """
    _require_payments()
    shop, addr, subtotal, lines, delivery_date = _build_order_draft(body, user, db)

    # Apply coupon if provided
    coupon_code, discount_amount, final_amount = _apply_coupon_to_checkout(
        body.coupon_code, user, subtotal, lines, is_kiosk_checkout=False, kiosk_user_id=None, db=db
    )
    amount_paise = int(round(final_amount * 100))
    if amount_paise <= 0:
        raise HTTPException(400, "Order total must be greater than zero.")

    # Persist header + lines first so we have a stable order id for the receipt
    # and for the webhook to find later. payment_status="created" keeps it out
    # of every distributor / kiosk / admin list until the money is captured.
    order = Order(
        user_id=user.id,
        distributor_user_id=shop.user_id,
        shop_id=shop.id,
        shop_name=shop.name,
        address_id=addr.id,
        delivery_address=addr.address,
        delivery_lat=addr.lat,
        delivery_lon=addr.lon,
        subtotal=subtotal,
        coupon_code=coupon_code,
        discount_amount=discount_amount,
        payment_status="created",
        status="pending",
        delivery_date=delivery_date,
    )
    db.add(order)
    db.flush()  # populate order.id for the lines + receipt
    for ln in lines:
        ln.order_id = order.id
        db.add(ln)

    return _create_checkout_session(order, amount_paise, final_amount, user, db)


@app.post("/customer/orders/{order_id}/confirm", response_model=OrderOut)
def confirm_payment(
    order_id: int,
    body: ConfirmPaymentIn,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> OrderOut:
    """Step 2: the app calls this after a successful checkout. We verify the
    payment signature with the Key Secret and flip the order to "paid". The
    webhook does the same independently, so this is best-effort fast-path —
    both are idempotent.
    """
    client = _require_razorpay()
    order = (
        db.query(Order)
        .filter(Order.id == order_id, Order.user_id == user.id)
        .first()
    )
    if not order:
        raise HTTPException(404, "Order not found.")
    if order.razorpay_order_id != body.razorpay_order_id:
        raise HTTPException(400, "Payment does not match this order.")

    try:
        client.utility.verify_payment_signature(
            {
                "razorpay_order_id": body.razorpay_order_id,
                "razorpay_payment_id": body.razorpay_payment_id,
                "razorpay_signature": body.razorpay_signature,
            }
        )
    except Exception:  # noqa: BLE001 — SignatureVerificationError or anything
        raise HTTPException(400, "Payment verification failed.")

    if order.payment_status != "paid":
        order.payment_status = "paid"
        order.razorpay_payment_id = body.razorpay_payment_id
        db.commit()
        db.refresh(order)
        if order.coupon_code:
            _log_coupon_usage(order.user_id, order.coupon_code, order.id, db)

    items = (
        db.query(OrderItem)
        .filter(OrderItem.order_id == order.id)
        .order_by(OrderItem.id)
        .all()
    )
    distributor = (
        db.query(User).filter(User.id == order.distributor_user_id).first()
    )
    return _order_dto(order, items, distributor)


@app.post("/customer/orders/{order_id}/confirm-easebuzz", response_model=OrderOut)
def confirm_easebuzz_payment(
    order_id: int,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> OrderOut:
    """Confirm Easebuzz payment and set order status to paid."""
    order = (
        db.query(Order)
        .filter(Order.id == order_id, Order.user_id == user.id)
        .first()
    )
    if not order:
        raise HTTPException(404, "Order not found.")

    if order.payment_status != "paid":
        order.payment_status = "paid"
        db.commit()
        db.refresh(order)
        if order.coupon_code:
            _log_coupon_usage(order.user_id, order.coupon_code, order.id, db)

    items = (
        db.query(OrderItem)
        .filter(OrderItem.order_id == order.id)
        .order_by(OrderItem.id)
        .all()
    )
    distributor = (
        db.query(User).filter(User.id == order.distributor_user_id).first()
    )
    return _order_dto(order, items, distributor)


@app.post("/webhooks/razorpay", include_in_schema=False)
async def razorpay_webhook(
    request: Request, db: Session = Depends(get_db)
) -> dict[str, str]:
    """Source-of-truth payment confirmation. Razorpay POSTs here signed with
    the WEBHOOK secret (distinct from the Key Secret). Verifying it lets us
    finalise a paid order even if the app crashed before calling /confirm.
    Idempotent: re-delivered events are no-ops.
    """
    if _razorpay_client is None or not RAZORPAY_WEBHOOK_SECRET:
        raise HTTPException(503, "Webhook not configured.")
    raw = await request.body()
    signature = request.headers.get("X-Razorpay-Signature", "")
    try:
        _razorpay_client.utility.verify_webhook_signature(
            raw.decode("utf-8"), signature, RAZORPAY_WEBHOOK_SECRET
        )
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "Invalid webhook signature.")

    payload = _json.loads(raw)
    event = payload.get("event", "")
    entities = payload.get("payload", {}) or {}
    payment = (entities.get("payment", {}) or {}).get("entity", {}) or {}
    order_entity = (entities.get("order", {}) or {}).get("entity", {}) or {}
    rzp_order_id = payment.get("order_id") or order_entity.get("id")
    rzp_payment_id = payment.get("id")
    if not rzp_order_id:
        return {"status": "ignored"}

    order = (
        db.query(Order)
        .filter(Order.razorpay_order_id == rzp_order_id)
        .first()
    )
    if not order:
        return {"status": "unknown-order"}

    if event in ("payment.captured", "order.paid") and order.payment_status != "paid":
        order.payment_status = "paid"
        if rzp_payment_id:
            order.razorpay_payment_id = rzp_payment_id
        db.commit()
        if order.coupon_code:
            _log_coupon_usage(order.user_id, order.coupon_code, order.id, db)
    elif event == "payment.failed" and order.payment_status == "created":
        order.payment_status = "failed"
        db.commit()
    return {"status": "ok"}


# ============ Customer: kiosk pre-order checkout (dine-in) ============
class KioskCheckoutIn(BaseModel):
    # Current GPS location — used to resolve the covering kiosk, mirroring how
    # the storefront found it. Dine-in, so there's no delivery address.
    lat: float
    lon: float
    items: list[OrderItemIn]
    coupon_code: Optional[str] = None


def _build_kiosk_draft(
    lat: float, lon: float, items: list[OrderItemIn], db: Session
) -> tuple[Kiosk, float, int, list[OrderItem]]:
    """Validate a kiosk cart against the covering kiosk's menu. Returns
    (kiosk, subtotal, max_prep_minutes, lines). Subtotal is server-side."""
    if not items:
        raise HTTPException(400, "Cart is empty.")
    hit = _closest_covering_kiosk(lat, lon, db)
    if hit is None:
        raise HTTPException(400, "No kiosk serves your current location.")
    _dist, k = hit
    if _effective_kiosk_operation_status(k) != "open":
        raise HTTPException(
            400, "This kiosk is currently closed. Try again when it reopens."
        )

    master_ids = [i.master_item_id for i in items]
    masters = {
        m.id: m
        for m in db.query(MenuItem)
        .filter(
            MenuItem.id.in_(master_ids),
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category.in_(KIOSK_CATEGORIES),
        )
        .all()
    }
    overrides = {
        ki.master_item_id: ki
        for ki in db.query(KioskMenuItem)
        .filter(
            KioskMenuItem.user_id == k.user_id,
            KioskMenuItem.master_item_id.in_(master_ids),
        )
        .all()
    }

    subtotal = 0.0
    max_prep = 0
    lines: list[OrderItem] = []
    for it in items:
        if it.quantity <= 0:
            raise HTTPException(400, "Item quantities must be positive.")
        m = masters.get(it.master_item_id)
        if not m:
            raise HTTPException(400, f"Item {it.master_item_id} is not available.")
        ki = overrides.get(it.master_item_id)
        if ki is not None and not ki.is_available:
            raise HTTPException(400, f'"{m.name}" is currently out of stock.')
        variant_name, variant_price, variant_weight = _selected_variant(
            m, it.variant_label
        )
        price = float(ki.price) if ki is not None and not it.variant_label else variant_price
        line_total = round(price * it.quantity, 2)
        subtotal = round(subtotal + line_total, 2)
        if m.prep_time_minutes and m.prep_time_minutes > max_prep:
            max_prep = int(m.prep_time_minutes)
        lines.append(
            OrderItem(
                master_item_id=m.id,
                name_snapshot=variant_name,
                price_snapshot=price,
                weight_kg_snapshot=variant_weight,
                quantity=it.quantity,
                line_total=line_total,
            )
        )
    return k, subtotal, max_prep, lines


@app.post("/customer/kiosk/checkout", response_model=CheckoutOut, status_code=201)
def kiosk_checkout(
    body: KioskCheckoutIn,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> CheckoutOut:
    _require_payments()
    k, subtotal, max_prep, lines = _build_kiosk_draft(
        body.lat, body.lon, body.items, db
    )
    # Apply coupon if provided
    coupon_code, discount_amount, final_amount = _apply_coupon_to_checkout(
        body.coupon_code, user, subtotal, lines, is_kiosk_checkout=True, kiosk_user_id=k.user_id, db=db
    )
    amount_paise = int(round(final_amount * 100))
    if amount_paise <= 0:
        raise HTTPException(400, "Order total must be greater than zero.")

    dining_at = datetime.now(timezone.utc) + timedelta(minutes=max_prep)
    order = Order(
        user_id=user.id,
        distributor_user_id=None,
        kiosk_user_id=k.user_id,
        shop_id=k.id,
        shop_name=k.name,
        address_id=None,
        # Dine-in: snapshot the kiosk as the "delivery" target so existing
        # order views stay populated; the coordinates are the kiosk's.
        delivery_address=k.location or f"Dine-in at {k.name}",
        delivery_lat=k.lat,
        delivery_lon=k.lon,
        subtotal=subtotal,
        coupon_code=coupon_code,
        discount_amount=discount_amount,
        payment_status="created",
        status="pending",
        delivery_date=dining_at.astimezone(_IST).date(),
        dining_at=dining_at,
    )
    db.add(order)
    db.flush()
    for ln in lines:
        ln.order_id = order.id
        db.add(ln)

    return _create_checkout_session(order, amount_paise, final_amount, user, db)


# ============ Customer: accessories checkout (shipped by central admin) ============
@app.post(
    "/customer/accessories/checkout", response_model=CheckoutOut, status_code=201
)
def accessories_checkout(
    body: OrderIn,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> CheckoutOut:
    _require_payments()
    if not body.items:
        raise HTTPException(400, "Cart is empty.")

    # Accessories ship to a typed postal address (preferred) with the coords the
    # app already has, or — for older clients — to a saved delivery address.
    postal = (body.postal_address or "").strip()
    if postal:
        if body.lat is None or body.lon is None:
            raise HTTPException(400, "Shipping location is required.")
        ship_address = postal
        ship_lat = body.lat
        ship_lon = body.lon
        ship_address_id = None
    else:
        addr = (
            db.query(Address)
            .filter(Address.id == body.address_id, Address.user_id == user.id)
            .first()
        )
        if not addr:
            raise HTTPException(404, "Delivery address not found.")
        ship_address = addr.address
        ship_lat = addr.lat
        ship_lon = addr.lon
        ship_address_id = addr.id

    master_ids = [i.master_item_id for i in body.items]
    masters = {
        m.id: m
        for m in db.query(MenuItem)
        .filter(
            MenuItem.id.in_(master_ids),
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category == "accessories",
        )
        .all()
    }
    subtotal = 0.0
    lines: list[OrderItem] = []
    for it in body.items:
        if it.quantity <= 0:
            raise HTTPException(400, "Item quantities must be positive.")
        m = masters.get(it.master_item_id)
        if not m:
            raise HTTPException(400, f"Item {it.master_item_id} is not available.")
        variant_name, price, variant_weight = _selected_variant(m, it.variant_label)
        line_total = round(price * it.quantity, 2)
        subtotal = round(subtotal + line_total, 2)
        lines.append(
            OrderItem(
                master_item_id=m.id,
                name_snapshot=variant_name,
                price_snapshot=price,
                weight_kg_snapshot=variant_weight,
                quantity=it.quantity,
                line_total=line_total,
            )
        )
    # Apply coupon if provided
    coupon_code, discount_amount, final_amount = _apply_coupon_to_checkout(
        body.coupon_code, user, subtotal, lines, is_kiosk_checkout=False, kiosk_user_id=None, db=db
    )
    amount_paise = int(round(final_amount * 100))
    if amount_paise <= 0:
        raise HTTPException(400, "Order total must be greater than zero.")

    # Central-admin order: no distributor, no kiosk. shop_id=0 is the sentinel
    # for "shipped by DayCatch"; the admin accessories view keys off both
    # fulfiller ids being null.
    order = Order(
        user_id=user.id,
        distributor_user_id=None,
        kiosk_user_id=None,
        shop_id=0,
        shop_name=ACCESSORIES_SHOP_NAME,
        address_id=ship_address_id,
        delivery_address=ship_address,
        delivery_lat=ship_lat,
        delivery_lon=ship_lon,
        subtotal=subtotal,
        coupon_code=coupon_code,
        discount_amount=discount_amount,
        payment_status="created",
        status="pending",
        delivery_date=None,
        dining_at=None,
    )
    db.add(order)
    db.flush()
    for ln in lines:
        ln.order_id = order.id
        db.add(ln)

    return _create_checkout_session(order, amount_paise, final_amount, user, db)


# ============ Customer: dry-fish checkout (shipped by central admin) ============
# A clone of the accessories checkout — dry fish is always-available and shipped
# by central admin, but kept as its own cart / order queue.
@app.post(
    "/customer/dry-fish/checkout", response_model=CheckoutOut, status_code=201
)
def dry_fish_checkout(
    body: OrderIn,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> CheckoutOut:
    _require_payments()
    if not body.items:
        raise HTTPException(400, "Cart is empty.")

    # Dry fish ships to a typed postal address (preferred) with the coords the
    # app already has, or — for older clients — to a saved delivery address.
    postal = (body.postal_address or "").strip()
    if postal:
        if body.lat is None or body.lon is None:
            raise HTTPException(400, "Shipping location is required.")
        ship_address = postal
        ship_lat = body.lat
        ship_lon = body.lon
        ship_address_id = None
    else:
        addr = (
            db.query(Address)
            .filter(Address.id == body.address_id, Address.user_id == user.id)
            .first()
        )
        if not addr:
            raise HTTPException(404, "Delivery address not found.")
        ship_address = addr.address
        ship_lat = addr.lat
        ship_lon = addr.lon
        ship_address_id = addr.id

    master_ids = [i.master_item_id for i in body.items]
    masters = {
        m.id: m
        for m in db.query(MenuItem)
        .filter(
            MenuItem.id.in_(master_ids),
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category == "dry_fish",
        )
        .all()
    }
    subtotal = 0.0
    lines: list[OrderItem] = []
    for it in body.items:
        if it.quantity <= 0:
            raise HTTPException(400, "Item quantities must be positive.")
        m = masters.get(it.master_item_id)
        if not m:
            raise HTTPException(400, f"Item {it.master_item_id} is not available.")
        variant_name, price, variant_weight = _selected_variant(m, it.variant_label)
        line_total = round(price * it.quantity, 2)
        subtotal = round(subtotal + line_total, 2)
        lines.append(
            OrderItem(
                master_item_id=m.id,
                name_snapshot=variant_name,
                price_snapshot=price,
                weight_kg_snapshot=variant_weight,
                quantity=it.quantity,
                line_total=line_total,
            )
        )
    # Apply coupon if provided
    coupon_code, discount_amount, final_amount = _apply_coupon_to_checkout(
        body.coupon_code, user, subtotal, lines, is_kiosk_checkout=False, kiosk_user_id=None, db=db
    )
    amount_paise = int(round(final_amount * 100))
    if amount_paise <= 0:
        raise HTTPException(400, "Order total must be greater than zero.")

    # Central-admin order: no distributor, no kiosk. shop_id=0 is the sentinel
    # for "shipped by DayCatch"; the admin dry-fish view keys off both fulfiller
    # ids being null plus the dry-fish shop-name snapshot.
    order = Order(
        user_id=user.id,
        distributor_user_id=None,
        kiosk_user_id=None,
        shop_id=0,
        shop_name=DRY_FISH_SHOP_NAME,
        address_id=ship_address_id,
        delivery_address=ship_address,
        delivery_lat=ship_lat,
        delivery_lon=ship_lon,
        subtotal=subtotal,
        coupon_code=coupon_code,
        discount_amount=discount_amount,
        payment_status="created",
        status="pending",
        delivery_date=None,
        dining_at=None,
    )
    db.add(order)
    db.flush()
    for ln in lines:
        ln.order_id = order.id
        db.add(ln)

    return _create_checkout_session(order, amount_paise, final_amount, user, db)


# ============ Customer: pickles checkout (shipped by central admin) ============
# A clone of the accessories checkout — pickles are always-available and shipped
# by central admin, but kept as their own cart / order queue.
@app.post(
    "/customer/pickles/checkout", response_model=CheckoutOut, status_code=201
)
def pickles_checkout(
    body: OrderIn,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> CheckoutOut:
    _require_payments()
    if not body.items:
        raise HTTPException(400, "Cart is empty.")

    # Pickles ship to a typed postal address (preferred) with the coords the app
    # already has, or — for older clients — to a saved delivery address.
    postal = (body.postal_address or "").strip()
    if postal:
        if body.lat is None or body.lon is None:
            raise HTTPException(400, "Shipping location is required.")
        ship_address = postal
        ship_lat = body.lat
        ship_lon = body.lon
        ship_address_id = None
    else:
        addr = (
            db.query(Address)
            .filter(Address.id == body.address_id, Address.user_id == user.id)
            .first()
        )
        if not addr:
            raise HTTPException(404, "Delivery address not found.")
        ship_address = addr.address
        ship_lat = addr.lat
        ship_lon = addr.lon
        ship_address_id = addr.id

    master_ids = [i.master_item_id for i in body.items]
    masters = {
        m.id: m
        for m in db.query(MenuItem)
        .filter(
            MenuItem.id.in_(master_ids),
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category == "pickles",
        )
        .all()
    }
    subtotal = 0.0
    lines: list[OrderItem] = []
    for it in body.items:
        if it.quantity <= 0:
            raise HTTPException(400, "Item quantities must be positive.")
        m = masters.get(it.master_item_id)
        if not m:
            raise HTTPException(400, f"Item {it.master_item_id} is not available.")
        variant_name, price, variant_weight = _selected_variant(m, it.variant_label)
        line_total = round(price * it.quantity, 2)
        subtotal = round(subtotal + line_total, 2)
        lines.append(
            OrderItem(
                master_item_id=m.id,
                name_snapshot=variant_name,
                price_snapshot=price,
                weight_kg_snapshot=variant_weight,
                quantity=it.quantity,
                line_total=line_total,
            )
        )
    # Apply coupon if provided
    coupon_code, discount_amount, final_amount = _apply_coupon_to_checkout(
        body.coupon_code, user, subtotal, lines, is_kiosk_checkout=False, kiosk_user_id=None, db=db
    )
    amount_paise = int(round(final_amount * 100))
    if amount_paise <= 0:
        raise HTTPException(400, "Order total must be greater than zero.")

    # Central-admin order: no distributor, no kiosk. shop_id=0 is the sentinel
    # for "shipped by DayCatch"; the admin pickles view keys off both fulfiller
    # ids being null plus the pickles shop-name snapshot.
    order = Order(
        user_id=user.id,
        distributor_user_id=None,
        kiosk_user_id=None,
        shop_id=0,
        shop_name=PICKLES_SHOP_NAME,
        address_id=ship_address_id,
        delivery_address=ship_address,
        delivery_lat=ship_lat,
        delivery_lon=ship_lon,
        subtotal=subtotal,
        coupon_code=coupon_code,
        discount_amount=discount_amount,
        payment_status="created",
        status="pending",
        delivery_date=None,
        dining_at=None,
    )
    db.add(order)
    db.flush()
    for ln in lines:
        ln.order_id = order.id
        db.add(ln)

    return _create_checkout_session(order, amount_paise, final_amount, user, db)


@app.get("/customer/orders", response_model=list[OrderOut])
def list_orders(
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> list[OrderOut]:
    orders = (
        db.query(Order)
        .filter(Order.user_id == user.id, Order.payment_status == "paid")
        .order_by(Order.created_at.desc())
        .limit(50)
        .all()
    )
    # Batch-fetch the distributor User rows so we don't do N+1.
    distributor_ids = {o.distributor_user_id for o in orders}
    distributors = (
        {
            u.id: u
            for u in db.query(User).filter(User.id.in_(distributor_ids)).all()
        }
        if distributor_ids
        else {}
    )
    out: list[OrderOut] = []
    for o in orders:
        items = (
            db.query(OrderItem)
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.id)
            .all()
        )
        out.append(_order_dto(o, items, distributors.get(o.distributor_user_id)))
    return out


# ============ Orders: shared status state machine ============
# Used by both /admin/orders (read-only) and /distributor/orders (mutating).
# Defined here so the admin section below can reference OrderStatus without
# a forward declaration that breaks Pydantic's schema build.
_ORDER_TRANSITIONS: dict[str, set[str]] = {
    "pending":   {"accepted", "cancelled"},
    "accepted":  {"ready", "cancelled"},
    "ready":     {"delivered", "cancelled"},
    "delivered": set(),
    "cancelled": set(),
}
OrderStatus = Literal["pending", "accepted", "ready", "delivered", "cancelled"]


# ============ Admin: orders (read-only across all distributors) ============
class AdminOrderOut(BaseModel):
    id: int
    distributor_user_id: int
    distributor_name: Optional[str] = None
    distributor_phone: str
    shop_id: int
    shop_name: str
    customer_name: Optional[str] = None
    customer_phone: str
    delivery_address: str
    delivery_lat: float
    delivery_lon: float
    subtotal: float
    status: str
    payment_status: str  # created | paid | failed
    delivery_date: Optional[date] = None
    created_at: datetime
    items: list[OrderItemOut]


def _admin_order_dto(
    o: Order,
    items: list[OrderItem],
    customer: Optional[User],
    distributor: Optional[User],
    categories: Optional[dict[int, str]] = None,
) -> AdminOrderOut:
    def _name(u: Optional[User]) -> Optional[str]:
        if not u:
            return None
        parts = [u.first_name, u.last_name]
        return " ".join(p for p in parts if p) or None

    cats = categories or {}
    return AdminOrderOut(
        id=o.id,
        distributor_user_id=o.distributor_user_id,
        distributor_name=_name(distributor),
        distributor_phone=distributor.phone if distributor else "",
        shop_id=o.shop_id,
        shop_name=o.shop_name,
        customer_name=_name(customer),
        customer_phone=customer.phone if customer else "",
        delivery_address=o.delivery_address,
        delivery_lat=float(o.delivery_lat),
        delivery_lon=float(o.delivery_lon),
        subtotal=float(o.subtotal),
        status=o.status,
        payment_status=o.payment_status,
        delivery_date=o.delivery_date,
        created_at=_utc_aware(o.created_at),
        items=[
            OrderItemOut(
                master_item_id=i.master_item_id,
                name=i.name_snapshot,
                price=float(i.price_snapshot),
                quantity=i.quantity,
                line_total=float(i.line_total),
                weight_kg=(
                    float(i.weight_kg_snapshot)
                    if i.weight_kg_snapshot is not None
                    else None
                ),
                category=cats.get(i.master_item_id),
            )
            for i in items
        ],
    )


@app.get("/admin/orders", response_model=list[AdminOrderOut])
def admin_list_orders(
    status: Optional[OrderStatus] = None,
    distributor_user_id: Optional[int] = None,
    # YYYY-MM-DD; FastAPI parses ISO into a date. The admin UI passes the
    # IST-computed tomorrow / day-after-tomorrow dates here.
    delivery_date: Optional[date] = None,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[AdminOrderOut]:
    # Distributor (delivery) orders only — this feeds the Fresh/Frozen sourcing
    # tabs. Kiosk and accessories orders have their own admin endpoints; without
    # this filter their null distributor_user_id would also break AdminOrderOut.
    q = db.query(Order).filter(
        Order.payment_status == "paid",
        Order.distributor_user_id.isnot(None),
    )
    if status:
        q = q.filter(Order.status == status)
    if distributor_user_id is not None:
        q = q.filter(Order.distributor_user_id == distributor_user_id)
    if delivery_date is not None:
        q = q.filter(Order.delivery_date == delivery_date)
    orders = q.order_by(Order.created_at.desc()).limit(200).all()

    # Batch-fetch customers + distributors so we don't do N+1 user lookups.
    user_ids = {o.user_id for o in orders} | {o.distributor_user_id for o in orders}
    users = {
        u.id: u
        for u in db.query(User).filter(User.id.in_(user_ids)).all()
    } if user_ids else {}

    out: list[AdminOrderOut] = []
    all_items: dict[int, list[OrderItem]] = {}
    master_ids: set[int] = set()
    for o in orders:
        items = (
            db.query(OrderItem)
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.id)
            .all()
        )
        all_items[o.id] = items
        master_ids.update(i.master_item_id for i in items)

    # Resolve each item's category from the master menu so the UI can split the
    # rollup into Fresh vs Frozen tabs. Deleted masters simply resolve to null.
    categories = (
        {
            m.id: m.category
            for m in db.query(MenuItem.id, MenuItem.category)
            .filter(MenuItem.id.in_(master_ids))
            .all()
        }
        if master_ids
        else {}
    )

    for o in orders:
        out.append(
            _admin_order_dto(
                o,
                all_items[o.id],
                users.get(o.user_id),
                users.get(o.distributor_user_id),
                categories,
            )
        )
    return out


# ============ Admin: accessories orders (central admin ships these) ============
# Accessories orders have neither a distributor nor a kiosk — central admin
# fulfils them. They're keyed off both fulfiller ids being null.
class AccessoryOrderOut(BaseModel):
    id: int
    customer_name: Optional[str] = None
    customer_phone: str
    delivery_address: str
    subtotal: float
    status: str
    payment_status: str
    created_at: datetime
    items: list[OrderItemOut]


def _accessory_order_dto(
    o: Order, items: list[OrderItem], customer: Optional[User]
) -> AccessoryOrderOut:
    name_parts = [customer.first_name, customer.last_name] if customer else []
    customer_name = " ".join(p for p in name_parts if p) or None
    return AccessoryOrderOut(
        id=o.id,
        customer_name=customer_name,
        customer_phone=customer.phone if customer else "",
        delivery_address=o.delivery_address,
        subtotal=float(o.subtotal),
        status=o.status,
        payment_status=o.payment_status,
        created_at=_utc_aware(o.created_at),
        items=[
            OrderItemOut(
                master_item_id=i.master_item_id,
                name=i.name_snapshot,
                price=float(i.price_snapshot),
                quantity=i.quantity,
                line_total=float(i.line_total),
                weight_kg=None,
            )
            for i in items
        ],
    )


@app.get("/admin/accessories-orders", response_model=list[AccessoryOrderOut])
def admin_list_accessory_orders(
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[AccessoryOrderOut]:
    orders = (
        db.query(Order)
        .filter(
            Order.distributor_user_id.is_(None),
            Order.kiosk_user_id.is_(None),
            Order.shop_name == ACCESSORIES_SHOP_NAME,
            Order.payment_status == "paid",
        )
        .order_by(Order.created_at.desc())
        .limit(200)
        .all()
    )
    cust_ids = {o.user_id for o in orders}
    customers = (
        {u.id: u for u in db.query(User).filter(User.id.in_(cust_ids)).all()}
        if cust_ids
        else {}
    )
    out: list[AccessoryOrderOut] = []
    for o in orders:
        items = (
            db.query(OrderItem)
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.id)
            .all()
        )
        out.append(_accessory_order_dto(o, items, customers.get(o.user_id)))
    return out


class AccessoryOrderUpdate(BaseModel):
    status: OrderStatus


@app.patch(
    "/admin/accessories-orders/{order_id}", response_model=AccessoryOrderOut
)
def admin_update_accessory_order(
    order_id: int,
    body: AccessoryOrderUpdate,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> AccessoryOrderOut:
    o = (
        db.query(Order)
        .filter(
            Order.id == order_id,
            Order.distributor_user_id.is_(None),
            Order.kiosk_user_id.is_(None),
            Order.shop_name == ACCESSORIES_SHOP_NAME,
        )
        .first()
    )
    if not o:
        raise HTTPException(404, "Accessories order not found.")
    allowed = _ORDER_TRANSITIONS.get(o.status, set())
    if body.status not in allowed:
        raise HTTPException(
            400, f"Can't move an order from {o.status} to {body.status}."
        )
    o.status = body.status
    db.commit()
    db.refresh(o)
    items = (
        db.query(OrderItem)
        .filter(OrderItem.order_id == o.id)
        .order_by(OrderItem.id)
        .all()
    )
    customer = db.query(User).filter(User.id == o.user_id).first()
    return _accessory_order_dto(o, items, customer)


# ============ Admin: dry-fish orders (central admin ships these) ============
# Like accessories, dry-fish orders have neither a distributor nor a kiosk —
# central admin fulfils them. They're keyed off both fulfiller ids being null
# plus the dry-fish shop-name snapshot, so they stay separate from accessories.
@app.get("/admin/dry-fish-orders", response_model=list[AccessoryOrderOut])
def admin_list_dry_fish_orders(
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[AccessoryOrderOut]:
    orders = (
        db.query(Order)
        .filter(
            Order.distributor_user_id.is_(None),
            Order.kiosk_user_id.is_(None),
            Order.shop_name == DRY_FISH_SHOP_NAME,
            Order.payment_status == "paid",
        )
        .order_by(Order.created_at.desc())
        .limit(200)
        .all()
    )
    cust_ids = {o.user_id for o in orders}
    customers = (
        {u.id: u for u in db.query(User).filter(User.id.in_(cust_ids)).all()}
        if cust_ids
        else {}
    )
    out: list[AccessoryOrderOut] = []
    for o in orders:
        items = (
            db.query(OrderItem)
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.id)
            .all()
        )
        out.append(_accessory_order_dto(o, items, customers.get(o.user_id)))
    return out


@app.patch(
    "/admin/dry-fish-orders/{order_id}", response_model=AccessoryOrderOut
)
def admin_update_dry_fish_order(
    order_id: int,
    body: AccessoryOrderUpdate,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> AccessoryOrderOut:
    o = (
        db.query(Order)
        .filter(
            Order.id == order_id,
            Order.distributor_user_id.is_(None),
            Order.kiosk_user_id.is_(None),
            Order.shop_name == DRY_FISH_SHOP_NAME,
        )
        .first()
    )
    if not o:
        raise HTTPException(404, "Dry-fish order not found.")
    allowed = _ORDER_TRANSITIONS.get(o.status, set())
    if body.status not in allowed:
        raise HTTPException(
            400, f"Can't move an order from {o.status} to {body.status}."
        )
    o.status = body.status
    db.commit()
    db.refresh(o)
    items = (
        db.query(OrderItem)
        .filter(OrderItem.order_id == o.id)
        .order_by(OrderItem.id)
        .all()
    )
    customer = db.query(User).filter(User.id == o.user_id).first()
    return _accessory_order_dto(o, items, customer)


# ============ Admin: pickles orders (central admin ships these) ============
# Like accessories, pickles orders have neither a distributor nor a kiosk —
# central admin fulfils them. They're keyed off both fulfiller ids being null
# plus the pickles shop-name snapshot, so they stay separate from the other
# central-admin queues.
@app.get("/admin/pickles-orders", response_model=list[AccessoryOrderOut])
def admin_list_pickles_orders(
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[AccessoryOrderOut]:
    orders = (
        db.query(Order)
        .filter(
            Order.distributor_user_id.is_(None),
            Order.kiosk_user_id.is_(None),
            Order.shop_name == PICKLES_SHOP_NAME,
            Order.payment_status == "paid",
        )
        .order_by(Order.created_at.desc())
        .limit(200)
        .all()
    )
    cust_ids = {o.user_id for o in orders}
    customers = (
        {u.id: u for u in db.query(User).filter(User.id.in_(cust_ids)).all()}
        if cust_ids
        else {}
    )
    out: list[AccessoryOrderOut] = []
    for o in orders:
        items = (
            db.query(OrderItem)
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.id)
            .all()
        )
        out.append(_accessory_order_dto(o, items, customers.get(o.user_id)))
    return out


@app.patch(
    "/admin/pickles-orders/{order_id}", response_model=AccessoryOrderOut
)
def admin_update_pickles_order(
    order_id: int,
    body: AccessoryOrderUpdate,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> AccessoryOrderOut:
    o = (
        db.query(Order)
        .filter(
            Order.id == order_id,
            Order.distributor_user_id.is_(None),
            Order.kiosk_user_id.is_(None),
            Order.shop_name == PICKLES_SHOP_NAME,
        )
        .first()
    )
    if not o:
        raise HTTPException(404, "Pickles order not found.")
    allowed = _ORDER_TRANSITIONS.get(o.status, set())
    if body.status not in allowed:
        raise HTTPException(
            400, f"Can't move an order from {o.status} to {body.status}."
        )
    o.status = body.status
    db.commit()
    db.refresh(o)
    items = (
        db.query(OrderItem)
        .filter(OrderItem.order_id == o.id)
        .order_by(OrderItem.id)
        .all()
    )
    customer = db.query(User).filter(User.id == o.user_id).first()
    return _accessory_order_dto(o, items, customer)


# ============ Admin: kiosk orders (read-only oversight) ============
# Kiosk (fish & chips) dine-in orders are fulfilled by the kiosk owner — admin
# only watches. This powers the "Fish & Chips" tab on the admin Orders page.
class AdminKioskOrderOut(BaseModel):
    id: int
    kiosk_name: Optional[str] = None
    customer_name: Optional[str] = None
    customer_phone: str
    subtotal: float
    status: str
    payment_status: str
    dining_at: Optional[datetime] = None
    created_at: datetime
    items: list[OrderItemOut]


@app.get("/admin/kiosk-orders", response_model=list[AdminKioskOrderOut])
def admin_list_kiosk_orders(
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
) -> list[AdminKioskOrderOut]:
    orders = (
        db.query(Order)
        .filter(
            Order.kiosk_user_id.isnot(None),
            Order.payment_status == "paid",
        )
        .order_by(Order.created_at.desc())
        .limit(200)
        .all()
    )
    cust_ids = {o.user_id for o in orders}
    kiosk_user_ids = {o.kiosk_user_id for o in orders}
    customers = (
        {u.id: u for u in db.query(User).filter(User.id.in_(cust_ids)).all()}
        if cust_ids
        else {}
    )
    kiosks = (
        {k.user_id: k for k in db.query(Kiosk).filter(Kiosk.user_id.in_(kiosk_user_ids)).all()}
        if kiosk_user_ids
        else {}
    )

    def _name(u: Optional[User]) -> Optional[str]:
        if not u:
            return None
        return " ".join(p for p in [u.first_name, u.last_name] if p) or None

    out: list[AdminKioskOrderOut] = []
    for o in orders:
        items = (
            db.query(OrderItem)
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.id)
            .all()
        )
        customer = customers.get(o.user_id)
        kiosk = kiosks.get(o.kiosk_user_id)
        out.append(
            AdminKioskOrderOut(
                id=o.id,
                kiosk_name=kiosk.name if kiosk else None,
                customer_name=_name(customer),
                customer_phone=customer.phone if customer else "",
                subtotal=float(o.subtotal),
                status=o.status,
                payment_status=o.payment_status,
                dining_at=_utc_aware(o.dining_at) if o.dining_at is not None else None,
                created_at=_utc_aware(o.created_at),
                items=[
                    OrderItemOut(
                        master_item_id=i.master_item_id,
                        name=i.name_snapshot,
                        price=float(i.price_snapshot),
                        quantity=i.quantity,
                        line_total=float(i.line_total),
                        weight_kg=None,
                    )
                    for i in items
                ],
            )
        )
    return out


# ============ Distributor: orders ============
# Status transitions + OrderStatus type live in the "Orders: shared status
# state machine" section above so /admin/orders can reference them without
# a forward declaration that breaks Pydantic's schema build.


class DistributorOrderOut(BaseModel):
    id: int
    customer_name: Optional[str] = None
    customer_phone: str
    delivery_address: str
    delivery_lat: float
    delivery_lon: float
    subtotal: float
    status: str
    payment_status: str  # created | paid | failed
    delivery_date: Optional[date] = None
    created_at: datetime
    items: list[OrderItemOut]


class DistributorOrderUpdate(BaseModel):
    status: OrderStatus


def _distributor_order_dto(
    o: Order, items: list[OrderItem], customer: Optional[User]
) -> DistributorOrderOut:
    name_parts = (
        [customer.first_name, customer.last_name] if customer else []
    )
    customer_name = " ".join(p for p in name_parts if p) or None
    return DistributorOrderOut(
        id=o.id,
        customer_name=customer_name,
        customer_phone=customer.phone if customer else "",
        delivery_address=o.delivery_address,
        delivery_lat=float(o.delivery_lat),
        delivery_lon=float(o.delivery_lon),
        subtotal=float(o.subtotal),
        status=o.status,
        payment_status=o.payment_status,
        delivery_date=o.delivery_date,
        created_at=_utc_aware(o.created_at),
        items=[
            OrderItemOut(
                master_item_id=i.master_item_id,
                name=i.name_snapshot,
                price=float(i.price_snapshot),
                quantity=i.quantity,
                line_total=float(i.line_total),
                weight_kg=(
                    float(i.weight_kg_snapshot)
                    if i.weight_kg_snapshot is not None
                    else None
                ),
            )
            for i in items
        ],
    )


@app.get("/distributor/orders", response_model=list[DistributorOrderOut])
def distributor_list_orders(
    status: Optional[OrderStatus] = None,
    user: User = Depends(distributor_required),
    db: Session = Depends(get_db),
) -> list[DistributorOrderOut]:
    q = db.query(Order).filter(
        Order.distributor_user_id == user.id, Order.payment_status == "paid"
    )
    if status:
        q = q.filter(Order.status == status)
    orders = q.order_by(Order.created_at.desc()).limit(200).all()
    out: list[DistributorOrderOut] = []
    # One query per order keeps the code simple; with limit=200 it's fine.
    # If this ever gets hot we can switch to a single joined fetch.
    for o in orders:
        items = (
            db.query(OrderItem)
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.id)
            .all()
        )
        customer = db.query(User).filter(User.id == o.user_id).first()
        out.append(_distributor_order_dto(o, items, customer))
    return out


@app.patch("/distributor/orders/{order_id}", response_model=DistributorOrderOut)
def distributor_update_order(
    order_id: int,
    body: DistributorOrderUpdate,
    user: User = Depends(distributor_required),
    db: Session = Depends(get_db),
) -> DistributorOrderOut:
    o = (
        db.query(Order)
        .filter(Order.id == order_id, Order.distributor_user_id == user.id)
        .first()
    )
    if not o:
        raise HTTPException(404, "Order not found.")
    allowed = _ORDER_TRANSITIONS.get(o.status, set())
    if body.status not in allowed:
        raise HTTPException(
            400,
            f"Can't move order from '{o.status}' to '{body.status}'.",
        )
    o.status = body.status
    db.commit()
    db.refresh(o)
    items = (
        db.query(OrderItem)
        .filter(OrderItem.order_id == o.id)
        .order_by(OrderItem.id)
        .all()
    )
    customer = db.query(User).filter(User.id == o.user_id).first()
    return _distributor_order_dto(o, items, customer)


# ============ Kiosk: shop ============
# Mirrors the distributor shop endpoints — no radius (customers come to the
# kiosk, not the other way round). Shop status / operation status semantics
# are identical (admin approves, owner toggles open/closed).
def kiosk_required(user: User = Depends(current_user)) -> User:
    if user.role != "kiosk":
        raise HTTPException(403, "Kiosk owner access required.")
    return user


class KioskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    location: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius: Optional[float] = None
    shop_status: str
    operation_status: str
    open_24h: bool = True
    opening_time: Optional[str] = None
    closing_time: Optional[str] = None
    open_days: Optional[list[int]] = None
    hours_label: Optional[str] = None


class KioskIn(BaseModel):
    name: str
    location: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius: Optional[float] = None
    open_24h: bool = True
    opening_time: Optional[str] = None
    closing_time: Optional[str] = None
    open_days: Optional[list[int]] = None


class KioskUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius: Optional[float] = None
    operation_status: Optional[OperationStatus] = None
    open_24h: Optional[bool] = None
    opening_time: Optional[str] = None
    closing_time: Optional[str] = None
    open_days: Optional[list[int]] = None


@app.get("/kiosk/shop", response_model=Optional[KioskOut])
def get_my_kiosk(
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> Optional[Kiosk]:
    return db.query(Kiosk).filter(Kiosk.user_id == user.id).first()


@app.put("/kiosk/shop", response_model=KioskOut)
def upsert_my_kiosk(
    body: KioskIn,
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> Kiosk:
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Kiosk name is required.")
    k = db.query(Kiosk).filter(Kiosk.user_id == user.id).first()
    if k is None:
        k = Kiosk(user_id=user.id)
        db.add(k)
    k.name = name
    k.location = (body.location or "").strip() or None
    k.address = (body.address or "").strip() or None
    k.lat = body.lat
    k.lon = body.lon
    k.radius = body.radius
    k.open_24h = body.open_24h
    k.open_days = _normalize_open_days(body.open_days)
    if body.open_24h:
        k.opening_time = None
        k.closing_time = None
    else:
        opening_time = _valid_hhmm(body.opening_time)
        closing_time = _valid_hhmm(body.closing_time)
        if not opening_time or not closing_time:
            raise HTTPException(400, "Opening and closing times are required.")
        k.opening_time = opening_time
        k.closing_time = closing_time
    # Editing kiosk details requires admin (re-)approval.
    k.shop_status = "inactive"
    k.operation_status = "closed"
    db.commit()
    db.refresh(k)
    return k


@app.patch("/kiosk/shop", response_model=KioskOut)
def patch_my_kiosk(
    body: KioskUpdate,
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> Kiosk:
    k = db.query(Kiosk).filter(Kiosk.user_id == user.id).first()
    if k is None:
        raise HTTPException(404, "Set up your kiosk first.")
    data = body.model_dump(exclude_unset=True)
    if "name" in data:
        name = (data.pop("name") or "").strip()
        if not name:
            raise HTTPException(400, "Kiosk name cannot be empty.")
        k.name = name
    if "operation_status" in data:
        op = data.pop("operation_status")
        k.operation_status = op if k.shop_status == "active" else "closed"
    if "open_24h" in data:
        k.open_24h = bool(data.pop("open_24h"))
        if k.open_24h:
            k.opening_time = None
            k.closing_time = None
    if "opening_time" in data:
        k.opening_time = _valid_hhmm(data.pop("opening_time"))
    if "closing_time" in data:
        k.closing_time = _valid_hhmm(data.pop("closing_time"))
    if "open_days" in data:
        k.open_days = _normalize_open_days(data.pop("open_days"))
    if not k.open_24h and (not k.opening_time or not k.closing_time):
        raise HTTPException(400, "Opening and closing times are required.")
    if "address" in data:
        k.address = (data.pop("address") or "").strip() or None
    for field, value in data.items():
        setattr(k, field, value)
    db.commit()
    db.refresh(k)
    return k


# ============ Kiosk: menu (inherited from master fish_and_chips) ============
# Kiosk is for dine-in pickup; only fish_and_chips items make sense here.
KIOSK_CATEGORIES = ("fish_and_chips",)


class KioskMenuRow(BaseModel):
    master_id: int
    name: str
    category: str
    description: Optional[str] = None
    image_url: Optional[str] = None
    master_price: float
    price: float
    is_available: bool


class KioskMenuUpdate(BaseModel):
    price: Optional[float] = None
    is_available: Optional[bool] = None


def _kiosk_row_from(master: MenuItem, override: Optional[KioskMenuItem]) -> KioskMenuRow:
    return KioskMenuRow(
        master_id=master.id,
        name=master.name,
        category=master.category,
        description=master.description,
        image_url=master.image_url,
        master_price=float(master.price),
        price=float(override.price) if override is not None else float(master.price),
        is_available=override.is_available if override is not None else True,
    )


@app.get("/kiosk/menu-items", response_model=list[KioskMenuRow])
def list_my_kiosk_menu(
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> list[KioskMenuRow]:
    masters = (
        db.query(MenuItem)
        .filter(
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category.in_(KIOSK_CATEGORIES),
        )
        .order_by(MenuItem.category, MenuItem.name)
        .all()
    )
    mine = {
        ki.master_item_id: ki
        for ki in db.query(KioskMenuItem)
        .filter(KioskMenuItem.user_id == user.id)
        .all()
    }
    return [_kiosk_row_from(m, mine.get(m.id)) for m in masters]


@app.patch("/kiosk/menu-items/{master_item_id}", response_model=KioskMenuRow)
def upsert_my_kiosk_menu_item(
    master_item_id: int,
    body: KioskMenuUpdate,
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> KioskMenuRow:
    master = (
        db.query(MenuItem)
        .filter(
            MenuItem.id == master_item_id,
            MenuItem.is_active == True,  # noqa: E712
            MenuItem.category.in_(KIOSK_CATEGORIES),
        )
        .first()
    )
    if not master:
        raise HTTPException(404, "Master menu item not found or inactive.")
    item = (
        db.query(KioskMenuItem)
        .filter(
            KioskMenuItem.user_id == user.id,
            KioskMenuItem.master_item_id == master_item_id,
        )
        .first()
    )
    if item is None:
        item = KioskMenuItem(
            user_id=user.id,
            master_item_id=master_item_id,
            price=master.price,
            is_available=True,
        )
        db.add(item)
    if body.price is not None:
        if body.price < 0:
            raise HTTPException(400, "Price must be zero or more.")
        item.price = body.price
    if body.is_available is not None:
        item.is_available = body.is_available
    db.commit()
    db.refresh(item)
    return _kiosk_row_from(master, item)


# ============ Kiosk: orders ============
# Same shape as distributor orders, scoped by Order.kiosk_user_id. Customer
# kiosk-pickup ordering isn't built yet so this list will be empty for now.
class KioskOrderOut(BaseModel):
    id: int
    customer_name: Optional[str] = None
    customer_phone: str
    subtotal: float
    status: str
    payment_status: str  # created | paid | failed
    # Expected-ready time for this dine-in pre-order (now + max prep).
    dining_at: Optional[datetime] = None
    created_at: datetime
    items: list[OrderItemOut]


class KioskOrderUpdate(BaseModel):
    status: OrderStatus


def _kiosk_order_dto(
    o: Order, items: list[OrderItem], customer: Optional[User]
) -> KioskOrderOut:
    name_parts = [customer.first_name, customer.last_name] if customer else []
    customer_name = " ".join(p for p in name_parts if p) or None
    return KioskOrderOut(
        id=o.id,
        customer_name=customer_name,
        customer_phone=customer.phone if customer else "",
        subtotal=float(o.subtotal),
        status=o.status,
        payment_status=o.payment_status,
        dining_at=_utc_aware(o.dining_at) if o.dining_at is not None else None,
        created_at=_utc_aware(o.created_at),
        items=[
            OrderItemOut(
                master_item_id=i.master_item_id,
                name=i.name_snapshot,
                price=float(i.price_snapshot),
                quantity=i.quantity,
                line_total=float(i.line_total),
                weight_kg=(
                    float(i.weight_kg_snapshot)
                    if i.weight_kg_snapshot is not None
                    else None
                ),
            )
            for i in items
        ],
    )


@app.get("/kiosk/orders", response_model=list[KioskOrderOut])
def kiosk_list_orders(
    status: Optional[OrderStatus] = None,
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> list[KioskOrderOut]:
    q = db.query(Order).filter(
        Order.kiosk_user_id == user.id, Order.payment_status == "paid"
    )
    if status:
        q = q.filter(Order.status == status)
    orders = q.order_by(Order.created_at.desc()).limit(200).all()
    out: list[KioskOrderOut] = []
    for o in orders:
        items = (
            db.query(OrderItem)
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.id)
            .all()
        )
        customer = db.query(User).filter(User.id == o.user_id).first()
        out.append(_kiosk_order_dto(o, items, customer))
    return out


@app.patch("/kiosk/orders/{order_id}", response_model=KioskOrderOut)
def kiosk_update_order(
    order_id: int,
    body: KioskOrderUpdate,
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> KioskOrderOut:
    o = (
        db.query(Order)
        .filter(Order.id == order_id, Order.kiosk_user_id == user.id)
        .first()
    )
    if not o:
        raise HTTPException(404, "Order not found.")
    allowed = _ORDER_TRANSITIONS.get(o.status, set())
    if body.status not in allowed:
        raise HTTPException(
            400, f"Can't move order from '{o.status}' to '{body.status}'."
        )
    o.status = body.status
    db.commit()
    db.refresh(o)
    items = (
        db.query(OrderItem)
        .filter(OrderItem.order_id == o.id)
        .order_by(OrderItem.id)
        .all()
    )
    customer = db.query(User).filter(User.id == o.user_id).first()
    return _kiosk_order_dto(o, items, customer)


# ============ Kiosk: coupons ============
@app.get("/kiosk/coupons", response_model=list[CouponOut])
def list_kiosk_coupons(
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> list[CouponOut]:
    coupons = db.query(Coupon).filter(Coupon.kiosk_user_id == user.id).order_by(Coupon.id.desc()).all()
    return coupons


@app.post("/kiosk/coupons", response_model=CouponOut, status_code=201)
def create_kiosk_coupon(
    body: CouponIn,
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> CouponOut:
    existing = db.query(Coupon).filter(Coupon.code == body.code.upper()).first()
    if existing:
        raise HTTPException(400, "Coupon code already exists.")
    coupon = Coupon(
        code=body.code.upper(),
        coupon_type=body.coupon_type,
        discount_type=body.discount_type,
        discount_value=body.discount_value,
        max_discount=body.max_discount,
        min_bill_amount=body.min_bill_amount,
        applicable_categories=body.applicable_categories,
        applicable_products=body.applicable_products,
        start_date=body.start_date,
        end_date=body.end_date,
        kiosk_user_id=user.id,
        is_active=body.is_active if body.is_active is not None else True,
    )
    db.add(coupon)
    db.commit()
    db.refresh(coupon)
    return coupon


@app.patch("/kiosk/coupons/{coupon_id}", response_model=CouponOut)
def update_kiosk_coupon(
    coupon_id: int,
    body: CouponIn,
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> CouponOut:
    coupon = db.query(Coupon).filter(Coupon.id == coupon_id, Coupon.kiosk_user_id == user.id).first()
    if not coupon:
        raise HTTPException(404, "Coupon not found or not owned by this kiosk.")
    
    if body.code.upper() != coupon.code:
        existing = db.query(Coupon).filter(Coupon.code == body.code.upper()).first()
        if existing:
            raise HTTPException(400, "Coupon code already exists.")
            
    coupon.code = body.code.upper()
    coupon.coupon_type = body.coupon_type
    coupon.discount_type = body.discount_type
    coupon.discount_value = body.discount_value
    coupon.max_discount = body.max_discount
    coupon.min_bill_amount = body.min_bill_amount
    coupon.applicable_categories = body.applicable_categories
    coupon.applicable_products = body.applicable_products
    coupon.start_date = body.start_date
    coupon.end_date = body.end_date
    if body.is_active is not None:
        coupon.is_active = body.is_active
    db.commit()
    db.refresh(coupon)
    return coupon


@app.delete("/kiosk/coupons/{coupon_id}", status_code=204)
def delete_kiosk_coupon(
    coupon_id: int,
    user: User = Depends(kiosk_required),
    db: Session = Depends(get_db),
) -> None:
    coupon = db.query(Coupon).filter(Coupon.id == coupon_id, Coupon.kiosk_user_id == user.id).first()
    if not coupon:
        raise HTTPException(404, "Coupon not found or not owned by this kiosk.")
    db.delete(coupon)
    db.commit()


# ============ Customer: coupons list ============
@app.get("/customer/coupons", response_model=list[CouponOut])
def list_customer_coupons(
    is_kiosk: bool = False,
    shop_id: Optional[int] = None,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    user: User = Depends(customer_required),  # noqa: ARG001
    db: Session = Depends(get_db),
) -> list[CouponOut]:
    today = datetime.now(timezone.utc).astimezone(_IST).date()
    
    # 1. Query active admin/global coupons
    admin_coupons = (
        db.query(Coupon)
        .filter(
            Coupon.kiosk_user_id == None,
            Coupon.is_active == True,
            Coupon.start_date <= today,
            Coupon.end_date >= today,
        )
        .all()
    )
    
    # 2. Check if we should only return admin coupons
    # Condition: "if the admin added a coupon then dont show kiosk coupons if not show kisoks coupon"
    if len(admin_coupons) > 0:
        return admin_coupons
        
    # 3. If there are no active admin coupons, check if we can query kiosk coupons
    if is_kiosk:
        kiosk_user_id = None
        if shop_id is not None:
            k = db.query(Kiosk).filter(Kiosk.id == shop_id).first()
            if k:
                kiosk_user_id = k.user_id
        elif lat is not None and lon is not None:
            hit = _closest_covering_kiosk(lat, lon, db)
            if hit is not None:
                _dist, k = hit
                kiosk_user_id = k.user_id
                
        if kiosk_user_id is not None:
            kiosk_coupons = (
                db.query(Coupon)
                .filter(
                    Coupon.kiosk_user_id == kiosk_user_id,
                    Coupon.is_active == True,
                    Coupon.start_date <= today,
                    Coupon.end_date >= today,
                )
                .all()
            )
            return kiosk_coupons
            
    return []


# ============ Customer: coupons validate ============
@app.post("/customer/coupons/validate", response_model=CouponValidateOut)
def validate_coupon_endpoint(
    body: CouponValidateIn,
    user: User = Depends(customer_required),
    db: Session = Depends(get_db),
) -> CouponValidateOut:
    coupon = db.query(Coupon).filter(Coupon.code == body.coupon_code.upper(), Coupon.is_active == True).first()
    if not coupon:
        raise HTTPException(400, "Invalid coupon code.")
        
    if body.is_kiosk:
        if body.lat is None or body.lon is None:
            raise HTTPException(400, "lat and lon are required for kiosk validation.")
        k, subtotal, max_prep, lines = _build_kiosk_draft(body.lat, body.lon, body.items, db)
        discount = _validate_coupon_for_lines(coupon, user, subtotal, lines, is_kiosk_checkout=True, kiosk_user_id=k.user_id, db=db)
    else:
        if body.address_id is None:
            raise HTTPException(400, "address_id is required for order validation.")
        order_body = OrderIn(
            address_id=body.address_id,
            shop_id=body.shop_id,
            items=body.items
        )
        shop, addr, subtotal, lines, delivery_date = _build_order_draft(order_body, user, db)
        discount = _validate_coupon_for_lines(coupon, user, subtotal, lines, is_kiosk_checkout=False, kiosk_user_id=None, db=db)
        
    return CouponValidateOut(
        coupon_code=coupon.code,
        discount_amount=discount,
        subtotal=subtotal,
        final_amount=round(subtotal - discount, 2)
    )


# ============ Admin: kiosk activation ============
# Same pattern as /admin/shops — admin approves kiosks before they can open.
class AdminKioskOut(BaseModel):
    id: int
    user_id: int
    owner_name: Optional[str] = None
    owner_phone: str
    name: str
    location: Optional[str] = None
    address: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    radius: Optional[float] = None
    shop_status: str
    operation_status: str
    open_24h: bool = True
    opening_time: Optional[str] = None
    closing_time: Optional[str] = None
    open_days: Optional[list[int]] = None
    hours_label: Optional[str] = None
    is_open_now: bool = False


class AdminKioskUpdate(BaseModel):
    shop_status: Optional[Literal["active", "inactive"]] = None
    operation_status: Optional[OperationStatus] = None


def _admin_kiosk_dto(k: Kiosk, user: Optional[User]) -> AdminKioskOut:
    parts = [user.first_name, user.last_name] if user else []
    owner_name = " ".join(p for p in parts if p) or None
    return AdminKioskOut(
        id=k.id,
        user_id=k.user_id,
        owner_name=owner_name,
        owner_phone=user.phone if user else "",
        name=k.name,
        location=k.location,
        address=k.address,
        lat=float(k.lat) if k.lat is not None else None,
        lon=float(k.lon) if k.lon is not None else None,
        radius=float(k.radius) if k.radius is not None else None,
        shop_status=k.shop_status,
        operation_status=k.operation_status,
        open_24h=k.open_24h,
        opening_time=k.opening_time,
        closing_time=k.closing_time,
        open_days=_kiosk_open_days(k),
        hours_label=_kiosk_hours_label(k),
        is_open_now=_effective_kiosk_operation_status(k) == "open",
    )


@app.get("/admin/kiosks", response_model=list[AdminKioskOut])
def admin_list_kiosks(
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Kiosk, User)
        .join(User, User.id == Kiosk.user_id)
        .order_by(Kiosk.shop_status.asc(), Kiosk.name.asc())
        .all()
    )
    return [_admin_kiosk_dto(k, u) for k, u in rows]


@app.patch("/admin/kiosks/{kiosk_id}", response_model=AdminKioskOut)
def admin_update_kiosk_status(
    kiosk_id: int,
    body: AdminKioskUpdate,
    _: User = Depends(admin_required),
    db: Session = Depends(get_db),
):
    k = db.query(Kiosk).filter(Kiosk.id == kiosk_id).first()
    if not k:
        raise HTTPException(404, "Kiosk not found.")
    if body.shop_status is None and body.operation_status is None:
        raise HTTPException(400, "Send shop_status or operation_status.")
    if body.shop_status is not None:
        k.shop_status = body.shop_status
    if body.operation_status is not None:
        if body.operation_status == "open" and k.shop_status != "active":
            raise HTTPException(400, "Activate this kiosk before opening it.")
        k.operation_status = body.operation_status
    if k.shop_status == "inactive":
        k.operation_status = "closed"
    db.commit()
    db.refresh(k)
    user = db.query(User).filter(User.id == k.user_id).first()
    return _admin_kiosk_dto(k, user)


# ============ Frontend (React SPA) ============
# Serves the built Vite app from frontend/dist. API routes above (/auth/*,
# /health, /docs) are registered first, so they take precedence over the
# catch-all. The backend/ folder is never under dist, so it stays unreachable.
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

# Several SPA client routes share a path with a real API endpoint
# (e.g. /distributor/orders, /admin/shops, /admin/kiosks). Those API routes are
# registered first, so a hard refresh or a typed/bookmarked URL on such a page
# hits the API — and a plain browser navigation carries no bearer token, so it
# 401s instead of loading the app. Browser navigations arrive as GET with
# "text/html" in Accept; the app's own fetch()/XHR calls send Accept: */*. So we
# intercept HTML navigations here and serve the SPA shell, while data calls fall
# straight through to the real routes below.
_SPA_BYPASS_PREFIXES = ("/assets/", "/media/", "/uploaded-images/")
_SPA_BYPASS_EXACT = {"/docs", "/redoc", "/openapi.json"}


@app.middleware("http")
async def _spa_html_fallback(request: Request, call_next):
    if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
        path = request.url.path
        if path not in _SPA_BYPASS_EXACT and not path.startswith(_SPA_BYPASS_PREFIXES):
            # Serve a real file if one exists at this path (e.g. a bookmarked
            # /logo.jpg); otherwise the SPA shell so client-side routing runs.
            if path != "/":
                candidate = (FRONTEND_DIST / path.lstrip("/")).resolve()
                if candidate.is_file() and FRONTEND_DIST.resolve() in candidate.parents:
                    return FileResponse(candidate)
            index = FRONTEND_DIST / "index.html"
            if index.is_file():
                return FileResponse(
                    index,
                    media_type="text/html",
                    headers={"Cache-Control": "no-store"},
                )
    return await call_next(request)


if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")


@app.get("/{full_path:path}", include_in_schema=False)
def spa(full_path: str) -> FileResponse:
    # Serve a real static file (logo.jpg, favicon, …) if it exists; otherwise
    # fall back to index.html so client-side routes work on refresh.
    if full_path:
        candidate = (FRONTEND_DIST / full_path).resolve()
        # guard against path traversal (e.g. ../backend/.env)
        if candidate.is_file() and FRONTEND_DIST.resolve() in candidate.parents:
            return FileResponse(candidate)
    index = FRONTEND_DIST / "index.html"
    if not index.is_file():
        raise HTTPException(503, "Frontend not built. Run `npm run build` in frontend/.")
    # Never cache the HTML shell, so a plain refresh always loads HTML that
    # references the current (hashed) asset filenames. The /assets bundles are
    # content-hashed and safe to cache forever.
    return FileResponse(
        index, media_type="text/html", headers={"Cache-Control": "no-store"}
    )
