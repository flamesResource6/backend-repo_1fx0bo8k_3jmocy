import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext
from bson.objectid import ObjectId
import smtplib
from email.message import EmailMessage

from database import db, create_document, get_documents
from schemas import (
    User as UserSchema,
    Service as ServiceSchema,
    Doctor as DoctorSchema,
    Appointment as AppointmentSchema,
    Message as MessageSchema,
    Offer as OfferSchema,
    Payment as PaymentSchema,
    NotificationToken as NotificationTokenSchema,
)

# App setup
app = FastAPI(title="DermaCare+ API", version="0.4.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "43200"))  # 30 days

# Email (SMTP)
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER or "no-reply@dermacare.local")
ENV_NAME = os.getenv("ENV", "development")

# Verification limits
VERIFY_MAX_ATTEMPTS = int(os.getenv("VERIFY_MAX_ATTEMPTS", "5"))
VERIFY_LOCK_MINUTES = int(os.getenv("VERIFY_LOCK_MINUTES", "15"))
VERIFY_RESEND_COOLDOWN_SECONDS = int(os.getenv("VERIFY_RESEND_COOLDOWN_SECONDS", "60"))

# Payments (Stripe)
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE")
DEFAULT_CURRENCY = os.getenv("DEFAULT_CURRENCY", "SAR")

try:
    import stripe
    if STRIPE_SECRET_KEY:
        stripe.api_key = STRIPE_SECRET_KEY
except Exception:
    stripe = None


# Helpers
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def create_token(sub: str, role: str) -> str:
    payload = {
        "sub": sub,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=["HS256"])
        user = db["user"].find_one({"email": payload.get("sub")})
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")
        user["_id"] = str(user["_id"])  # stringify id
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def _send_email(to_email: str, subject: str, body_text: str, body_html: Optional[str] = None) -> bool:
    """Send an email via SMTP. Returns True on success, False otherwise. In development with no SMTP env, logs to console."""
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        # Dev fallback: log email so flows are testable
        print("\n=== EMAIL (DEV MODE) ===")
        print(f"To: {to_email}")
        print(f"Subject: {subject}")
        print(body_text)
        if body_html:
            print("-- HTML --\n" + body_html)
        print("=== END EMAIL ===\n")
        return True
    try:
        msg = EmailMessage()
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body_text)
        if body_html:
            msg.add_alternative(body_html, subtype="html")
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email send error: {e}")
        return False


# Models for requests
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None
    phone: Optional[str] = None


class RegisterResponse(BaseModel):
    status: str
    message: str
    next_step: str
    email: EmailStr


class VerifyStartRequest(BaseModel):
    email: EmailStr


class VerifyConfirmRequest(BaseModel):
    email: EmailStr
    code: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ServiceCreate(ServiceSchema):
    pass


class ServiceUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    duration_minutes: Optional[int] = None
    price: Optional[float] = None
    featured: Optional[bool] = None


class AppointmentCreate(BaseModel):
    service_id: str
    date: str  # YYYY-MM-DD
    time: str  # HH:mm
    mode: str = "in_clinic"
    doctor_id: Optional[str] = None
    notes: Optional[str] = None


class AppointmentStatusUpdate(BaseModel):
    status: str


class MessageCreate(BaseModel):
    doctor_id: str
    text: Optional[str] = None
    image_url: Optional[str] = None
    audio_url: Optional[str] = None


class NotificationTokenCreate(BaseModel):
    platform: str
    token: str
    locale: Optional[str] = None
    tz: Optional[str] = None


# Routes
@app.get("/")
def root():
    return {"name": "DermaCare+ API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# Auth
@app.post("/auth/register", response_model=RegisterResponse)
def register(payload: RegisterRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing and existing.get("is_verified"):
        raise HTTPException(status_code=400, detail="Email already registered")

    code = f"{int(datetime.now().timestamp()) % 1000000:06d}"  # 6-digit code
    expires = datetime.now(timezone.utc) + timedelta(minutes=15)
    now = datetime.now(timezone.utc)

    if existing:
        # Update existing unverified user
        db["user"].update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "password_hash": pwd_context.hash(payload.password),
                "name": payload.name,
                "phone": payload.phone,
                "verification_code": code,
                "verification_expires": expires,
                "is_verified": False,
                "verification_attempts": 0,
                "verification_locked_until": None,
                "last_verification_sent_at": now,
                "updated_at": now
            }}
        )
    else:
        user = UserSchema(
            email=payload.email,
            password_hash=pwd_context.hash(payload.password),
            name=payload.name,
            phone=payload.phone,
            is_verified=False,
            verification_code=code,
            verification_expires=expires,
            verification_attempts=0,
            last_verification_sent_at=now,
        )
        create_document("user", user)

    subject = "Your DermaCare+ verification code"
    text = f"Your verification code is: {code}. It expires in 15 minutes."
    html = f"""
    <div style='font-family:Inter,Segoe UI,Arial,sans-serif'>
      <h2>Verify your email</h2>
      <p>Your verification code is:</p>
      <p style='font-size:24px;font-weight:700;letter-spacing:3px'>{code}</p>
      <p>This code expires in 15 minutes.</p>
    </div>
    """
    _send_email(payload.email, subject, text, html)

    # In development, expose hint to help testers
    hint = " (code sent to email)"
    if ENV_NAME.startswith("dev") or ENV_NAME.startswith("local"):
        hint = f" (dev hint: {code})"

    return RegisterResponse(
        status="pending_verification",
        message="We sent a 6‑digit code to your email." + hint,
        next_step="verify_code",
        email=payload.email,
    )


@app.post("/auth/verify/start")
def verify_start(payload: VerifyStartRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    if user.get("is_verified"):
        return {"status": "already_verified"}

    now = datetime.now(timezone.utc)
    last_sent = user.get("last_verification_sent_at")
    if isinstance(last_sent, str):
        try:
            last_sent = datetime.fromisoformat(last_sent)
        except Exception:
            last_sent = None
    if last_sent and last_sent.tzinfo is None:
        last_sent = last_sent.replace(tzinfo=timezone.utc)

    if last_sent and (now - last_sent).total_seconds() < VERIFY_RESEND_COOLDOWN_SECONDS:
        remaining = int(VERIFY_RESEND_COOLDOWN_SECONDS - (now - last_sent).total_seconds())
        raise HTTPException(status_code=429, detail=f"Please wait {remaining}s before requesting another code")

    code = f"{int(datetime.now().timestamp()) % 1000000:06d}"
    expires = now + timedelta(minutes=15)
    db["user"].update_one(
        {"_id": user["_id"]},
        {"$set": {
            "verification_code": code,
            "verification_expires": expires,
            "last_verification_sent_at": now,
            "updated_at": now
        }}
    )
    subject = "Your DermaCare+ verification code"
    text = f"Your verification code is: {code}. It expires in 15 minutes."
    html = f"<p>Your code: <b>{code}</b></p>"
    _send_email(payload.email, subject, text, html)
    return {"status": "sent"}


@app.post("/auth/verify/confirm", response_model=TokenResponse)
def verify_confirm(payload: VerifyConfirmRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")
    if user.get("is_verified"):
        # Issue token directly
        token = create_token(payload.email, role=user.get("role", "user"))
        return TokenResponse(access_token=token)

    # Lock check
    now = datetime.now(timezone.utc)
    locked_until = user.get("verification_locked_until")
    if isinstance(locked_until, str):
        try:
            locked_until = datetime.fromisoformat(locked_until)
        except Exception:
            locked_until = None
    if locked_until and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    if locked_until and now < locked_until:
        seconds = int((locked_until - now).total_seconds())
        raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {seconds}s")

    code = user.get("verification_code")
    exp = user.get("verification_expires")
    if not code or not exp:
        raise HTTPException(status_code=400, detail="No verification in progress")

    if isinstance(exp, str):
        try:
            exp = datetime.fromisoformat(exp)
        except Exception:
            pass
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)

    if now > exp:
        # Expired; reset attempts to allow resend flow
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"verification_attempts": 0}})
        raise HTTPException(status_code=400, detail="Code expired")

    if payload.code != code:
        attempts = int(user.get("verification_attempts") or 0) + 1
        updates = {"verification_attempts": attempts, "last_verification_attempt_at": now}
        # Lock if exceeded
        if attempts >= VERIFY_MAX_ATTEMPTS:
            updates["verification_locked_until"] = now + timedelta(minutes=VERIFY_LOCK_MINUTES)
            updates["verification_attempts"] = 0
        db["user"].update_one({"_id": user["_id"]}, {"$set": updates})
        remaining = max(0, VERIFY_MAX_ATTEMPTS - int(user.get("verification_attempts") or 0) - 1)
        raise HTTPException(status_code=400, detail=f"Invalid code. Attempts left: {remaining}")

    # Success
    db["user"].update_one(
        {"_id": user["_id"]},
        {"$set": {
            "is_verified": True,
            "verification_code": None,
            "verification_expires": None,
            "verification_attempts": 0,
            "verification_locked_until": None,
            "updated_at": now
        }}
    )

    token = create_token(payload.email, role=user.get("role", "user"))
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)

def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not pwd_context.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_verified"):
        raise HTTPException(status_code=403, detail="Email not verified")
    token = create_token(payload.email, role=user.get("role", "user"))
    return TokenResponse(access_token=token)


@app.get("/me")

def me(current=Depends(get_current_user)):
    current.pop("password_hash", None)
    return current


# Notification tokens
@app.post("/notifications/token")

def save_notification_token(payload: NotificationTokenCreate, current=Depends(get_current_user)):
    doc = NotificationTokenSchema(
        user_id=str(current["_id"]),
        platform=payload.platform,
        token=payload.token,
        locale=payload.locale,
        tz=payload.tz,
    )
    nid = create_document("notificationtoken", doc)
    return {"id": nid}


# Services
@app.get("/services")

def list_services():
    items = get_documents("service")
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.post("/services")

def create_service(service: ServiceCreate, current=Depends(get_current_user)):
    if current.get("role") not in ("admin", "doctor"):
        raise HTTPException(status_code=403, detail="Not authorized")
    sid = create_document("service", service)
    return {"id": sid}


@app.put("/services/{service_id}")

def update_service(service_id: str, payload: ServiceUpdate, current=Depends(get_current_user)):
    if current.get("role") not in ("admin", "doctor"):
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        oid = ObjectId(service_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return {"updated": 0}
    updates["updated_at"] = datetime.now(timezone.utc)
    res = db["service"].update_one({"_id": oid}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"updated": res.modified_count}


@app.delete("/services/{service_id}")

def delete_service(service_id: str, current=Depends(get_current_user)):
    if current.get("role") not in ("admin", "doctor"):
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        oid = ObjectId(service_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    res = db["service"].delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"deleted": 1}


# Doctors
@app.get("/doctors")

def list_doctors():
    items = get_documents("doctor")
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.post("/doctors")

def create_doctor(doctor: DoctorSchema, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    did = create_document("doctor", doctor)
    return {"id": did}


# Offers
@app.get("/offers")

def list_offers():
    items = get_documents("offer")
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.post("/offers")

def create_offer(offer: OfferSchema, current=Depends(get_current_user)):
    if current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    oid = create_document("offer", offer)
    return {"id": oid}


# Appointments
@app.post("/appointments")

def create_appointment(payload: AppointmentCreate, current=Depends(get_current_user)):
    appt = AppointmentSchema(
        user_id=str(current["_id"]),
        doctor_id=payload.doctor_id,
        service_id=payload.service_id,
        date=payload.date,
        time=payload.time,
        mode=payload.mode,
        notes=payload.notes,
    )
    aid = create_document("appointment", appt)
    return {"id": aid, "status": "pending"}


@app.get("/appointments/my")

def my_appointments(current=Depends(get_current_user)):
    items = get_documents("appointment", {"user_id": str(current["_id"])})
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.get("/appointments")

def list_appointments(current=Depends(get_current_user)):
    if current.get("role") not in ("admin", "doctor"):
        raise HTTPException(status_code=403, detail="Not authorized")
    items = get_documents("appointment")
    for it in items:
        it["_id"] = str(it["_id"])
    return items


@app.put("/appointments/{appointment_id}/status")

def update_appointment_status(appointment_id: str, payload: AppointmentStatusUpdate, current=Depends(get_current_user)):
    if current.get("role") not in ("admin", "doctor"):
        raise HTTPException(status_code=403, detail="Not authorized")
    try:
        oid = ObjectId(appointment_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    res = db["appointment"].update_one({"_id": oid}, {"$set": {"status": payload.status, "updated_at": datetime.now(timezone.utc)}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"updated": res.modified_count}


# Messages (simple chat)
@app.get("/messages/thread")

def get_thread(user_id: str, doctor_id: str, current=Depends(get_current_user)):
    # Allow user or doctor/admin to view
    if current.get("role") == "user" and user_id != str(current["_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    items = get_documents("message", {"user_id": user_id, "doctor_id": doctor_id})
    for it in items:
        it["_id"] = str(it["_id"])
    return sorted(items, key=lambda x: x.get("created_at", datetime.now()))


@app.post("/messages")

def send_message(payload: MessageCreate, current=Depends(get_current_user)):
    sender = "user" if current.get("role") == "user" else "doctor"
    msg = MessageSchema(
        user_id=str(current["_id"]) if sender == "user" else "",
        doctor_id=payload.doctor_id,
        sender=sender,
        text=payload.text,
        image_url=payload.image_url,
        audio_url=payload.audio_url,
        created_at=datetime.now(timezone.utc),
    )
    mid = create_document("message", msg)
    return {"id": mid}


# Payments
class PaymentInit(BaseModel):
    appointment_id: str
    amount: float
    currency: str | None = None


@app.post("/payments/init")

def init_payment(payload: PaymentInit, current=Depends(get_current_user)):
    currency = payload.currency or DEFAULT_CURRENCY
    payment = PaymentSchema(
        user_id=str(current["_id"]),
        appointment_id=payload.appointment_id,
        amount=payload.amount,
        currency=currency,
        provider="stripe",
        status="initiated",
        reference=f"PMT-{int(datetime.now().timestamp())}",
    )
    pid = create_document("payment", payment)

    client_secret = "test_client_secret"
    if stripe and STRIPE_SECRET_KEY:
        try:
            intent = stripe.PaymentIntent.create(
                amount=int(round(payload.amount * 100)),
                currency=currency.lower(),
                metadata={
                    "appointment_id": payload.appointment_id,
                    "user_id": str(current["_id"]),
                    "payment_id": pid,
                },
                automatic_payment_methods={"enabled": True},
            )
            client_secret = intent.get("client_secret")
        except Exception:
            client_secret = "test_client_secret"
    return {"id": pid, "status": "initiated", "client_secret": client_secret}


# Webhook endpoint (Stripe)
class StripeEvent(BaseModel):
    id: Optional[str] = None
    type: Optional[str] = None
    data: Optional[dict] = None


@app.post("/payments/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    event = None
    if stripe and webhook_secret:
        try:
            event = stripe.Webhook.construct_event(
                payload=payload, sig_header=sig_header, secret=webhook_secret
            )
        except Exception:
            return {"received": False}
    else:
        # In dev without real webhook secret, accept payload
        try:
            import json
            event = json.loads(payload.decode("utf-8"))
        except Exception:
            return {"received": False}

    # Normalize event data
    if isinstance(event, dict):
        event_type = event.get("type")
        data_obj = (event.get("data") or {}).get("object", {})
    else:
        event_type = getattr(event, "type", None)
        data = getattr(event, "data", None)
        data_obj = getattr(data, "object", {}) if data else {}

    payment_id = None
    metadata = data_obj.get("metadata") or {}
    payment_id = metadata.get("payment_id")

    if event_type in ("payment_intent.succeeded", "charge.succeeded") and payment_id:
        try:
            db["payment"].update_one({"_id": ObjectId(payment_id)}, {"$set": {"status": "succeeded", "updated_at": datetime.now(timezone.utc)}})
        except Exception:
            pass
    elif event_type in ("payment_intent.payment_failed", "charge.failed") and payment_id:
        try:
            db["payment"].update_one({"_id": ObjectId(payment_id)}, {"$set": {"status": "failed", "updated_at": datetime.now(timezone.utc)}})
        except Exception:
            pass

    return {"received": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
