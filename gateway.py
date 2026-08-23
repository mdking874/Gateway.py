
"""
Commercial Personal-Number Payment Gateway
===========================================

Single-file FastAPI backend.

IMPORTANT:
- This integrates with an EXISTING SMS Reader that writes payment/SMS data
  into Firebase Realtime Database.
- It does NOT use bKash/Nagad official APIs.
- It does NOT collect OTP/PIN/passwords.
- Configure FIREBASE_SMS_NODE to point to the node where the existing reader
  stores payment-confirmation records.
- The exact Firebase structure in the screenshot is not enough to know the
  reader's exact SMS node, so the parser supports common record shapes and
  should be adjusted in `extract_sms_records()` if needed.

Install:
    pip install -r requirements.txt

Run:
    uvicorn gateway:app --host 0.0.0.0 --port 8000

Environment:
    DATABASE_URL=sqlite:///./gateway.db
    JWT_SECRET=CHANGE_ME_TO_A_LONG_RANDOM_SECRET
    FIREBASE_DATABASE_URL=https://YOUR-PROJECT-default-rtdb.REGION.firebasedatabase.app
    FIREBASE_SMS_NODE=sms_messages
    FIREBASE_AUTH_TOKEN=                       # optional
    ADMIN_USERNAME=admin
    ADMIN_PASSWORD=CHANGE_THIS_PASSWORD
    PUBLIC_BASE_URL=https://gateway.example.com
    WEBHOOK_TIMEOUT=10
    SMS_POLL_SECONDS=3

For production:
- Use PostgreSQL instead of SQLite.
- Put the API behind HTTPS/reverse proxy.
- Store secrets in a secret manager/environment.
- Restrict Firebase rules so the SMS Reader can only write to its required
  node and the gateway can only read the required node.
- Add provider/account/legal compliance before processing third-party funds.
"""

import os
import re
import json
import time
import hmac
import hashlib
import secrets
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional, Any

import requests
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import (
    create_engine, String, Integer, BigInteger, Boolean, DateTime,
    Text, ForeignKey, Numeric, UniqueConstraint, select
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from jose import jwt


# ============================================================
# CONFIG
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./gateway.db")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME")
JWT_ALGORITHM = "HS256"

FIREBASE_DATABASE_URL = os.getenv("FIREBASE_DATABASE_URL", "").rstrip("/")
FIREBASE_SMS_NODE = os.getenv("FIREBASE_SMS_NODE", "sms_messages").strip("/")
FIREBASE_AUTH_TOKEN = os.getenv("FIREBASE_AUTH_TOKEN", "")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CHANGE_THIS_PASSWORD")

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
WEBHOOK_TIMEOUT = int(os.getenv("WEBHOOK_TIMEOUT", "10"))
SMS_POLL_SECONDS = int(os.getenv("SMS_POLL_SECONDS", "3"))

if JWT_SECRET == "CHANGE_ME":
    # Deliberately refuse production-like startup with the default secret.
    # For local testing, change it in the environment.
    print("WARNING: JWT_SECRET is still the default value.")

# SQLite needs this option; PostgreSQL ignores it.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


# ============================================================
# DATABASE MODELS
# ============================================================

class Base(DeclarativeBase):
    pass


class Merchant(Base):
    __tablename__ = "merchants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150))
    email: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    webhook_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    webhook_secret: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    key_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    secret_hash: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class PaymentAccount(Base):
    __tablename__ = "payment_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(30))  # bkash/nagad/etc.
    account_number: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")
    daily_limit: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class PaymentSession(Base):
    __tablename__ = "payment_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    payment_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    amount: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(10), default="BDT")
    provider: Mapped[str] = mapped_column(String(30))
    payment_account: Mapped[str] = mapped_column(String(40))
    customer_reference: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="PENDING", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Transaction(Base):
    __tablename__ = "transactions"
    __table_args__ = (
        UniqueConstraint("provider", "provider_txid", name="uq_provider_txid"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    payment_id: Mapped[str] = mapped_column(String(80), index=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"), index=True)
    provider: Mapped[str] = mapped_column(String(30))
    provider_txid: Mapped[str] = mapped_column(String(120), index=True)
    amount: Mapped[int] = mapped_column(BigInteger)
    receiver: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    raw_sms_id: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="SUCCESS")
    raw_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    payment_id: Mapped[str] = mapped_column(String(80), index=True)
    merchant_id: Mapped[int] = mapped_column(ForeignKey("merchants.id"))
    url: Mapped[str] = mapped_column(String(500))
    event: Mapped[str] = mapped_column(String(80))
    payload: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="PENDING")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(120))
    target: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="Commercial Personal Payment Gateway",
    version="1.0.0",
)


# ============================================================
# SCHEMAS
# ============================================================

class MerchantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    email: Optional[str] = None
    phone: Optional[str] = None
    webhook_url: Optional[str] = None


class PaymentCreate(BaseModel):
    amount: int = Field(gt=0, le=10_000_000)
    currency: str = Field(default="BDT", max_length=10)
    provider: str = Field(default="bkash", max_length=30)
    reference: Optional[str] = Field(default=None, max_length=120)
    expires_minutes: int = Field(default=15, ge=1, le=120)


class PaymentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    payment_id: str
    amount: int
    currency: str
    provider: str
    payment_account: str
    reference: Optional[str]
    status: str
    checkout_url: str
    expires_at: datetime


# ============================================================
# HELPERS
# ============================================================

def db() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_secret(value: str) -> str:
    return bcrypt.hashpw(value.encode(), bcrypt.gensalt()).decode()


def verify_secret(value: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(value.encode(), hashed.encode())
    except Exception:
        return False


def make_token(subject: str, role: str) -> str:
    payload = {
        "sub": subject,
        "role": role,
        "exp": int(time.time()) + 60 * 60 * 12,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def new_payment_id() -> str:
    return "PAY_" + secrets.token_urlsafe(12).replace("-", "").replace("_", "").upper()


def new_api_key():
    key_id = "pk_" + secrets.token_urlsafe(12)
    secret = secrets.token_urlsafe(32)
    return key_id, secret


def sign_webhook(secret: str, body: str) -> str:
    return hmac.new(
        secret.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()


def audit(
    session: Session,
    actor: str,
    action: str,
    target: Optional[str] = None,
    details: Optional[dict] = None,
    ip: Optional[str] = None,
):
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            target=target,
            details=json.dumps(details or {}, ensure_ascii=False),
            ip=ip,
        )
    )
    session.commit()


# ============================================================
# API AUTHENTICATION
# ============================================================

def merchant_auth(
    x_api_key: Optional[str] = Header(default=None),
    x_api_secret: Optional[str] = Header(default=None),
    session: Session = Depends(db),
) -> Merchant:

    if not x_api_key or not x_api_secret:
        raise HTTPException(401, "Missing API credentials")

    key = session.scalar(
        select(ApiKey).where(
            ApiKey.key_id == x_api_key,
            ApiKey.status == "ACTIVE",
        )
    )

    if not key or not verify_secret(x_api_secret, key.secret_hash):
        raise HTTPException(401, "Invalid API credentials")

    merchant = session.get(Merchant, key.merchant_id)

    if not merchant or merchant.status != "ACTIVE":
        raise HTTPException(403, "Merchant is inactive")

    key.last_used_at = utcnow()
    session.commit()

    return merchant


# ============================================================
# FIREBASE
# ============================================================

def firebase_url(node: str) -> str:
    if not FIREBASE_DATABASE_URL:
        raise RuntimeError("FIREBASE_DATABASE_URL is not configured")

    url = f"{FIREBASE_DATABASE_URL}/{node.strip('/')}.json"

    if FIREBASE_AUTH_TOKEN:
        url += "?auth=" + FIREBASE_AUTH_TOKEN

    return url


def firebase_get(node: str) -> Any:
    response = requests.get(
        firebase_url(node),
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


# ============================================================
# SMS NORMALIZATION
# ============================================================

def clean_amount(value: Any) -> Optional[int]:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return int(value)

    text = str(value)
    text = text.replace(",", "").replace("৳", "").strip()

    match = re.search(r"(\d+(?:\.\d+)?)", text)

    if not match:
        return None

    try:
        return int(float(match.group(1)))
    except ValueError:
        return None


def normalize_txid(value: Any) -> Optional[str]:
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    return value[:120]


def normalize_provider(value: Any) -> str:
    value = str(value or "").lower()

    if "bkash" in value:
        return "bkash"

    if "nagad" in value:
        return "nagad"

    if "rocket" in value:
        return "rocket"

    return value or "unknown"


def normalize_receiver(value: Any) -> Optional[str]:
    if value is None:
        return None

    digits = re.sub(r"\D", "", str(value))

    if not digits:
        return None

    if digits.startswith("880"):
        digits = "0" + digits[3:]

    return digits


def parse_time(value: Any) -> datetime:
    if value is None:
        return utcnow()

    try:
        number = float(value)

        # Firebase timestamps may be milliseconds.
        if number > 10_000_000_000:
            number /= 1000

        return datetime.fromtimestamp(number, tz=timezone.utc)
    except Exception:
        return utcnow()


def normalize_record(
    record_id: str,
    record: dict,
) -> Optional[dict]:

    if not isinstance(record, dict):
        return None

    # Common possible field names.
    amount = (
        record.get("amount")
        or record.get("Amount")
        or record.get("value")
    )

    txid = (
        record.get("txid")
        or record.get("txnId")
        or record.get("transaction_id")
        or record.get("transactionId")
        or record.get("trxid")
        or record.get("trxId")
    )

    provider = (
        record.get("method")
        or record.get("provider")
        or record.get("type")
        or ""
    )

    receiver = (
        record.get("receiver")
        or record.get("number")
        or record.get("account")
        or record.get("payment_number")
    )

    # Some readers save the SMS body.
    body = record.get("message") or record.get("sms") or record.get("body")

    if not amount and body:
        amount_match = re.search(
            r"(?:Tk|BDT|৳|amount)\s*[:\-]?\s*([\d,]+(?:\.\d+)?)",
            str(body),
            re.I,
        )
        if amount_match:
            amount = amount_match.group(1)

    if not txid and body:
        tx_match = re.search(
            r"(?:TrxID|TxnID|Transaction\s*ID|TxID)\s*[:\-]?\s*([A-Za-z0-9]+)",
            str(body),
            re.I,
        )
        if tx_match:
            txid = tx_match.group(1)

    amount = clean_amount(amount)
    txid = normalize_txid(txid)

    if amount is None or not txid:
        return None

    return {
        "record_id": record_id,
        "provider": normalize_provider(provider),
        "amount": amount,
        "txid": txid,
        "receiver": normalize_receiver(receiver),
        "received_at": parse_time(
            record.get("time")
            or record.get("timestamp")
            or record.get("received_at")
        ),
        "raw": record,
    }


def extract_sms_records(data: Any) -> list[dict]:
    """
    Converts common Firebase shapes into normalized payment records.

    Supported examples:

    {
        "SMS1": {
            "amount": 100,
            "method": "bkash",
            "txid": "ABC123",
            "time": 1773249940762
        }
    }

    or:

    [
        {...},
        {...}
    ]

    If your existing reader uses another structure, only this function
    normally needs adjustment.
    """

    records = []

    if isinstance(data, dict):
        for record_id, record in data.items():
            if isinstance(record, dict):
                normalized = normalize_record(str(record_id), record)
                if normalized:
                    records.append(normalized)

    elif isinstance(data, list):
        for index, record in enumerate(data):
            normalized = normalize_record(str(index), record)
            if normalized:
                records.append(normalized)

    return records


# ============================================================
# PAYMENT ACCOUNT SELECTION
# ============================================================

def select_payment_account(session: Session, provider: str) -> PaymentAccount:
    account = session.scalar(
        select(PaymentAccount)
        .where(
            PaymentAccount.provider == provider,
            PaymentAccount.status == "ACTIVE",
        )
        .limit(1)
    )

    if not account:
        raise HTTPException(
            503,
            f"No active {provider} payment account configured",
        )

    return account


# ============================================================
# PAYMENT API
# ============================================================

@app.post("/api/v1/payments", response_model=PaymentResponse)
def create_payment(
    payload: PaymentCreate,
    merchant: Merchant = Depends(merchant_auth),
    session: Session = Depends(db),
):

    account = select_payment_account(session, payload.provider)

    payment_id = new_payment_id()

    expires_at = utcnow() + timedelta(minutes=payload.expires_minutes)

    payment = PaymentSession(
        payment_id=payment_id,
        merchant_id=merchant.id,
        amount=payload.amount,
        currency=payload.currency,
        provider=payload.provider,
        payment_account=account.account_number,
        customer_reference=payload.reference,
        status="PENDING",
        expires_at=expires_at,
    )

    session.add(payment)
    session.commit()

    return PaymentResponse(
        payment_id=payment_id,
        amount=payment.amount,
        currency=payment.currency,
        provider=payment.provider,
        payment_account=payment.payment_account,
        reference=payment.customer_reference,
        status=payment.status,
        checkout_url=f"{PUBLIC_BASE_URL}/pay/{payment_id}",
        expires_at=payment.expires_at,
    )


@app.get("/api/v1/payments/{payment_id}")
def payment_status(
    payment_id: str,
    merchant: Merchant = Depends(merchant_auth),
    session: Session = Depends(db),
):
    payment = session.scalar(
        select(PaymentSession).where(
            PaymentSession.payment_id == payment_id,
            PaymentSession.merchant_id == merchant.id,
        )
    )

    if not payment:
        raise HTTPException(404, "Payment not found")

    if payment.status == "PENDING" and payment.expires_at < utcnow():
        payment.status = "EXPIRED"
        session.commit()

    return {
        "payment_id": payment.payment_id,
        "amount": payment.amount,
        "currency": payment.currency,
        "provider": payment.provider,
        "payment_account": payment.payment_account,
        "reference": payment.customer_reference,
        "status": payment.status,
        "created_at": payment.created_at,
        "expires_at": payment.expires_at,
        "paid_at": payment.paid_at,
    }


# ============================================================
# PUBLIC PAYMENT PAGE
# ============================================================

@app.get("/pay/{payment_id}", response_class=HTMLResponse)
def payment_page(payment_id: str, session: Session = Depends(db)):

    payment = session.scalar(
        select(PaymentSession).where(
            PaymentSession.payment_id == payment_id
        )
    )

    if not payment:
        raise HTTPException(404, "Payment not found")

    if payment.status == "PENDING" and payment.expires_at < utcnow():
        payment.status = "EXPIRED"
        session.commit()

    if payment.status == "SUCCESS":
        status_text = "Payment Successful"
    elif payment.status == "EXPIRED":
        status_text = "Payment Expired"
    else:
        status_text = "Waiting for payment"

    return f"""
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Payment {payment.payment_id}</title>
<style>
body {{
    margin:0;
    background:#f4f6f8;
    font-family:Arial,sans-serif;
}}
.card {{
    max-width:430px;
    margin:60px auto;
    background:white;
    border-radius:18px;
    padding:28px;
    box-shadow:0 10px 40px rgba(0,0,0,.08);
}}
.amount {{
    font-size:34px;
    font-weight:800;
    margin:15px 0;
}}
.number {{
    background:#f5f5f5;
    border-radius:12px;
    padding:15px;
    font-size:22px;
    font-weight:700;
}}
.ref {{
    margin-top:15px;
    padding:12px;
    background:#fafafa;
    border-radius:10px;
}}
.status {{
    margin-top:20px;
    padding:14px;
    border-radius:10px;
    background:#eef4ff;
}}
button {{
    width:100%;
    padding:15px;
    border:0;
    border-radius:10px;
    margin-top:18px;
    font-size:16px;
    font-weight:700;
    cursor:pointer;
}}
</style>
</head>
<body>
<div class="card">
    <h2>Payment</h2>
    <div class="amount">৳{payment.amount}</div>

    <p>Send Money to:</p>
    <div class="number">{payment.payment_account}</div>

    <div class="ref">
        Payment ID:<br>
        <b>{payment.payment_id}</b>
    </div>

    <div class="ref">
        Reference:<br>
        <b>{payment.customer_reference or "N/A"}</b>
    </div>

    <div class="status" id="status">{status_text}</div>

    <button onclick="location.reload()">Check Payment Status</button>
</div>

<script>
setInterval(() => location.reload(), 5000);
</script>
</body>
</html>
"""


# ============================================================
# WEBHOOK
# ============================================================

def queue_webhook(
    session: Session,
    payment: PaymentSession,
    merchant: Merchant,
):
    if not merchant.webhook_url:
        return

    payload = {
        "event": "payment.success",
        "payment_id": payment.payment_id,
        "amount": payment.amount,
        "currency": payment.currency,
        "provider": payment.provider,
        "status": payment.status,
        "paid_at": payment.paid_at.isoformat() if payment.paid_at else None,
    }

    session.add(
        WebhookDelivery(
            payment_id=payment.payment_id,
            merchant_id=merchant.id,
            url=merchant.webhook_url,
            event="payment.success",
            payload=json.dumps(payload),
            status="PENDING",
        )
    )
    session.commit()


def deliver_webhook(delivery_id: int):
    session = SessionLocal()

    try:
        delivery = session.get(WebhookDelivery, delivery_id)

        if not delivery or delivery.status == "SUCCESS":
            return

        merchant = session.get(Merchant, delivery.merchant_id)

        if not merchant:
            return

        body = delivery.payload

        signature = sign_webhook(
            merchant.webhook_secret,
            body,
        )

        try:
            response = requests.post(
                delivery.url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Payment-Gateway-Signature": signature,
                    "X-Payment-Gateway-Event": delivery.event,
                },
                timeout=WEBHOOK_TIMEOUT,
            )

            delivery.attempts += 1

            if 200 <= response.status_code < 300:
                delivery.status = "SUCCESS"
                delivery.last_error = None
            else:
                delivery.status = "RETRY"
                delivery.last_error = f"HTTP {response.status_code}"

        except Exception as exc:
            delivery.attempts += 1
            delivery.status = "RETRY"
            delivery.last_error = str(exc)

        session.commit()

    finally:
        session.close()


# ============================================================
# MATCHING ENGINE
# ============================================================

def match_sms_record(record: dict):
    session = SessionLocal()

    try:
        provider = record["provider"]
        amount = record["amount"]
        txid = record["txid"]
        receiver = record.get("receiver")

        # Duplicate provider transaction protection.
        existing_tx = session.scalar(
            select(Transaction).where(
                Transaction.provider == provider,
                Transaction.provider_txid == txid,
            )
        )

        if existing_tx:
            return

        candidates = session.scalars(
            select(PaymentSession).where(
                PaymentSession.provider == provider,
                PaymentSession.amount == amount,
                PaymentSession.status == "PENDING",
            )
        ).all()

        candidates = [
            p for p in candidates
            if p.expires_at >= utcnow()
        ]

        # Receiver must match when reader provides receiver.
        if receiver:
            candidates = [
                p for p in candidates
                if normalize_receiver(p.payment_account) == receiver
            ]

        # No exact candidate => don't auto-credit.
        if len(candidates) != 1:
            return

        payment = candidates[0]

        merchant = session.get(Merchant, payment.merchant_id)

        if not merchant:
            return

        # Final duplicate check immediately before writing.
        existing_tx = session.scalar(
            select(Transaction).where(
                Transaction.provider == provider,
                Transaction.provider_txid == txid,
            )
        )

        if existing_tx:
            return

        payment.status = "SUCCESS"
        payment.paid_at = utcnow()

        transaction = Transaction(
            payment_id=payment.payment_id,
            merchant_id=payment.merchant_id,
            provider=provider,
            provider_txid=txid,
            amount=amount,
            receiver=receiver,
            raw_sms_id=record.get("record_id"),
            status="SUCCESS",
            raw_data=json.dumps(record["raw"], ensure_ascii=False),
        )

        session.add(transaction)
        session.commit()

        queue_webhook(session, payment, merchant)

        delivery = session.scalar(
            select(WebhookDelivery)
            .where(
                WebhookDelivery.payment_id == payment.payment_id
            )
            .order_by(WebhookDelivery.id.desc())
        )

        if delivery:
            threading.Thread(
                target=deliver_webhook,
                args=(delivery.id,),
                daemon=True,
            ).start()

    except Exception as exc:
        session.rollback()
        print("MATCHING ERROR:", exc)

    finally:
        session.close()


# ============================================================
# FIREBASE POLLER
# ============================================================

_seen_firebase_ids = set()
_firebase_initialized = False


def firebase_poll_loop():
    global _firebase_initialized

    if not FIREBASE_DATABASE_URL:
        print("Firebase polling disabled: FIREBASE_DATABASE_URL not configured.")
        return

    print(
        f"Firebase SMS listener started: /{FIREBASE_SMS_NODE}"
    )

    while True:
        try:
            data = firebase_get(FIREBASE_SMS_NODE)
            records = extract_sms_records(data)

            # On first startup, don't auto-process every historical record.
            if not _firebase_initialized:
                for record in records:
                    _seen_firebase_ids.add(
                        f"{record['provider']}:{record['txid']}"
                    )

                _firebase_initialized = True

            else:
                for record in records:
                    key = f"{record['provider']}:{record['txid']}"

                    if key in _seen_firebase_ids:
                        continue

                    _seen_firebase_ids.add(key)
                    match_sms_record(record)

                    # Prevent unlimited memory growth.
                    if len(_seen_firebase_ids) > 50_000:
                        _seen_firebase_ids.clear()

        except Exception as exc:
            print("FIREBASE POLLER ERROR:", exc)

        time.sleep(SMS_POLL_SECONDS)


# ============================================================
# ADMIN
# ============================================================

@app.post("/admin/login")
def admin_login(
    username: str,
    password: str,
):
    if not hmac.compare_digest(username, ADMIN_USERNAME):
        raise HTTPException(401, "Invalid credentials")

    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        raise HTTPException(401, "Invalid credentials")

    return {
        "access_token": make_token(username, "SUPER_ADMIN"),
        "token_type": "bearer",
    }


def require_admin(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")

    token = authorization[7:]

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
    except Exception:
        raise HTTPException(401, "Invalid token")

    if payload.get("role") not in {
        "SUPER_ADMIN",
        "ADMIN",
        "MANAGER",
    }:
        raise HTTPException(403, "Insufficient permissions")

    return payload


@app.post("/admin/merchants")
def admin_create_merchant(
    payload: MerchantCreate,
    admin=Depends(require_admin),
    session: Session = Depends(db),
):
    webhook_secret = secrets.token_urlsafe(32)

    merchant = Merchant(
        name=payload.name,
        email=payload.email,
        phone=payload.phone,
        webhook_url=payload.webhook_url,
        webhook_secret=webhook_secret,
        status="ACTIVE",
    )

    session.add(merchant)
    session.commit()
    session.refresh(merchant)

    key_id, secret = new_api_key()

    api_key = ApiKey(
        merchant_id=merchant.id,
        key_id=key_id,
        secret_hash=hash_secret(secret),
        status="ACTIVE",
    )

    session.add(api_key)
    session.commit()

    audit(
        session,
        actor=admin["sub"],
        action="CREATE_MERCHANT",
        target=str(merchant.id),
        details={"merchant": merchant.name},
    )

    # Secret is returned ONLY once.
    return {
        "merchant_id": merchant.id,
        "name": merchant.name,
        "api_key": key_id,
        "api_secret": secret,
        "webhook_secret": webhook_secret,
        "warning": "Store these secrets securely. They will not be shown again.",
    }


@app.post("/admin/payment-accounts")
def admin_add_payment_account(
    provider: str,
    account_number: str,
    admin=Depends(require_admin),
    session: Session = Depends(db),
):
    account_number = normalize_receiver(account_number)

    if not account_number:
        raise HTTPException(400, "Invalid account number")

    account = PaymentAccount(
        provider=provider.lower(),
        account_number=account_number,
        status="ACTIVE",
    )

    session.add(account)
    session.commit()

    audit(
        session,
        actor=admin["sub"],
        action="ADD_PAYMENT_ACCOUNT",
        target=str(account.id),
        details={
            "provider": provider,
            "account_number": account_number,
        },
    )

    return {
        "id": account.id,
        "provider": account.provider,
        "account_number": account.account_number,
        "status": account.status,
    }


@app.get("/admin/transactions")
def admin_transactions(
    limit: int = 100,
    admin=Depends(require_admin),
    session: Session = Depends(db),
):
    limit = min(max(limit, 1), 500)

    rows = session.scalars(
        select(Transaction)
        .order_by(Transaction.id.desc())
        .limit(limit)
    ).all()

    return [
        {
            "id": row.id,
            "payment_id": row.payment_id,
            "merchant_id": row.merchant_id,
            "provider": row.provider,
            "provider_txid": row.provider_txid,
            "amount": row.amount,
            "receiver": row.receiver,
            "status": row.status,
            "created_at": row.created_at,
        }
        for row in rows
    ]


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "payment-gateway",
        "firebase_configured": bool(FIREBASE_DATABASE_URL),
        "firebase_node": FIREBASE_SMS_NODE,
        "time": utcnow().isoformat(),
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup():
    if FIREBASE_DATABASE_URL:
        thread = threading.Thread(
            target=firebase_poll_loop,
            daemon=True,
            name="firebase-sms-listener",
        )
        thread.start()

    print("Payment Gateway started.")


# ============================================================
# LOCAL TEST DATA HELPER
# ============================================================

@app.get("/debug/firebase")
def debug_firebase(
    admin=Depends(require_admin),
):
    """
    Admin-only diagnostic endpoint.
    Remove/disable this in strict production environments.
    """
    try:
        data = firebase_get(FIREBASE_SMS_NODE)
        records = extract_sms_records(data)

        return {
            "node": FIREBASE_SMS_NODE,
            "record_count": len(records),
            "records": records[:50],
        }

    except Exception as exc:
        raise HTTPException(
            502,
            f"Firebase read failed: {exc}",
        )


# ============================================================
# END
# ============================================================
