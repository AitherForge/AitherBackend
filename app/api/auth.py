from __future__ import annotations

import hashlib
import hmac
import html
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import quote

import resend
from fastapi import APIRouter, Cookie, Header, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.db import connection

router = APIRouter(prefix="/api/auth", tags=["auth"])
SESSION_COOKIE = "aither_session"
AITHER_FORGE_LOGO_URL = "https://aitherforge.github.io/AitherTech/aither-forge-logo.jpg"


def now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, salt_hex, digest_hex = encoded.split("$", 2)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id: str) -> str:
    raw = secrets.token_urlsafe(48)
    created = now()
    expires = created + timedelta(hours=settings.session_ttl_hours)
    with connection() as conn:
        conn.execute(
            "INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
            (token_hash(raw), user_id, created.isoformat(), expires.isoformat()),
        )
        conn.execute(
            "INSERT INTO audit_logs(user_id,event,created_at) VALUES(?,?,?)",
            (user_id, "login", created.isoformat()),
        )
    return raw


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite=settings.session_cookie_samesite,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def session_token(aither_session: str | None, authorization: str | None) -> str | None:
    return bearer_token(authorization) or aither_session


def authenticated_user(aither_session: str | None, authorization: str | None) -> dict[str, object] | None:
    token = session_token(aither_session, authorization)
    if not token:
        return None
    with connection() as conn:
        row = conn.execute(
            "SELECT u.id,u.name,u.email,u.email_verified,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash = ?",
            (token_hash(token),),
        ).fetchone()
    if not row or datetime.fromisoformat(row["expires_at"]) <= now():
        return None
    return {"id": row["id"], "name": row["name"], "email": row["email"], "email_verified": bool(row["email_verified"])}


def create_verification_token(user_id: str) -> str:
    raw = secrets.token_urlsafe(48)
    created = now()
    expires = created + timedelta(hours=settings.verification_token_hours)
    with connection() as conn:
        conn.execute("DELETE FROM email_verification_tokens WHERE user_id = ?", (user_id,))
        conn.execute(
            "INSERT INTO email_verification_tokens(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
            (token_hash(raw), user_id, created.isoformat(), expires.isoformat()),
        )
    return raw


async def send_verification_email(name: str, email: str, token: str) -> None:
    """Send a polished, responsive Aither Forge verification email through Resend."""
    resend_api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not resend_api_key:
        raise RuntimeError("Email delivery is not configured. Set RESEND_API_KEY in the Render service environment.")

    link = f"{settings.verification_base_url.rstrip('/')}/api/auth/verify?token={quote(token)}"
    from_name = os.getenv("RESEND_FROM_NAME", settings.smtp_from_name).strip() or "Aither Forge"
    from_email = os.getenv("RESEND_FROM_EMAIL", settings.smtp_from_email).strip() or "onboarding@resend.dev"
    from_address = f"{from_name} <{from_email}>"
    safe_name = html.escape(name or "there")
    safe_link = html.escape(link, quote=True)
    safe_logo = html.escape(AITHER_FORGE_LOGO_URL, quote=True)
    expiry = settings.verification_token_hours

    html_body = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verify your Aither Account</title></head>
<body style="margin:0;padding:28px 10px;background:#070b14;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#f7f9ff;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center"><table role="presentation" width="100%" style="max-width:680px;background:#0b111d;border:1px solid #243a5c;border-radius:24px;overflow:hidden"><tr><td style="padding:34px 28px;text-align:center"><img src="{safe_logo}" alt="Aither Forge" width="260" style="max-width:85%;height:auto"><h1 style="color:#fff">Hello <span style="color:#28a9ff">{safe_name}</span>,</h1><p style="font-size:17px;color:#d8e4f7">Thanks for creating an Aither Account!</p><p style="font-size:15px;line-height:1.7;color:#aebed5">Please verify your email address to secure your account and unlock full Aither access.</p><p style="margin:30px 0"><a href="{safe_link}" style="display:inline-block;padding:16px 34px;border-radius:14px;background:#159ff4;color:white;text-decoration:none;font-weight:800">Verify My Email</a></p><p style="font-size:12px;color:#8da5c4">This link expires in {expiry} hours.</p><p style="font-size:13px;color:#879bb5">If you did not create an Aither Account, you can safely ignore this message.</p></td></tr></table></td></tr></table></body></html>'''

    text_body = f"Hi {name},\n\nThanks for creating your Aither Account. Verify your email address here:\n\n{link}\n\nThis link expires in {expiry} hours.\n\n— Aither Forge"
    params: resend.Emails.SendParams = {"from": from_address, "to": [email], "subject": "Verify your Aither Account", "html": html_body, "text": text_body}
    resend.api_key = resend_api_key
    await resend.Emails.send_async(params)


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=200)


def user_payload(row_or_id: object, name: str, email: str, verified: bool) -> dict[str, object]:
    return {"id": row_or_id, "name": name, "email": email, "email_verified": verified}


@router.post("/register", status_code=201)
async def register(payload: RegisterRequest, response: Response) -> dict[str, object]:
    email = payload.email.strip().lower(); name = payload.name.strip()
    with connection() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="An account with this email already exists. Sign in instead.")
        user_id = str(uuid.uuid4()); created = now().isoformat()
        conn.execute("INSERT INTO users(id,name,email,password_hash,created_at) VALUES(?,?,?,?,?)", (user_id, name, email, hash_password(payload.password), created))
        conn.execute("INSERT INTO audit_logs(user_id,event,created_at) VALUES(?,?,?)", (user_id, "account_created", created))
    session_token_value = create_session(user_id); verification_token = create_verification_token(user_id)
    try:
        await send_verification_email(name, email, verification_token)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Account created, but the verification email could not be sent: {exc}") from exc
    set_session_cookie(response, session_token_value)
    return {"authenticated": True, "session_token": session_token_value, "user": user_payload(user_id, name, email, False), "verification_sent": True}


@router.post("/login")
async def login(payload: LoginRequest, response: Response) -> dict[str, object]:
    email = payload.email.strip().lower()
    with connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    session_token_value = create_session(row["id"]); set_session_cookie(response, session_token_value)
    return {"authenticated": True, "session_token": session_token_value, "user": user_payload(row["id"], row["name"], row["email"], bool(row["email_verified"]))}


@router.post("/verify/resend")
async def resend_verification(response: Response, aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE), authorization: str | None = Header(default=None)) -> dict[str, object]:
    user = authenticated_user(aither_session, authorization)
    if not user: raise HTTPException(status_code=401, detail="Sign in first.")
    if user["email_verified"]: return {"sent": False, "already_verified": True}
    token = create_verification_token(str(user["id"]))
    try: await send_verification_email(str(user["name"]), str(user["email"]), token)
    except Exception as exc: raise HTTPException(status_code=503, detail=f"The verification email could not be sent: {exc}") from exc
    return {"sent": True}


@router.get("/verify", response_class=HTMLResponse)
async def verify_email(token: str = Query(min_length=20)) -> str:
    with connection() as conn:
        row = conn.execute("SELECT user_id,expires_at FROM email_verification_tokens WHERE token_hash = ?", (token_hash(token),)).fetchone()
        if not row: return "<html><body><h1>Invalid verification link</h1><p>This Aither verification link is invalid or has already been used.</p></body></html>"
        if datetime.fromisoformat(row["expires_at"]) <= now():
            conn.execute("DELETE FROM email_verification_tokens WHERE token_hash = ?", (token_hash(token),)); return "<html><body><h1>Verification link expired</h1><p>Please request a new Aither verification email.</p></body></html>"
        conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["user_id"],)); conn.execute("DELETE FROM email_verification_tokens WHERE token_hash = ?", (token_hash(token),)); conn.execute("INSERT INTO audit_logs(user_id,event,created_at) VALUES(?,?,?)", (row["user_id"], "email_verified", now().isoformat()))
    return "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'></head><body><h1>Email verified</h1><p>Your Aither Account email is now verified. You can return to any Aither app and refresh your account status.</p></body></html>"


@router.post("/logout")
async def logout(response: Response, aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE), authorization: str | None = Header(default=None)) -> dict[str, str]:
    token = session_token(aither_session, authorization)
    if token:
        with connection() as conn: conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
    response.delete_cookie(SESSION_COOKIE, path="/"); return {"status": "ok"}


@router.get("/session")
async def session(response: Response, aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE), authorization: str | None = Header(default=None)) -> dict[str, object]:
    user = authenticated_user(aither_session, authorization)
    token = session_token(aither_session, authorization)
    if user and token:
        # Sliding session: every successful restore extends the existing session
        # and refreshes the persistent HttpOnly cookie without changing the token.
        expires = now() + timedelta(hours=settings.session_ttl_hours)
        with connection() as conn:
            conn.execute("UPDATE sessions SET expires_at = ? WHERE token_hash = ?", (expires.isoformat(), token_hash(token)))
        set_session_cookie(response, token)
    return {"authenticated": bool(user), "user": user}
