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
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <meta name="supported-color-schemes" content="dark">
  <title>Verify your Aither Account</title>
</head>
<body style="margin:0;padding:0;background:#070b14;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;color:#f7f9ff;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">Verify your Aither Account email address.</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#070b14;padding:28px 10px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;background:#0b111d;border:1px solid #243a5c;border-radius:24px;overflow:hidden;box-shadow:0 24px 70px rgba(0,0,0,.45);">
        <tr><td style="padding:34px 28px 28px;text-align:center;background:radial-gradient(circle at 50% 0%,#1b3b682e,transparent 65%),#080d17;">
          <img src="{safe_logo}" alt="Aither Forge" width="260" style="display:block;width:260px;max-width:85%;height:auto;margin:0 auto;border:0;outline:none;text-decoration:none;">
          <p style="margin:16px 0 0;font-size:11px;line-height:1.5;letter-spacing:5px;color:#9db7d9;font-weight:700;">BUILD &nbsp; • &nbsp; CREATE &nbsp; • &nbsp; EXPLORE</p>
        </td></tr>
        <tr><td style="padding:0 18px 18px;background:#080d17;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:linear-gradient(145deg,#101b2d,#0b111d);border:1px solid #294568;border-radius:22px;overflow:hidden;">
            <tr><td style="padding:38px 30px 34px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr><td style="padding:0 0 26px;">
                  <h1 style="margin:0 0 12px;font-size:30px;line-height:1.15;letter-spacing:-.6px;color:#ffffff;">Hello <span style="color:#28a9ff;">{safe_name}</span>,</h1>
                  <p style="margin:0 0 14px;font-size:17px;line-height:1.6;color:#d8e4f7;font-weight:700;">Thanks for creating an Aither Account!</p>
                  <p style="margin:0;font-size:15px;line-height:1.75;color:#aebed5;">To keep your account safe and secure, please verify your email address by clicking the button below. This confirms that you own this email and gives you full access to Aither features.</p>
                </td></tr>
                <tr><td align="center" style="padding:4px 0 30px;">
                  <table role="presentation" cellpadding="0" cellspacing="0"><tr><td align="center" style="border-radius:14px;background:linear-gradient(135deg,#159ff4,#7757ff);box-shadow:0 10px 30px rgba(40,145,255,.24);">
                    <a href="{safe_link}" style="display:inline-block;padding:16px 34px;border-radius:14px;color:#ffffff;text-decoration:none;font-size:16px;font-weight:800;letter-spacing:.1px;">✉ &nbsp; Verify My Email</a>
                  </td></tr></table>
                </td></tr>
                <tr><td style="padding:0 0 24px;">
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="height:1px;background:#29405f;font-size:1px;line-height:1px;">&nbsp;</td><td style="padding:0 14px;white-space:nowrap;font-size:12px;color:#8da5c4;">Or copy and paste this link</td><td style="height:1px;background:#29405f;font-size:1px;line-height:1px;">&nbsp;</td></tr></table>
                </td></tr>
                <tr><td style="padding:14px 16px;border:1px solid #294d78;border-radius:14px;background:#08111e;word-break:break-all;">
                  <p style="margin:0;font-size:12px;line-height:1.65;color:#39aaff;">🔗 {safe_link}</p>
                </td></tr>
                <tr><td style="padding:28px 0 0;">
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
                    <td width="50%" valign="top" style="padding-right:18px;border-right:1px solid #29405f;">
                      <p style="margin:0 0 4px;font-size:13px;color:#aebed5;">◷ &nbsp; This link expires in</p>
                      <p style="margin:0;font-size:18px;font-weight:800;color:#27a9ff;">{expiry} hours</p>
                    </td>
                    <td width="50%" valign="top" style="padding-left:18px;">
                      <p style="margin:0 0 4px;font-size:13px;color:#d8e4f7;font-weight:700;">♢ &nbsp; For your security</p>
                      <p style="margin:0;font-size:12px;line-height:1.6;color:#879bb5;">If you didn't create this account, you can safely ignore this email.</p>
                    </td>
                  </tr></table>
                </td></tr>
                <tr><td style="padding-top:28px;">
                  <p style="margin:0 0 4px;font-size:14px;color:#aebed5;">Thanks,</p>
                  <p style="margin:0;font-size:16px;color:#25a9ff;font-weight:800;">The Aither Forge Team ♡</p>
                </td></tr>
              </table>
            </td></tr>
          </table>
        </td></tr>
        <tr><td style="padding:24px 22px 30px;text-align:center;background:#070b14;">
          <img src="{safe_logo}" alt="Aither Forge" width="190" style="display:block;width:190px;max-width:70%;height:auto;margin:0 auto 14px;border:0;outline:none;text-decoration:none;">
          <p style="margin:0 0 20px;font-size:11px;line-height:1.5;letter-spacing:3px;color:#8195b2;font-weight:700;">MORE THAN APPS. IT'S A LIFESTYLE.</p>
          <p style="margin:0;font-size:11px;line-height:1.6;color:#5f718b;">If you did not create an Aither Account, you can safely ignore this message.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>'''

    text_body = (
        f"Hi {name},\n\n"
        "Thanks for creating your Aither Account. Verify your email address here:\n\n"
        f"{link}\n\n"
        f"This link expires in {expiry} hours.\n\n"
        "If you did not create an Aither Account, you can safely ignore this email.\n\n"
        "— Aither Forge"
    )

    params: resend.Emails.SendParams = {
        "from": from_address,
        "to": [email],
        "subject": "Verify your Aither Account",
        "html": html_body,
        "text": text_body,
    }
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
    email = payload.email.strip().lower()
    name = payload.name.strip()
    with connection() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="An account with this email already exists. Sign in instead.")
        user_id = str(uuid.uuid4())
        created = now().isoformat()
        conn.execute(
            "INSERT INTO users(id,name,email,password_hash,created_at) VALUES(?,?,?,?,?)",
            (user_id, name, email, hash_password(payload.password), created),
        )
        conn.execute(
            "INSERT INTO audit_logs(user_id,event,created_at) VALUES(?,?,?)",
            (user_id, "account_created", created),
        )
    session_token_value = create_session(user_id)
    verification_token = create_verification_token(user_id)
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
    session_token_value = create_session(row["id"])
    set_session_cookie(response, session_token_value)
    return {"authenticated": True, "session_token": session_token_value, "user": user_payload(row["id"], row["name"], row["email"], bool(row["email_verified"]))}


@router.post("/verify/resend")
async def resend_verification(
    response: Response,
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user = authenticated_user(aither_session, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in first.")
    if user["email_verified"]:
        return {"sent": False, "already_verified": True}
    token = create_verification_token(str(user["id"]))
    try:
        await send_verification_email(str(user["name"]), str(user["email"]), token)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"The verification email could not be sent: {exc}") from exc
    return {"sent": True}


@router.get("/verify", response_class=HTMLResponse)
async def verify_email(token: str = Query(min_length=20)) -> str:
    with connection() as conn:
        row = conn.execute(
            "SELECT user_id,expires_at FROM email_verification_tokens WHERE token_hash = ?",
            (token_hash(token),),
        ).fetchone()
        if not row:
            return "<html><body><h1>Invalid verification link</h1><p>This Aither verification link is invalid or has already been used.</p></body></html>"
        if datetime.fromisoformat(row["expires_at"]) <= now():
            conn.execute("DELETE FROM email_verification_tokens WHERE token_hash = ?", (token_hash(token),))
            return "<html><body><h1>Verification link expired</h1><p>Please request a new Aither verification email.</p></body></html>"
        conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (row["user_id"],))
        conn.execute("DELETE FROM email_verification_tokens WHERE token_hash = ?", (token_hash(token),))
        conn.execute(
            "INSERT INTO audit_logs(user_id,event,created_at) VALUES(?,?,?)",
            (row["user_id"], "email_verified", now().isoformat()),
        )
    return "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'></head><body><h1>Email verified</h1><p>Your Aither Account email is now verified. You can return to any Aither app and refresh your account status.</p></body></html>"


@router.post("/logout")
async def logout(response: Response, aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE), authorization: str | None = Header(default=None)) -> dict[str, str]:
    token = session_token(aither_session, authorization)
    if token:
        with connection() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/session")
async def session(
    response: Response,
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user = authenticated_user(aither_session, authorization)
    token = bearer_token(authorization)
    if user and token:
        set_session_cookie(response, token)
    return {"authenticated": bool(user), "user": user}
