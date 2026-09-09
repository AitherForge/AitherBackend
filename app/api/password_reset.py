from __future__ import annotations

import html
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import resend
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.api.auth import hash_password, token_hash
from app.config import settings
from app.db import connection

router = APIRouter(prefix="/api/auth", tags=["auth"])


def now() -> datetime:
    return datetime.now(timezone.utc)


def make_token(user_id: str) -> str:
    raw = secrets.token_urlsafe(48)
    created = now()
    expires = created + timedelta(hours=1)
    with connection() as conn:
        conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
        conn.execute(
            "INSERT INTO password_reset_tokens(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
            (token_hash(raw), user_id, created.isoformat(), expires.isoformat()),
        )
    return raw


async def send_reset_email(name: str, email: str, token: str) -> None:
    key = os.getenv("RESEND_API_KEY", "").strip()
    if not key:
        raise RuntimeError("RESEND_API_KEY is not configured")
    base = os.getenv("RESEND_FROM_EMAIL", settings.smtp_from_email).strip()
    from_name = os.getenv("RESEND_FROM_NAME", "Aither").strip() or "Aither"
    sender = f"{from_name} <{base}>"
    link = f"{settings.verification_base_url.rstrip('/')}/api/auth/reset-password?token={quote(token)}"
    safe_name = html.escape(name or "there")
    safe_link = html.escape(link, quote=True)
    html_body = f'''<!doctype html><html><body style="margin:0;background:#080d17;color:#f7f9ff;font-family:Arial,Helvetica,sans-serif"><table width="100%" cellpadding="0" cellspacing="0" border="0"><tr><td align="center" style="padding:40px 16px"><table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;background:#101b2d;border:1px solid #294568;border-radius:20px"><tr><td style="padding:36px"><h1 style="font-size:28px;line-height:1.2;color:#28a9ff">Reset your Aither Account password</h1><p style="font-size:16px;line-height:1.6;color:#d8e4f7">Hi {safe_name},</p><p style="font-size:15px;line-height:1.7;color:#aebed5">We received a request to reset your Aither Account password. Use the button below to choose a new password.</p><p style="text-align:center;padding:18px 0"><a href="{safe_link}" style="display:inline-block;padding:15px 28px;background:#159ff4;color:#fff;text-decoration:none;border-radius:12px;font-weight:700">Reset Password</a></p><p style="font-size:12px;line-height:1.6;color:#879bb5">This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email.</p></td></tr></table></td></tr></table></body></html>'''
    text = f"Hi {name},\n\nReset your Aither Account password here:\n{link}\n\nThis link expires in 1 hour. If you did not request this, ignore this email."
    resend.api_key = key
    await resend.Emails.send_async({"from": sender, "to": [email], "subject": "Reset your Aither Account password", "html": html_body, "text": text})


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str = Field(min_length=8, max_length=200)


@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest) -> dict[str, bool]:
    email = payload.email.strip().lower()
    with connection() as conn:
        row = conn.execute("SELECT id,name,email FROM users WHERE email = ?", (email,)).fetchone()
    if row:
        token = make_token(str(row["id"]))
        try:
            await send_reset_email(str(row["name"]), str(row["email"]), token)
        except Exception:
            pass
    return {"ok": True}


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest) -> dict[str, bool]:
    with connection() as conn:
        row = conn.execute("SELECT user_id,expires_at FROM password_reset_tokens WHERE token_hash = ?", (token_hash(payload.token),)).fetchone()
        if not row or datetime.fromisoformat(row["expires_at"]) <= now():
            raise HTTPException(status_code=400, detail="This password reset link is invalid or expired.")
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(payload.password), row["user_id"]))
        conn.execute("DELETE FROM password_reset_tokens WHERE token_hash = ?", (token_hash(payload.token),))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (row["user_id"],))
        conn.execute("INSERT INTO audit_logs(user_id,event,created_at) VALUES(?,?,?)", (row["user_id"], "password_reset", now().isoformat()))
    return {"ok": True}


@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(token: str = Query(min_length=20)) -> str:
    safe_token = html.escape(token, quote=True)
    return f'''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aither — Reset Password</title></head><body style="margin:0;background:#080d17;color:white;font-family:Arial,Helvetica,sans-serif"><main style="max-width:440px;margin:12vh auto;padding:28px;background:#101b2d;border:1px solid #294568;border-radius:20px"><h1 style="color:#28a9ff">Choose a new password</h1><form method="post" action="/api/auth/reset-password"><input type="hidden" name="token" value="{safe_token}"><input name="password" type="password" minlength="8" required placeholder="New password" style="width:100%;box-sizing:border-box;padding:14px;margin:14px 0;border-radius:10px;border:1px solid #47627f;background:#08111e;color:white"><button type="submit" style="padding:14px 20px;border:0;border-radius:10px;background:#159ff4;color:white;font-weight:700">Set New Password</button></form></main></body></html>'''
