from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone
from email.utils import parseaddr

from fastapi import APIRouter, Cookie, Header, HTTPException
from pydantic import BaseModel, Field

from app.api.auth import SESSION_COOKIE, authenticated_user
from app.db import connection

router = APIRouter(prefix="/api/mail", tags=["mail"])

def _user(aither_session: str | None, authorization: str | None):
    user = authenticated_user(aither_session, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user

class SendMail(BaseModel):
    to: str = Field(min_length=3, max_length=2000)
    cc: str = Field(default="", max_length=2000)
    bcc: str = Field(default="", max_length=2000)
    subject: str = Field(default="", max_length=998)
    body: str = Field(default="", max_length=1_000_000)

def _split(value: str) -> list[str]:
    return [parseaddr(x.strip())[1] for x in value.split(",") if parseaddr(x.strip())[1]]

def _row(row):
    return {"id": str(row["id"]), "from": row["sender"], "to": row["recipients"], "cc": row["cc"], "subject": row["subject"], "date": row["created_at"], "text": row["body"], "html": "", "read": bool(row["is_read"])}

@router.get("/messages")
async def list_messages(start: int = 0, limit: int = 100, aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE), authorization: str | None = Header(default=None)):
    user = _user(aither_session, authorization)
    start, limit = max(0, start), min(100, max(1, limit))
    with connection() as conn:
        rows = conn.execute("SELECT * FROM mail_messages WHERE owner_user_id = ? AND deleted = 0 ORDER BY id DESC LIMIT ? OFFSET ?", (str(user["id"]), limit, start)).fetchall()
    return {"items": [_row(r) for r in rows], "start": start, "limit": limit}

@router.get("/messages/{message_id}")
async def get_message(message_id: str, aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE), authorization: str | None = Header(default=None)):
    user = _user(aither_session, authorization)
    with connection() as conn:
        row = conn.execute("SELECT * FROM mail_messages WHERE id = ? AND owner_user_id = ? AND deleted = 0", (message_id, str(user["id"]))).fetchone()
        if not row: raise HTTPException(status_code=404, detail="Message not found.")
        conn.execute("UPDATE mail_messages SET is_read = 1 WHERE id = ?", (message_id,))
    return _row(row)

@router.delete("/messages/{message_id}")
async def delete_message(message_id: str, aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE), authorization: str | None = Header(default=None)):
    user = _user(aither_session, authorization)
    with connection() as conn:
        changed = conn.execute("UPDATE mail_messages SET deleted = 1 WHERE id = ? AND owner_user_id = ?", (message_id, str(user["id"]))).rowcount
    if not changed: raise HTTPException(status_code=404, detail="Message not found.")
    return {"ok": True}

@router.post("/send")
async def send_message(payload: SendMail, aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE), authorization: str | None = Header(default=None)):
    user = _user(aither_session, authorization)
    sender = user["email"]
    recipients, cc, bcc = _split(payload.to), _split(payload.cc), _split(payload.bcc)
    if not recipients and not cc and not bcc: raise HTTPException(status_code=400, detail="Add at least one recipient.")
    now = datetime.now(timezone.utc).isoformat()
    recipient_text = ", ".join(recipients)
    with connection() as conn:
        cur = conn.execute("INSERT INTO mail_messages(owner_user_id,sender,recipients,cc,subject,body,created_at,is_read,deleted,folder) VALUES(?,?,?,?,?,?,?,?,?,?)", (str(user["id"]), sender, recipient_text, ", ".join(cc), payload.subject, payload.body, now, 1, 0, "sent"))
        sent_id = str(cur.lastrowid)
        local_emails = {x.lower() for x in recipients + cc + bcc}
        if local_emails:
            placeholders = ",".join("?" for _ in local_emails)
            rows = conn.execute(f"SELECT id,email FROM users WHERE lower(email) IN ({placeholders})", tuple(local_emails)).fetchall()
            for target in rows:
                conn.execute("INSERT INTO mail_messages(owner_user_id,sender,recipients,cc,subject,body,created_at,is_read,deleted,folder) VALUES(?,?,?,?,?,?,?,?,?,?)", (str(target["id"]), sender, recipient_text, ", ".join(cc), payload.subject, payload.body, now, 0, 0, "inbox"))
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    external = [x for x in recipients + cc + bcc if x.lower() != sender.lower()]
    if smtp_host and external:
        msg = EmailMessage(); msg["From"] = sender; msg["To"] = ", ".join(recipients)
        if cc: msg["Cc"] = ", ".join(cc)
        msg["Subject"] = payload.subject; msg.set_content(payload.body)
        with smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587")), timeout=20) as smtp:
            if os.getenv("SMTP_TLS", "true").lower() == "true": smtp.starttls()
            username = os.getenv("SMTP_USERNAME", "")
            if username: smtp.login(username, os.getenv("SMTP_PASSWORD", ""))
            smtp.send_message(msg, to_addrs=external)
    return {"ok": True, "id": sent_id}
