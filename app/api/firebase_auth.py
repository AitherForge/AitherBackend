from __future__ import annotations

import secrets
import uuid

import firebase_admin
from fastapi import APIRouter, HTTPException, Response
from firebase_admin import auth as firebase_auth
from pydantic import BaseModel, Field

from app.api.auth import create_session, hash_password, set_session_cookie, user_payload
from app.db import connection

router = APIRouter(prefix="/api/auth", tags=["firebase-auth"])


class FirebaseTokenRequest(BaseModel):
    id_token: str = Field(min_length=20, max_length=10000)


def _firebase_app() -> firebase_admin.App:
    try:
        return firebase_admin.get_app()
    except ValueError:
        return firebase_admin.initialize_app()


@router.post("/firebase")
async def exchange_firebase_token(payload: FirebaseTokenRequest, response: Response) -> dict[str, object]:
    try:
        _firebase_app()
        decoded = firebase_auth.verify_id_token(payload.id_token)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired Firebase ID token.") from exc

    email = str(decoded.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="The Firebase account must have an email address.")

    name = str(decoded.get("name") or decoded.get("email") or "Aither User").strip()[:80]
    verified = bool(decoded.get("email_verified"))
    firebase_uid = str(decoded.get("uid") or "").strip()
    if not firebase_uid:
        raise HTTPException(status_code=401, detail="Firebase token did not contain a user ID.")

    with connection() as conn:
        row = conn.execute("SELECT id,name,email,email_verified FROM users WHERE email = ?", (email,)).fetchone()
        if row:
            user_id = row["id"]
            if verified and not row["email_verified"]:
                conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?", (user_id,))
            display_name = row["name"] or name
            email_verified = bool(row["email_verified"]) or verified
        else:
            user_id = f"firebase_{firebase_uid}"
            existing_id = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
            if existing_id:
                user_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO users(id,name,email,password_hash,email_verified,created_at) VALUES(?,?,?,?,?,datetime('now'))",
                (user_id, name, email, hash_password(secrets.token_urlsafe(48)), 1 if verified else 0),
            )
            display_name = name
            email_verified = verified

    session_token = create_session(user_id)
    set_session_cookie(response, session_token)
    return {
        "authenticated": True,
        "session_token": session_token,
        "user": user_payload(user_id, display_name, email, email_verified),
        "firebase_uid": firebase_uid,
    }
