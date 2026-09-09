from __future__ import annotations

import hashlib
import secrets

import httpx

from app.config import settings
from app.db import connection


FIREBASE_LOOKUP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:lookup"


def verify_firebase_id_token(id_token: str) -> dict[str, object] | None:
    """Validate a Firebase ID token through Firebase Auth REST using the Render API key."""
    api_key = settings.firebase_api_key.strip()
    if not api_key or not id_token.strip():
        return None

    try:
        response = httpx.post(
            FIREBASE_LOOKUP_URL,
            params={"key": api_key},
            json={"idToken": id_token.strip()},
            timeout=10.0,
        )
        if response.status_code != 200:
            return None
        payload = response.json()
        users = payload.get("users") or []
        if not users:
            return None
        firebase_user = users[0]
        if firebase_user.get("localId") is None:
            return None
        return firebase_user
    except (httpx.HTTPError, ValueError, TypeError):
        return None


def get_or_create_local_user(firebase_user: dict[str, object]) -> dict[str, object] | None:
    """Map a verified Firebase identity to the existing Aither user/data model."""
    firebase_uid = str(firebase_user.get("localId", "")).strip()
    email = str(firebase_user.get("email", "")).strip().lower()
    if not firebase_uid or not email:
        return None

    user_id = f"firebase:{firebase_uid}"
    name = str(firebase_user.get("displayName") or email.split("@", 1)[0] or "Aither User").strip()
    verified = bool(firebase_user.get("emailVerified", False))

    with connection() as conn:
        row = conn.execute(
            "SELECT id,name,email,email_verified FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            existing = conn.execute(
                "SELECT id,name,email,email_verified FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            if existing:
                user_id = str(existing["id"])
                row = existing
            else:
                password_hash = "firebase$" + hashlib.sha256(secrets.token_bytes(32)).hexdigest()
                created_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO users(id,name,email,password_hash,email_verified,created_at) VALUES(?,?,?,?,?,?)",
                    (user_id, name, email, password_hash, int(verified), created_at),
                )
                row = conn.execute(
                    "SELECT id,name,email,email_verified FROM users WHERE id = ?",
                    (user_id,),
                ).fetchone()

    if not row:
        return None
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "email_verified": bool(row["email_verified"]),
        "firebase": True,
    }
