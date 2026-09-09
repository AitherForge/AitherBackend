from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import firebase_admin
from firebase_admin import credentials, firestore


_DEFAULT_SECRET_FILES = (
    "/etc/secrets/firebase-service-account.json",
    "/etc/secrets/firebase_service_account.json",
    "/etc/secrets/firebase.json",
    "/etc/secrets/service-account.json",
)

_app = None
_db = None


def _service_account_source() -> str | dict[str, Any] | None:
    """Find Firebase Admin credentials without ever logging their contents."""
    configured = os.getenv("FIREBASE_SERVICE_ACCOUNT_FILE", "").strip()
    candidates = ([configured] if configured else []) + list(_DEFAULT_SECRET_FILES)
    for filename in candidates:
        if not filename:
            continue
        path = Path(filename)
        if path.is_file():
            return str(path)

    raw = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    return None


def firebase_enabled() -> bool:
    return _service_account_source() is not None


def db():
    global _app, _db
    if _db is not None:
        return _db

    source = _service_account_source()
    if source is None:
        raise RuntimeError(
            "Firebase service account not configured. Add the JSON as a Render Secret File "
            "and set FIREBASE_SERVICE_ACCOUNT_FILE to /etc/secrets/<filename> if it is not one of the default names."
        )

    if isinstance(source, str):
        cred = credentials.Certificate(source)
    else:
        cred = credentials.Certificate(source)

    project_id = os.getenv("FIREBASE_PROJECT_ID", "aither-66da8").strip() or "aither-66da8"
    _app = firebase_admin.initialize_app(cred, {"projectId": project_id})
    _db = firestore.client(app=_app)
    return _db


def user_app_ref(user_id: str, app_id: str):
    return db().collection("users").document(user_id).collection("apps").document(app_id)


def all_user_apps(user_id: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for snapshot in db().collection("users").document(user_id).collection("apps").stream():
        value = snapshot.to_dict() or {}
        result[snapshot.id] = value
    return result
