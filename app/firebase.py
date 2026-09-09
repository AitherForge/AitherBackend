from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import firebase_admin
from firebase_admin import credentials, firestore, storage


_DEFAULT_SECRET_FILES = (
    "/etc/secrets/firebase-service-account.json",
    "/etc/secrets/firebase_service_account.json",
    "/etc/secrets/firebase.json",
    "/etc/secrets/service-account.json",
)

_app = None
_db = None
_bucket = None


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


def _initialize() -> None:
    global _app
    if _app is not None:
        return

    source = _service_account_source()
    if source is None:
        raise RuntimeError(
            "Firebase service account not configured. Add the JSON as a Render Secret File "
            "and set FIREBASE_SERVICE_ACCOUNT_FILE to /etc/secrets/<filename> if it is not one of the default names."
        )

    cred = credentials.Certificate(source)
    project_id = os.getenv("FIREBASE_PROJECT_ID", "aither-66da8").strip() or "aither-66da8"
    bucket_name = os.getenv("FIREBASE_STORAGE_BUCKET", "").strip() or None
    options: dict[str, str] = {"projectId": project_id}
    if bucket_name:
        options["storageBucket"] = bucket_name
    _app = firebase_admin.initialize_app(cred, options)


def db():
    global _db
    if _db is not None:
        return _db
    _initialize()
    _db = firestore.client(app=_app)
    return _db


def firebase_storage_enabled() -> bool:
    return firebase_enabled() and bool(os.getenv("FIREBASE_STORAGE_BUCKET", "").strip())


def firebase_storage_bucket():
    global _bucket
    if _bucket is not None:
        return _bucket
    if not firebase_storage_enabled():
        raise RuntimeError("FIREBASE_STORAGE_BUCKET is not configured.")
    _initialize()
    _bucket = storage.bucket(app=_app)
    return _bucket


def user_app_ref(user_id: str, app_id: str):
    return db().collection("users").document(user_id).collection("apps").document(app_id)


def all_user_apps(user_id: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for snapshot in db().collection("users").document(user_id).collection("apps").stream():
        value = snapshot.to_dict() or {}
        result[snapshot.id] = value
    return result
