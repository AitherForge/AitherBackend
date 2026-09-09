from __future__ import annotations

import os
from datetime import timedelta

from fastapi import APIRouter, Cookie, File, Header, HTTPException, UploadFile
from fastapi.responses import Response
from firebase_admin import get_app, storage

from app.api.auth import SESSION_COOKIE, authenticated_user
from app.firebase import _initialize

router = APIRouter(prefix="/api/storage", tags=["storage"])


def _user_id(aither_session: str | None, authorization: str | None) -> str:
    user = authenticated_user(aither_session, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return str(user["id"])


def _storage_bucket():
    try:
        _initialize()
        app = get_app()
        configured = os.getenv("FIREBASE_STORAGE_BUCKET", "").strip()
        if configured:
            return storage.bucket(configured, app=app)
        project_id = os.getenv("FIREBASE_PROJECT_ID", "aither-66da8").strip() or "aither-66da8"
        last_error: Exception | None = None
        for name in (f"{project_id}.firebasestorage.app", f"{project_id}.appspot.com"):
            candidate = storage.bucket(name, app=app)
            try:
                if candidate.exists():
                    return candidate
            except Exception as exc:
                last_error = exc
        raise RuntimeError("No Firebase Storage bucket found.") from last_error
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Firebase Storage is unavailable.") from exc


def _safe_name(name: str | None) -> str:
    value = str(name or "file").replace("\\", "_")
    for char in "/#?%*:|\"<>":
        value = value.replace(char, "_")
    return value[:180] or "file"


def _prefix(user_id: str) -> str:
    return f"users/{user_id}/"


def _key(user_id: str, name: str) -> str:
    import secrets
    from time import time_ns
    return f"{_prefix(user_id)}{time_ns()}-{secrets.token_hex(16)}-{_safe_name(name)}"


@router.get("/health")
async def storage_health() -> dict[str, object]:
    try:
        bucket = _storage_bucket()
        return {"ok": bool(bucket.exists()), "storage": "Firebase Storage", "configured": True}
    except HTTPException as exc:
        return {"ok": False, "storage": "Firebase Storage", "configured": False, "error": exc.detail}


@router.get("/files")
async def list_files(
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user_id = _user_id(aither_session, authorization)
    bucket = _storage_bucket()
    try:
        files = []
        for blob in bucket.list_blobs(prefix=_prefix(user_id)):
            name = blob.name.rsplit("/", 1)[-1]
            display_name = name.split("-", 2)[-1] if name.count("-") >= 2 else name
            files.append({"key": blob.name, "name": display_name, "size": int(blob.size or 0), "added": blob.time_created.isoformat() if blob.time_created else None, "type": blob.content_type or "application/octet-stream"})
        return {"files": files}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Unable to list files.") from exc


@router.post("/files", status_code=201)
async def upload_file(
    file: UploadFile = File(...),
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user_id = _user_id(aither_session, authorization)
    bucket = _storage_bucket()
    key = _key(user_id, file.filename or "file")
    blob = bucket.blob(key)
    try:
        await file.seek(0)
        blob.upload_from_file(file.file, content_type=file.content_type or "application/octet-stream", rewind=True)
        blob.reload()
        return {"key": key, "name": _safe_name(file.filename), "size": int(blob.size or 0)}
    except Exception as exc:
        try:
            blob.delete()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Unable to upload file.") from exc
    finally:
        await file.close()


@router.get("/files/url")
async def file_url(
    key: str,
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    user_id = _user_id(aither_session, authorization)
    if not key.startswith(_prefix(user_id)):
        raise HTTPException(status_code=403, detail="Forbidden")
    bucket = _storage_bucket()
    try:
        blob = bucket.blob(key)
        if not blob.exists():
            raise HTTPException(status_code=404, detail="File not found")
        return {"url": blob.generate_signed_url(version="v4", expiration=timedelta(minutes=15), method="GET")}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=404, detail="File not found") from exc


@router.delete("/files")
async def delete_file(
    key: str,
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> Response:
    user_id = _user_id(aither_session, authorization)
    if not key.startswith(_prefix(user_id)):
        raise HTTPException(status_code=403, detail="Forbidden")
    bucket = _storage_bucket()
    try:
        bucket.blob(key).delete()
    except Exception as exc:
        if "Not Found" not in str(exc) and "404" not in str(exc):
            raise HTTPException(status_code=500, detail="Unable to delete file.") from exc
    return Response(status_code=204)
