from __future__ import annotations

from fastapi import APIRouter, Cookie, File, Header, HTTPException, UploadFile
from fastapi.responses import Response

from app.api.auth import SESSION_COOKIE, authenticated_user
from app.firebase import firebase_storage_bucket, firebase_storage_enabled

router = APIRouter(prefix="/api/storage", tags=["storage"])


def _user_id(aither_session: str | None, authorization: str | None) -> str:
    user = authenticated_user(aither_session, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return str(user["id"])


def _require_storage() -> object:
    if not firebase_storage_enabled():
        raise HTTPException(status_code=503, detail="Firebase Storage is not configured on AitherBackendNew.")
    try:
        return firebase_storage_bucket()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Firebase Storage is unavailable.") from exc


def _safe_name(name: str | None) -> str:
    value = str(name or "file")
    value = value.replace("\\", "_")
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
    if not firebase_storage_enabled():
        return {"ok": False, "storage": "Firebase Storage", "configured": False}
    try:
        bucket = firebase_storage_bucket()
        # A metadata request validates credentials/bucket access without listing user files.
        bucket.get_iam_policy(requested_policy_version=3)
        return {"ok": True, "storage": "Firebase Storage", "configured": True}
    except Exception as exc:
        return {"ok": False, "storage": "Firebase Storage", "configured": True, "error": str(exc)}


@router.get("/files")
async def list_files(
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user_id = _user_id(aither_session, authorization)
    bucket = _require_storage()
    try:
        blobs = bucket.list_blobs(prefix=_prefix(user_id))
        files = []
        for blob in blobs:
            name = blob.name.rsplit("/", 1)[-1]
            display_name = name.split("-", 2)[-1] if name.count("-") >= 2 else name
            files.append({
                "key": blob.name,
                "name": display_name,
                "size": int(blob.size or 0),
                "added": blob.time_created.isoformat() if blob.time_created else None,
                "type": blob.content_type or "application/octet-stream",
            })
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
    bucket = _require_storage()
    key = _key(user_id, file.filename or "file")
    blob = bucket.blob(key)
    try:
        # UploadFile is backed by a spooled temporary file, so the whole upload is not
        # required to live in RAM. This keeps large uploads practical on Render.
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
    bucket = _require_storage()
    try:
        blob = bucket.blob(key)
        if not blob.exists():
            raise HTTPException(status_code=404, detail="File not found")
        from datetime import timedelta
        url = blob.generate_signed_url(version="v4", expiration=timedelta(minutes=15), method="GET")
        return {"url": url}
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
    bucket = _require_storage()
    try:
        bucket.blob(key).delete(if_generation_match=None)
    except Exception as exc:
        # Treat an already-missing object as successfully deleted.
        if "Not Found" not in str(exc) and "404" not in str(exc):
            raise HTTPException(status_code=500, detail="Unable to delete file.") from exc
    return Response(status_code=204)
