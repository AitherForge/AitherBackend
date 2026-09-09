from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Cookie, Header, HTTPException
from pydantic import BaseModel, Field
from google.cloud.firestore_v1 import SERVER_TIMESTAMP

from app.api.auth import SESSION_COOKIE, authenticated_user
from app.firebase import all_user_apps, firebase_enabled, user_app_ref

router = APIRouter(prefix="/api/data", tags=["data"])


def _user_id(aither_session: str | None, authorization: str | None) -> str:
    user = authenticated_user(aither_session, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return str(user["id"])


def _require_firebase() -> None:
    if not firebase_enabled():
        raise HTTPException(
            status_code=503,
            detail="Firebase storage is not configured on AitherBackendNew.",
        )


class AppData(BaseModel):
    data: dict = Field(default_factory=dict)


@router.get("")
async def get_all_data(
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user_id = _user_id(aither_session, authorization)
    _require_firebase()
    apps = all_user_apps(user_id)
    return {"apps": apps}


@router.get("/{app_id}")
async def get_app_data(
    app_id: str,
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user_id = _user_id(aither_session, authorization)
    _require_firebase()
    if not app_id or len(app_id) > 80 or any(
        c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in app_id
    ):
        raise HTTPException(status_code=400, detail="Invalid app id.")
    snapshot = user_app_ref(user_id, app_id).get()
    if not snapshot.exists:
        return {"app_id": app_id, "data": {}, "updated_at": None}
    value = snapshot.to_dict() or {}
    return {"app_id": app_id, "data": value.get("data", {}), "updated_at": value.get("updated_at")}


@router.put("/{app_id}")
async def put_app_data(
    app_id: str,
    payload: AppData,
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user_id = _user_id(aither_session, authorization)
    _require_firebase()
    if not app_id or len(app_id) > 80 or any(
        c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in app_id
    ):
        raise HTTPException(status_code=400, detail="Invalid app id.")

    # Firestore documents are limited to 1 MiB. Keep the existing API's
    # conservative 2 MB request guard, while enforcing the actual limit here.
    import json
    encoded = json.dumps(payload.data, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 900_000:
        raise HTTPException(status_code=413, detail="App data is too large for Firebase storage.")

    now = datetime.now(timezone.utc).isoformat()
    user_app_ref(user_id, app_id).set(
        {"data": payload.data, "updated_at": now, "updated_at_server": SERVER_TIMESTAMP},
        merge=True,
    )
    return {"ok": True, "app_id": app_id, "updated_at": now}


@router.delete("/{app_id}")
async def delete_app_data(
    app_id: str,
    aither_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    user_id = _user_id(aither_session, authorization)
    _require_firebase()
    user_app_ref(user_id, app_id).delete()
    return {"ok": True, "app_id": app_id}
