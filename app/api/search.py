from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query

from app.config import settings

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
async def search(
    q: str = Query(min_length=1, max_length=500),
    page: int = Query(default=1, ge=1, le=100),
    num: int = Query(default=10, ge=1, le=20),
    device: str = Query(default="desktop", pattern="^(desktop|mobile|tablet)$"),
    location: str | None = Query(default=None, max_length=200),
    language: str | None = Query(default=None, max_length=50),
) -> dict[str, Any]:
    """Search the public web through the server-side Serpstack credential."""
    if not settings.serpstack_api_key:
        raise HTTPException(
            status_code=503,
            detail="Serpstack is not configured on AitherBackend. Add SERPSTACK_API_KEY as a Render secret.",
        )

    params: dict[str, Any] = {
        "access_key": settings.serpstack_api_key,
        "query": q,
        "page": page,
        "num": num,
        "device": device,
    }
    if location:
        params["location"] = location
    if language:
        params["language"] = language

    try:
        async with httpx.AsyncClient(timeout=settings.serpstack_timeout_seconds) as client:
            response = await client.get(settings.serpstack_url, params=params)
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Serpstack timed out.") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Could not reach Serpstack.") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Serpstack returned invalid JSON.") from exc

    if response.status_code >= 400 or data.get("success") is False:
        error = data.get("error")
        if isinstance(error, dict):
            detail = error.get("info") or error.get("message") or "Serpstack request failed."
        else:
            detail = "Serpstack request failed."
        raise HTTPException(status_code=502, detail=str(detail))

    organic = data.get("organic_results") or []
    results = []
    for item in organic:
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "position": item.get("position"),
                "title": item.get("title"),
                "url": item.get("url") or item.get("link"),
                "displayed_url": item.get("displayed_url"),
                "snippet": item.get("snippet") or item.get("description"),
                "date": item.get("date"),
            }
        )

    return {
        "success": True,
        "provider": "serpstack",
        "query": q,
        "page": page,
        "results": results,
        "total_results": (data.get("search_information") or {}).get("total_results"),
        "raw": data,
    }
