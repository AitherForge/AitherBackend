from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import httpx

from app.config import settings

router = APIRouter(prefix="/api/ai", tags=["ai"])


class Message(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str = Field(min_length=1, max_length=20000)


class ChatRequest(BaseModel):
    messages: list[Message] = Field(min_length=1, max_length=100)
    model: str | None = None


@router.get("/models")
async def models() -> dict[str, list[str]]:
    available = []
    if settings.openrouter_api_key:
        available.append(settings.ai_model)
    if settings.gemini_api_key:
        available.append(settings.gemini_model)
    return {"models": available}


async def gemini_chat(request: ChatRequest) -> dict[str, object]:
    if not settings.gemini_api_key:
        raise HTTPException(status_code=503, detail="Gemini is not configured on AitherBackend.")

    contents = []
    for message in request.messages:
        if message.role == "system":
            continue
        contents.append({
            "role": "model" if message.role == "assistant" else "user",
            "parts": [{"text": message.content}],
        })

    system_instruction = next((m.content for m in request.messages if m.role == "system"), None)
    payload = {
        "contents": contents,
        "generationConfig": {"temperature": settings.ai_temperature},
    }
    if system_instruction:
        payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

    model = request.model or settings.gemini_model
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {"x-goog-api-key": settings.gemini_api_key, "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Gemini timed out.") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Could not reach Gemini.") from exc

    if response.status_code >= 400:
        try:
            detail = response.json().get("error", {}).get("message", "Gemini request failed")
        except Exception:
            detail = "Gemini request failed"
        raise HTTPException(status_code=502, detail=str(detail))

    data = response.json()
    parts = (((data.get("candidates") or [{}])[0]).get("content") or {}).get("parts") or []
    content = "".join(part.get("text", "") for part in parts if isinstance(part, dict)).strip()
    if not content:
        raise HTTPException(status_code=502, detail="Gemini returned an empty response.")

    return {"success": True, "reply": content, "model": model, "provider": "gemini"}


@router.post("/chat")
async def chat(request: ChatRequest) -> dict[str, object]:
    # Prefer the existing OpenRouter setup when configured; otherwise use the
    # server-side Gemini secret. The browser never receives either API key.
    if not settings.openrouter_api_key:
        return await gemini_chat(request)

    payload = {
        "model": request.model or settings.ai_model,
        "messages": [message.model_dump() for message in request.messages],
        "temperature": settings.ai_temperature,
    }
    headers = {
        "Authorization": f"Bearer {settings.openrouter_api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": settings.app_url,
        "X-Title": "Aither AI",
    }

    try:
        async with httpx.AsyncClient(timeout=settings.ai_timeout_seconds) as client:
            response = await client.post(settings.openrouter_url, json=payload, headers=headers)
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Aither AI provider timed out.") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Could not reach the Aither AI provider.") from exc

    if response.status_code >= 400:
        try:
            error = response.json().get("error", {}).get("message", "Provider request failed")
        except Exception:
            error = "Provider request failed"
        raise HTTPException(status_code=502, detail=str(error))

    data = response.json()
    choices = data.get("choices") or []
    if not choices:
        raise HTTPException(status_code=502, detail="Aither AI provider returned no response.")

    content = choices[0].get("message", {}).get("content", "")
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    content = str(content).strip()
    if not content:
        raise HTTPException(status_code=502, detail="Aither AI provider returned an empty response.")

    return {
        "success": True,
        "reply": content,
        "model": data.get("model") or payload["model"],
        "provider": "openrouter",
    }
