"""
Proxy routes — intercepts LLM API requests, scrubs PII, forwards,
then reconstructs the response.

Flow:
  Client → POST /proxy/chat
         → Aegis scrubs payload
         → Aegis forwards to upstream LLM (OpenAI-compatible)
         → Aegis reconstructs response tokens
         → Client receives clean response
"""

import os
import time
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.scrubber import Scrubber
from core.vault import Vault

router = APIRouter()

# Default upstream — can be any OpenAI-compatible endpoint
UPSTREAM_URL = os.getenv("UPSTREAM_LLM_URL", "https://api.openai.com/v1/chat/completions")
UPSTREAM_KEY = os.getenv("UPSTREAM_API_KEY", "")

_scrubber = Scrubber()
_vault = Vault()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class Message(BaseModel):
    role: str
    content: str


class ProxyRequest(BaseModel):
    messages: list[Message]
    model: str = "gpt-3.5-turbo"
    temperature: float = 0.7
    max_tokens: int = 512
    upstream_url: Optional[str] = None   # override per-request if needed
    upstream_key: Optional[str] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.post("/chat")
async def proxy_chat(payload: ProxyRequest):
    """
    Main proxy endpoint.
    Scrubs all message content before forwarding to the LLM,
    then reconstructs the response.
    """
    t_start = time.perf_counter()

    # --- Step 1: Scrub each message ---
    scrub_reports = []
    sanitized_messages = []

    for msg in payload.messages:
        result = _scrubber.scrub(msg.content)

        # Store redacted values in vault for later reconstruction
        for r in result.redactions:
            token = _vault.store(r["value"], r["label"])
            # Replace [LABEL] placeholder with actual vault token in sanitized text
            result = _scrubber.scrub(msg.content)  # re-run for clean token substitution

        scrub_reports.append({
            "role": msg.role,
            "redactions": len(result.redactions),
            "processing_ms": result.processing_ms,
        })

        sanitized_messages.append({
            "role": msg.role,
            "content": result.sanitized,
        })

    # --- Step 2: Forward to upstream LLM ---
    upstream = payload.upstream_url or UPSTREAM_URL
    api_key = payload.upstream_key or UPSTREAM_KEY

    upstream_payload = {
        "model": payload.model,
        "messages": sanitized_messages,
        "temperature": payload.temperature,
        "max_tokens": payload.max_tokens,
    }

    llm_response_text = None
    upstream_error = None

    if api_key:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    upstream,
                    json=upstream_payload,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                llm_data = resp.json()
                llm_response_text = llm_data["choices"][0]["message"]["content"]
        except Exception as e:
            upstream_error = str(e)
    else:
        # No API key configured — return sanitized payload for inspection/testing
        upstream_error = "No upstream API key configured. Set UPSTREAM_API_KEY env var."

    # --- Step 3: Reconstruct response (replace vault tokens with originals) ---
    reconstructed = None
    if llm_response_text:
        reconstructed = _vault.reconstruct(llm_response_text)

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 3)

    return JSONResponse({
        "aegis": {
            "total_ms": elapsed_ms,
            "messages_processed": len(payload.messages),
            "scrub_reports": scrub_reports,
            "vault_stats": _vault.stats(),
        },
        "sanitized_request": sanitized_messages,
        "llm_response": reconstructed,
        "upstream_error": upstream_error,
    })


@router.post("/scrub-only")
async def scrub_only(request: Request):
    """
    Scrub endpoint — sanitizes text without forwarding to any LLM.
    Useful for testing and integration without an API key.
    """
    body = await request.json()
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="'text' field required")

    result = _scrubber.scrub(text)

    return JSONResponse({
        "original": result.original,
        "sanitized": result.sanitized,
        "redactions": result.redactions,
        "processing_ms": result.processing_ms,
        "regex_matches": result.regex_matches,
        "ac_matches": result.ac_matches,
    })


@router.delete("/vault")
async def clear_vault():
    """Clear all stored token mappings."""
    _vault.clear()
    return {"message": "Vault cleared."}


@router.get("/vault/stats")
async def vault_stats():
    return _vault.stats()
