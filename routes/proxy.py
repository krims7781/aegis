import os
from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
import httpx
from pydantic import BaseModel

from core.vault import Vault
from core.scrubber import Scrubber
from core.trie_registry import PersistentTrieRegistry

_scrubber = Scrubber()


class Message(BaseModel):
    role: str
    content: str | None = ""


class ProxyRequest(BaseModel):
    messages: list[Message]


router = APIRouter()


@router.post("/chat")
async def proxy_chat(
    request: Request,
    payload: ProxyRequest,
    x_tenant_id: str = Header(default="_default_")
):
    registry: PersistentTrieRegistry = request.app.state.trie_registry
    tenant_ac = registry.get_trie(x_tenant_id)

    vault = Vault()
    try:
        sanitized_messages = []
        for msg in payload.messages:
            content_to_scrub = msg.content or ""
            result = _scrubber.scrub(content_to_scrub, ac_engine=tenant_ac)

            for r in result.redactions:
                vault.store(r["value"], r["label"])

            sanitized_messages.append(
                {"role": msg.role, "content": result.sanitized}
            )

        client: httpx.AsyncClient = request.app.state.client
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise HTTPException(
                status_code=500, detail="OPENAI_API_KEY environment variable is missing"
            )

        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            json={"messages": sanitized_messages, "model": "gpt-4o"},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code, detail="LLM request failed"
            )

        llm_response_text = response.json()["choices"][0]["message"]["content"]
        reconstructed = vault.reconstruct(llm_response_text) if llm_response_text else None
        return JSONResponse({"llm_response": reconstructed})

    finally:
        vault.close()
