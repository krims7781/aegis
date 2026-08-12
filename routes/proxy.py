from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
import httpx

router = APIRouter()

@router.post("/chat")
async def proxy_chat(request: Request, payload: ProxyRequest):
    vault = Vault()  # Isolated request-scoped memory

    try:
        # Step 1: Scrub & store
        sanitized_messages = []
        for msg in payload.messages:
            result = _scrubber.scrub(msg.content)
            for r in result.redactions:
                vault.store(r["value"], r["label"])
            sanitized_messages.append(
                {"role": msg.role, "content": result.sanitized}
            )

        # Step 2: Forward to LLM using shared application connection pool
        client: httpx.AsyncClient = request.app.state.client
        
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            json={"messages": sanitized_messages, "model": "gpt-4o"},
            headers={"Authorization": "Bearer YOUR_API_KEY"}
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="LLM request failed")

        llm_response_text = response.json()["choices"][0]["message"]["content"]

        # Step 3: Reconstruct response
        reconstructed = (
            vault.reconstruct(llm_response_text) if llm_response_text else None
        )

        return JSONResponse({"llm_response": reconstructed})

    finally:
        vault.close()  # Guaranteed C-level RAM release
