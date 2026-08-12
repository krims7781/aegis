@router.post("/chat")
async def proxy_chat(payload: ProxyRequest):
    vault = Vault()  # Fresh, isolated vault for this specific request

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

        # Step 2: Forward to LLM (httpx call)...

        # Step 3: Reconstruct response
        reconstructed = (
            vault.reconstruct(llm_response_text) if llm_response_text else None
        )

        return JSONResponse({"llm_response": reconstructed, ...})

    finally:
        vault.close()  # Instantly frees RAM
