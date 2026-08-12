from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
import httpx

from routes.proxy import router as proxy_router
from routes.health import router as health_router

MAX_PAYLOAD_SIZE = 2 * 1024 * 1024  # 2 MB payload cap

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fix 1: Initialize shared HTTP connection pool on startup
    app.state.client = httpx.AsyncClient(
        limits=httpx.Limits(max_keepalive_connections=100, max_connections=1000)
    )
    yield
    # Clean up socket pool on app shutdown
    await app.state.client.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Aegis",
        description="Low-Latency PII & Token Masking Proxy for LLM APIs",
        version="1.0.0",
        lifespan=lifespan,  # Attach connection pool lifecycle
    )

    # Fix 2: Middleware guarding against massive payloads (RAM protection)
    @app.middleware("http")
    async def limit_payload_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_PAYLOAD_SIZE:
            raise HTTPException(status_code=413, detail="Payload too large")
        return await call_next(request)

    app.include_router(health_router, tags=["health"])
    app.include_router(proxy_router, prefix="/proxy", tags=["proxy"])

    return app
