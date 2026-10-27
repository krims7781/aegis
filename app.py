from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
import httpx

from core.db import init_db
from core.trie_registry import PersistentTrieRegistry
from routes.proxy import router as proxy_router
from routes.health import router as health_router
from routes.admin import router as admin_router

MAX_PAYLOAD_SIZE = 2 * 1024 * 1024  # 2 MB payload cap
trie_registry = PersistentTrieRegistry()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize SQLite rules DB
    init_db()

    # 2. Hydrate rules into RAM Tries on startup
    await trie_registry.hydrate_from_db()
    app.state.trie_registry = trie_registry

    # 3. Connection pool
    app.state.client = httpx.AsyncClient(
        limits=httpx.Limits(max_keepalive_connections=100, max_connections=1000)
    )
    yield
    await app.state.client.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Aegis",
        description="Low-Latency PII & Token Masking Proxy for LLM APIs",
        version="1.0.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def limit_payload_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_PAYLOAD_SIZE:
            raise HTTPException(status_code=413, detail="Payload too large")
        return await call_next(request)

    app.include_router(health_router, tags=["health"])
    app.include_router(proxy_router, prefix="/proxy", tags=["proxy"])
    app.include_router(admin_router, tags=["admin"])

    return app
