"""
App factory — wires up routes and middleware.
"""

from fastapi import FastAPI
from routes.proxy import router as proxy_router
from routes.health import router as health_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Aegis",
        description="Low-Latency PII & Token Masking Proxy for LLM APIs",
        version="1.0.0",
    )

    app.include_router(health_router, tags=["health"])
    app.include_router(proxy_router, prefix="/proxy", tags=["proxy"])

    return app
