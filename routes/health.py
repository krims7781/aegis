from fastapi import APIRouter
from fastapi.responses import JSONResponse
import time

router = APIRouter()

_start_time = time.time()

@router.get("/health")
async def health():
    return JSONResponse({
        "status": "ok",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "service": "aegis",
        "version": "1.0.0",
    })
