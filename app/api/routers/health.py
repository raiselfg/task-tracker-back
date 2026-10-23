from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request):
    try:
        async with request.app.state.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        await request.app.state.redis.ping()
        return {"status": "ready"}
    except SQLAlchemyError, RedisError, OSError, TimeoutError:
        return JSONResponse({"status": "not_ready"}, status_code=503)
