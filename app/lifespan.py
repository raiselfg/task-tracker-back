from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import get_settings
from app.db.redis import create_redis
from app.db.session import create_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    engine, factory = create_database(settings)
    redis = create_redis(settings)
    app.state.redis = redis
    app.state.engine = engine
    app.state.session_factory = factory
    try:
        yield
    finally:
        try:
            await redis.aclose()
        finally:
            await engine.dispose()
