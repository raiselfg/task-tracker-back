import socket
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from fastapi import FastAPI
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import SQLAlchemyError

from app.api.routers.health import router
from app.core.config import Settings
from app.db.session import create_database


@pytest.mark.parametrize(
    "error",
    [ConnectionRefusedError(), OSError(), TimeoutError(), SQLAlchemyError()],
)
async def test_readiness_reports_database_connection_errors(error):
    app = FastAPI()
    app.include_router(router)
    app.state.engine = Mock()
    app.state.engine.connect.side_effect = error
    app.state.redis = AsyncMock()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
    app.state.redis.ping.assert_not_awaited()


async def test_readiness_reports_real_asyncpg_connection_refusal():
    # Reserve a local port without listening: no connection can be accepted.
    with socket.socket() as unused_port:
        unused_port.bind(("127.0.0.1", 0))
        port = unused_port.getsockname()[1]
        settings = Settings(
            _env_file=None, database_url=f"postgresql://test:test@127.0.0.1:{port}/test"
        )
        engine, _ = create_database(settings)
        app = FastAPI()
        app.include_router(router)
        app.state.engine = engine
        app.state.redis = AsyncMock()
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                response = await client.get("/ready")
            assert response.status_code == 503
            assert response.json() == {"status": "not_ready"}
        finally:
            await engine.dispose()


async def test_readiness_reports_redis_connection_error():
    app = FastAPI()
    app.include_router(router)
    connection = AsyncMock()
    app.state.engine = Mock()
    app.state.engine.connect.return_value.__aenter__ = AsyncMock(return_value=connection)
    app.state.engine.connect.return_value.__aexit__ = AsyncMock(return_value=False)
    app.state.redis = AsyncMock()
    app.state.redis.ping.side_effect = RedisConnectionError()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
