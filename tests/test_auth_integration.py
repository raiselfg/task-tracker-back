"""Run only against dedicated test services via AUTH_TEST_* environment variables."""

import asyncio
import os
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from redis.asyncio import Redis
from sqlalchemy import delete, select, update

from app.core.config import Settings
from app.core.security import token_hash, utc_now
from app.db.base import Base
from app.db.session import create_database
from app.models.session import Session
from app.models.user import User
from app.services.auth import AuthenticationRequiredError, AuthService, Principal

pytestmark = pytest.mark.skipif(
    not os.getenv("AUTH_TEST_DATABASE_URL"),
    reason="Set AUTH_TEST_DATABASE_URL to a dedicated test database",
)


@pytest.fixture
def redis():
    client = AsyncMock(spec=Redis)
    client.get.return_value = None
    return client


async def test_logout_cannot_be_undone_by_inflight_session_refresh(redis):
    settings = Settings(
        _env_file=None,
        app_env="development",
        database_url=os.environ["AUTH_TEST_DATABASE_URL"],
    )
    engine, factory = create_database(settings)
    user_id = None
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory() as db:
            service = AuthService(db, settings, redis=redis)
            user = await service.register("test_" + uuid4().hex[:20], "secret")
            user_id = user.id
            _, token = await service.login(user.login, "secret")
            row = await db.scalar(select(Session).where(Session.token_hash == token_hash(token)))
            principal = Principal(user, row)
        async with factory() as fill_db, factory() as logout_db:
            fill = AuthService(fill_db, settings, redis=redis)
            logout = AuthService(logout_db, settings, redis=redis)
            fill_started, resume_fill, logout_started = (
                asyncio.Event(),
                asyncio.Event(),
                asyncio.Event(),
            )
            original_refresh = fill.sessions.refresh
            original_delete = logout.sessions.delete

            async def delayed_refresh(*args):
                session = await original_refresh(*args)
                fill_started.set()
                await resume_fill.wait()
                return session

            async def observed_delete(*args):
                logout_started.set()
                await original_delete(*args)

            fill.sessions.refresh = delayed_refresh
            logout.sessions.delete = observed_delete
            pending_fill = asyncio.create_task(fill.verify_session(token))
            pending_logout = None
            try:
                await asyncio.wait_for(fill_started.wait(), timeout=5)
                pending_logout = asyncio.create_task(logout.logout(principal))
                await asyncio.wait_for(logout_started.wait(), timeout=5)
                # Logout waits for the row lock held by the session refresh.
                await asyncio.wait({pending_logout}, timeout=0.2)
                resume_fill.set()
                await asyncio.wait_for(asyncio.gather(pending_fill, pending_logout), timeout=5)
            finally:
                resume_fill.set()
                tasks = [task for task in (pending_fill, pending_logout) if task is not None]
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        async with factory() as db:
            assert await db.scalar(select(Session).where(Session.id == row.id)) is None
            service = AuthService(db, settings, redis=redis)
            with pytest.raises(AuthenticationRequiredError):
                await service.verify_session(token)
    finally:
        if user_id is not None:
            async with factory() as db:
                await db.execute(delete(User).where(User.id == user_id))
                await db.commit()
        await engine.dispose()


async def test_failed_commit_cannot_extend_session_expiry(redis):
    from datetime import timedelta
    from types import SimpleNamespace

    settings = Settings(
        _env_file=None,
        app_env="development",
        database_url=os.environ["AUTH_TEST_DATABASE_URL"],
    )
    engine, factory = create_database(settings)
    user_id = None
    clock = SimpleNamespace(now=utc_now())
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory() as db:
            service = AuthService(db, settings, redis=redis, clock=lambda: clock.now)
            user = await service.register("test_" + uuid4().hex[:20], "secret")
            user_id = user.id
            _, token = await service.login(user.login, "secret")
            digest = token_hash(token)
            confirmed_expiry = clock.now + timedelta(seconds=2)
            await db.execute(
                update(Session)
                .where(Session.token_hash == digest)
                .values(expires_at=confirmed_expiry)
            )
            await db.commit()
        async with factory() as db:
            service = AuthService(db, settings, redis=redis, clock=lambda: clock.now)

            async def failed_commit():
                await db.rollback()
                raise ConnectionError("Simulated commit failure with real PostgreSQL rollback")

            db.commit = failed_commit
            with pytest.raises(ConnectionError):
                await service.verify_session(token)
        async with factory() as db:
            expiry = await db.scalar(select(Session.expires_at).where(Session.token_hash == digest))
            assert expiry == confirmed_expiry
            clock.now = confirmed_expiry + timedelta(seconds=1)
            service = AuthService(db, settings, redis=redis, clock=lambda: clock.now)
            with pytest.raises(AuthenticationRequiredError):
                await service.verify_session(token)
    finally:
        if user_id is not None:
            async with factory() as db:
                await db.execute(delete(User).where(User.id == user_id))
                await db.commit()
        await engine.dispose()
