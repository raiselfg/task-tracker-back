"""Run only against dedicated test services via AUTH_TEST_* environment variables."""

import asyncio
import os
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, update

from app.core.config import Settings
from app.core.security import token_hash, utc_now
from app.db.base import Base
from app.db.redis import create_redis
from app.db.session import create_database
from app.models.session import Session
from app.models.user import User
from app.repository.session_cache import SessionCache
from app.services.auth import AuthenticationRequiredError, AuthService, Principal

pytestmark = pytest.mark.skipif(
    not (os.getenv("AUTH_TEST_DATABASE_URL") and os.getenv("AUTH_TEST_REDIS_URL")),
    reason="Set AUTH_TEST_DATABASE_URL and AUTH_TEST_REDIS_URL to dedicated test services",
)


async def test_logout_with_redis_loss_cannot_be_undone_by_inflight_cache_fill():
    settings = Settings(
        _env_file=None,
        app_env="development",
        database_url=os.environ["AUTH_TEST_DATABASE_URL"],
        redis_url=os.environ["AUTH_TEST_REDIS_URL"],
    )
    engine, factory = create_database(settings)
    redis = create_redis(settings)
    user_id = None
    key = None
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory() as db:
            service = AuthService(db, settings)
            user = await service.register("test_" + uuid4().hex[:20], "secret")
            user_id = user.id
            _, token = await service.login(user.login, "secret")
            row = await db.scalar(select(Session).where(Session.token_hash == token_hash(token)))
            principal = Principal(user, row)
        key = SessionCache.key(token_hash(token))
        async with factory() as fill_db, factory() as logout_db:
            fill = AuthService(fill_db, settings, cache=SessionCache(redis))
            logout = AuthService(logout_db, settings, cache=SessionCache(redis))
            fill_started, resume_fill, logout_started = (
                asyncio.Event(),
                asyncio.Event(),
                asyncio.Event(),
            )
            original_put = fill.cache.put
            original_delete = logout.sessions.delete

            async def delayed_put(*args):
                fill_started.set()
                await resume_fill.wait()
                return await original_put(*args)

            async def observed_delete(*args):
                logout_started.set()
                await original_delete(*args)

            fill.cache.put = delayed_put
            logout.sessions.delete = observed_delete
            pending_fill = asyncio.create_task(fill.authenticate(token))
            pending_logout = None
            try:
                await asyncio.wait_for(fill_started.wait(), timeout=5)
                pending_logout = asyncio.create_task(logout.logout(principal))
                await asyncio.wait_for(logout_started.wait(), timeout=5)
                # With the old ordering logout completes while the stale fill waits.
                # With row locking logout cannot finish until the fill commits.
                await asyncio.wait({pending_logout}, timeout=0.2)
                await redis.delete(key)  # Lose only this test's key, as on Redis restart.
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
            service = AuthService(db, settings, cache=SessionCache(redis))
            with pytest.raises(AuthenticationRequiredError):
                await service.authenticate(token)
        assert await redis.get(key) == "revoked"
    finally:
        if user_id is not None:
            async with factory() as db:
                await db.execute(delete(User).where(User.id == user_id))
                await db.commit()
        if key is not None:
            await redis.delete(key)
        await redis.aclose()
        await engine.dispose()


async def test_failed_commit_cannot_extend_access_through_redis():
    from datetime import timedelta
    from types import SimpleNamespace

    settings = Settings(
        _env_file=None,
        app_env="development",
        database_url=os.environ["AUTH_TEST_DATABASE_URL"],
        redis_url=os.environ["AUTH_TEST_REDIS_URL"],
    )
    engine, factory = create_database(settings)
    redis = create_redis(settings)
    user_id = key = None
    clock = SimpleNamespace(now=utc_now())
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with factory() as db:
            service = AuthService(db, settings, lambda: clock.now)
            user = await service.register("test_" + uuid4().hex[:20], "secret")
            user_id = user.id
            _, token = await service.login(user.login, "secret")
            digest = token_hash(token)
            key = SessionCache.key(digest)
            confirmed_expiry = clock.now + timedelta(seconds=2)
            await db.execute(
                update(Session)
                .where(Session.token_hash == digest)
                .values(expires_at=confirmed_expiry)
            )
            await db.commit()
        async with factory() as db:
            service = AuthService(db, settings, lambda: clock.now, cache=SessionCache(redis))

            async def failed_commit():
                await db.rollback()
                raise ConnectionError("Simulated commit failure with real PostgreSQL rollback")

            db.commit = failed_commit
            with pytest.raises(ConnectionError):
                await service.authenticate(token)
        cached = await SessionCache(redis).get(digest)
        assert cached.expires_at == confirmed_expiry
        async with factory() as db:
            expiry = await db.scalar(select(Session.expires_at).where(Session.token_hash == digest))
            assert expiry == confirmed_expiry
            clock.now = confirmed_expiry + timedelta(seconds=1)
            service = AuthService(db, settings, lambda: clock.now, cache=SessionCache(redis))
            with pytest.raises(AuthenticationRequiredError):
                await service.authenticate(token)
    finally:
        if user_id is not None:
            async with factory() as db:
                await db.execute(delete(User).where(User.id == user_id))
                await db.commit()
        if key is not None:
            await redis.delete(key)
        await redis.aclose()
        await engine.dispose()
