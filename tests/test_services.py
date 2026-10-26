from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from argon2 import PasswordHasher
from asyncpg import UniqueViolationError
from sqlalchemy.dialects.postgresql.asyncpg import AsyncAdapt_asyncpg_dbapi
from sqlalchemy.exc import IntegrityError

import app.services.auth as auth_module
from app.core.security import token_hash
from app.services.auth import (
    AuthenticationRequiredError,
    InvalidCredentialsError,
    LoginAlreadyExistsError,
)
from tests.fakes import make_service

PASSWORD = "long secure password"


@pytest.fixture
def auth():
    clock = SimpleNamespace(now=datetime(2026, 10, 17, tzinfo=UTC))
    return make_service(lambda: clock.now), clock


async def register_and_login(service, login="User"):
    user = await service.register(login, PASSWORD)
    _, token = await service.login(login, PASSWORD)
    return user, token


async def test_case_sensitive_registration_and_login(auth):
    service, _ = auth
    upper, upper_token = await register_and_login(service, "User")
    lower, lower_token = await register_and_login(service, "user")
    assert upper.id != lower.id
    assert (await service.verify_session(upper_token)).user.id == upper.id
    assert (await service.verify_session(lower_token)).user.id == lower.id
    assert service.users.lookups == ["User", "User", "user", "user"]
    with pytest.raises(InvalidCredentialsError):
        await service.login("USER", PASSWORD)


async def test_duplicate_and_no_automatic_login(auth):
    service, _ = auth
    await service.register("User", PASSWORD)
    assert not service.sessions.records
    with pytest.raises(LoginAlreadyExistsError):
        await service.register("User", PASSWORD)


@pytest.mark.parametrize("constraint", ["uq_users_login", "uq_other"])
async def test_registration_conflict_rolls_back(auth, constraint):
    service, _ = auth
    violation = UniqueViolationError("duplicate value")
    violation.constraint_name = constraint
    orig = AsyncAdapt_asyncpg_dbapi.IntegrityError("duplicate value", violation)
    orig.__cause__ = violation
    service.transaction.commit.side_effect = IntegrityError("insert", {}, orig)
    expected_error = LoginAlreadyExistsError if constraint == "uq_users_login" else IntegrityError
    with pytest.raises(expected_error):
        await service.register("User", PASSWORD)
    service.transaction.rollback.assert_awaited_once()
    service.transaction.commit.assert_awaited_once()


async def test_unrelated_integrity_error_not_reported_as_duplicate(auth):
    service, _ = auth
    service.transaction.commit.side_effect = IntegrityError("insert", {}, Exception())
    with pytest.raises(IntegrityError):
        await service.register("User", PASSWORD)
    service.transaction.rollback.assert_awaited_once()


async def test_invalid_credentials_same_response_and_dummy_check(auth, monkeypatch):
    service, _ = auth
    await service.register("User", PASSWORD)
    verify = AsyncMock(wraps=auth_module.verify_password)
    monkeypatch.setattr(auth_module, "verify_password", verify)
    errors = []
    for login, password in [("User", "incorrect password"), ("Missing", PASSWORD)]:
        with pytest.raises(InvalidCredentialsError) as exc:
            await service.login(login, password)
        errors.append((type(exc.value), str(exc.value)))
    assert errors[0] == errors[1]
    assert verify.await_args_list[-1].args == (None, PASSWORD)
    assert not service.sessions.records


async def test_only_token_hash_stored(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    record = next(iter(service.sessions.records.values()))
    assert record.token_hash == token_hash(token)
    assert token not in vars(record).values()


@pytest.mark.parametrize("seconds_after_expiry", [0, 1])
async def test_expiry_at_boundary(auth, seconds_after_expiry):
    service, clock = auth
    _, token = await register_and_login(service)
    record = next(iter(service.sessions.records.values()))
    original_expiry = record.expires_at
    clock.now = original_expiry + timedelta(seconds=seconds_after_expiry)
    with pytest.raises(AuthenticationRequiredError):
        await service.verify_session(token)
    assert record.expires_at == original_expiry


async def test_current_session_revocation(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    current = await service.verify_session(token)
    await service.logout(current)
    with pytest.raises(AuthenticationRequiredError):
        await service.verify_session(token)


@pytest.mark.parametrize("token", [None, "", "invalid", "я" * 43])
async def test_malformed_token_never_reaches_repository(auth, token):
    service, _ = auth
    service.sessions.get_active = AsyncMock()
    with pytest.raises(AuthenticationRequiredError):
        await service.verify_session(token)
    service.sessions.get_active.assert_not_awaited()


async def test_password_rehash_is_saved_on_login(auth):
    service, _ = auth
    user = await service.register("User", PASSWORD)
    old_hash = PasswordHasher(time_cost=1, memory_cost=19456, parallelism=1).hash(PASSWORD)
    user.password_hash = old_hash

    await service.login("User", PASSWORD)

    assert user.password_hash != old_hash
    assert await auth_module.verify_password(user.password_hash, PASSWORD)
    assert not auth_module.needs_rehash(user.password_hash)
    assert service.transaction.commit.await_count == 2


async def test_session_renews_for_thirty_days_on_activity(auth):
    service, clock = auth
    _, token = await register_and_login(service)
    record = next(iter(service.sessions.records.values()))
    assert record.expires_at == clock.now + timedelta(days=30)
    for _ in range(3):
        clock.now += timedelta(days=29)
        current = await service.verify_session(token)
        assert current.session.expires_at == clock.now + timedelta(days=30)


async def test_revoked_session_is_not_restored_during_refresh(auth):
    service, _ = auth
    _, token = await register_and_login(service)

    async def concurrent_logout(session_id, *args):
        await service.sessions.delete(session_id)
        return None

    service.sessions.refresh = AsyncMock(side_effect=concurrent_logout)
    with pytest.raises(AuthenticationRequiredError):
        await service.verify_session(token)
    assert not service.sessions.records


async def test_logout_keeps_other_sessions(auth):
    service, _ = auth
    _, first = await register_and_login(service)
    _, second = await service.login("User", PASSWORD)
    current = await service.verify_session(first)
    await service.logout(current)
    await service.logout(current)  # Concurrent logout does not fail on a missing row.
    with pytest.raises(AuthenticationRequiredError):
        await service.verify_session(first)
    assert (await service.verify_session(second)).user.id == current.user.id


async def test_cache_hit_skips_database_and_expires_after_sixty_seconds(auth):
    service, clock = auth
    _, token = await register_and_login(service)
    service.sessions.get_active = AsyncMock(wraps=service.sessions.get_active)
    await service.verify_session(token)
    service.transaction.reset_mock()
    clock.now += timedelta(seconds=59)
    current = await service.verify_session(token)
    assert service.sessions.get_active.await_count == 1
    service.transaction.commit.assert_not_awaited()
    assert current.user.login == "User"
    clock.now += timedelta(seconds=1)
    current = await service.verify_session(token)
    assert service.sessions.get_active.await_count == 2
    assert current.session.expires_at == clock.now + timedelta(days=30)
    await service.logout(current)
    with pytest.raises(AuthenticationRequiredError):
        await service.verify_session(token)


async def test_cache_contains_public_data_and_no_raw_token(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    await service.verify_session(token)
    key, (value, _) = next(iter(service.redis.records.items()))
    assert key == f"auth:session:{token_hash(token)}"
    assert token not in key + value
    assert "password" not in value
    assert "$argon2" not in value


@pytest.mark.parametrize("operation", ["get", "set", "delete"])
async def test_redis_failure_falls_back_to_database(auth, operation):
    from redis.exceptions import ConnectionError

    service, _ = auth
    _, token = await register_and_login(service)
    setattr(service.redis, operation, AsyncMock(side_effect=ConnectionError("unavailable")))
    current = await service.verify_session(token)
    assert current.user.login == "User"
    await service.logout(current)
    assert not service.sessions.records


async def test_failed_commit_does_not_fill_cache(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    service.transaction.commit.side_effect = ConnectionError("commit failed")
    with pytest.raises(ConnectionError):
        await service.verify_session(token)
    assert not service.redis.records


async def test_cache_does_not_outlive_short_session(auth):
    service, clock = auth
    service.settings.session_ttl_seconds = 10
    _, token = await register_and_login(service)
    await service.verify_session(token)
    _, cache_expiry = next(iter(service.redis.records.values()))
    assert cache_expiry == clock.now + timedelta(seconds=10)
    clock.now = cache_expiry
    with pytest.raises(AuthenticationRequiredError):
        await service.verify_session(token)


async def test_invalid_cache_is_replaced_from_database(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    await service.redis.set(f"auth:session:{token_hash(token)}", "invalid json", ex=60)
    assert (await service.verify_session(token)).user.login == "User"
