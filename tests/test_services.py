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
    assert (await service.authenticate(upper_token)).user.id == upper.id
    assert (await service.authenticate(lower_token)).user.id == lower.id
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
        await service.authenticate(token)
    assert record.expires_at == original_expiry


async def test_current_session_revocation(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    current = await service.authenticate(token)
    await service.logout(current)
    with pytest.raises(AuthenticationRequiredError):
        await service.authenticate(token)


@pytest.mark.parametrize("token", [None, "", "invalid", "я" * 43])
async def test_malformed_token_never_reaches_repository(auth, token):
    service, _ = auth
    service.sessions.get_active = AsyncMock()
    with pytest.raises(AuthenticationRequiredError):
        await service.authenticate(token)
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
        current = await service.authenticate(token)
        assert current.session.expires_at == clock.now + timedelta(days=30)


async def test_revoked_session_is_not_restored_during_refresh(auth):
    service, _ = auth
    _, token = await register_and_login(service)

    async def concurrent_logout(session_id, *args):
        await service.sessions.delete(session_id)
        return None

    service.sessions.refresh = AsyncMock(side_effect=concurrent_logout)
    with pytest.raises(AuthenticationRequiredError):
        await service.authenticate(token)
    assert not service.sessions.records


async def test_logout_keeps_other_sessions(auth):
    service, _ = auth
    _, first = await register_and_login(service)
    _, second = await service.login("User", PASSWORD)
    current = await service.authenticate(first)
    await service.logout(current)
    await service.logout(current)  # Concurrent logout does not fail on a missing row.
    with pytest.raises(AuthenticationRequiredError):
        await service.authenticate(first)
    assert (await service.authenticate(second)).user.id == current.user.id


async def test_cache_hit_does_not_access_postgres(auth):
    service, clock = auth
    _, token = await register_and_login(service)
    await service.authenticate(token)
    service.transaction.reset_mock()
    service.sessions.get_active = AsyncMock(side_effect=AssertionError("Unexpected SQL"))
    service.users.by_id = AsyncMock(side_effect=AssertionError("Unexpected SQL"))
    clock.now += timedelta(seconds=150)
    current = await service.authenticate(token)
    assert current.user.login == "User"
    service.transaction.commit.assert_not_awaited()
    service.sessions.get_active.assert_not_awaited()
    service.users.by_id.assert_not_awaited()


async def test_cache_expires_even_with_activity(auth):
    service, clock = auth
    _, token = await register_and_login(service)
    current = await service.authenticate(token)
    expiry = current.session.expires_at
    clock.now += timedelta(seconds=150)
    assert (await service.authenticate(token)).session.expires_at == expiry
    clock.now += timedelta(seconds=150)
    assert (await service.authenticate(token)).session.expires_at == clock.now + timedelta(days=30)


async def test_cache_contains_no_password_or_raw_token(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    await service.authenticate(token)
    key, (value, _) = next(iter(service.cache.redis.records.items()))
    assert token_hash(token) in key
    assert token not in key + value
    assert "password" not in value
    assert "$argon2" not in value


async def test_logout_marker_blocks_late_cache_fill(auth):
    from app.repository.session_cache import CachedSession, RevokedSessionError
    from app.schemas.user import UserRead

    service, clock = auth
    _, token = await register_and_login(service)
    current = await service.authenticate(token)
    entry = CachedSession(
        id=current.session.id,
        user=UserRead.model_validate(current.user),
        expires_at=current.session.expires_at,
    )
    await service.logout(current)
    # Even a very delayed cache fill cannot overwrite logout's marker.
    clock.now += timedelta(seconds=301)
    with pytest.raises(RevokedSessionError):
        await service.cache.put(token_hash(token), entry, 300)
    with pytest.raises(AuthenticationRequiredError):
        await service.authenticate(token)


async def test_redis_cache_loss_keeps_postgres_session(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    await service.authenticate(token)
    service.cache.redis.records.clear()
    assert (await service.authenticate(token)).user.login == "User"


async def test_cache_fill_happens_before_database_commit(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    service.transaction.commit.reset_mock()
    original_put = service.cache.put

    async def cache_while_locked(*args):
        service.transaction.commit.assert_not_awaited()
        return await original_put(*args)

    service.cache.put = AsyncMock(side_effect=cache_while_locked)
    await service.authenticate(token)
    service.cache.put.assert_awaited_once()
    service.transaction.commit.assert_awaited_once()


async def test_logout_deletes_row_before_revoking_cache_and_committing(auth):
    service, _ = auth
    _, token = await register_and_login(service)
    current = await service.authenticate(token)
    service.transaction.commit.reset_mock()
    original_revoke = service.cache.revoke

    async def revoke_after_delete(*args):
        assert current.session.id not in service.sessions.records
        service.transaction.commit.assert_not_awaited()
        await original_revoke(*args)

    service.cache.revoke = AsyncMock(side_effect=revoke_after_delete)
    await service.logout(current)
    service.cache.revoke.assert_awaited_once()
    service.transaction.commit.assert_awaited_once()


async def test_failed_commit_never_caches_uncommitted_expiry(auth):
    service, clock = auth
    _, token = await register_and_login(service)
    row = next(iter(service.sessions.records.values()))
    committed_expiry = clock.now + timedelta(seconds=2)
    row.expires_at = committed_expiry

    async def failed_commit():
        # Represent a database failure that rolls back the UPDATE.
        row.expires_at = committed_expiry
        raise ConnectionError("commit failed")

    service.transaction.commit.side_effect = failed_commit
    with pytest.raises(ConnectionError):
        await service.authenticate(token)
    cached = await service.cache.get(token_hash(token))
    assert cached.expires_at == committed_expiry
    clock.now = committed_expiry
    with pytest.raises(AuthenticationRequiredError):
        await service.authenticate(token)


async def test_confirmation_publishes_committed_expiry(auth):
    service, clock = auth
    _, token = await register_and_login(service)
    row = next(iter(service.sessions.records.values()))
    row.expires_at = clock.now + timedelta(days=1)
    committed_expiry = row.expires_at

    async def check_before_commit():
        cached = await service.cache.get(token_hash(token))
        assert cached.expires_at == committed_expiry

    service.transaction.commit.side_effect = check_before_commit
    current = await service.authenticate(token)
    cached = await service.cache.get(token_hash(token))
    assert current.session.expires_at == cached.expires_at == clock.now + timedelta(days=30)


@pytest.mark.parametrize("interruption", ["logout", "redis_loss", "replacement"])
async def test_confirmation_does_not_overwrite_lost_or_replaced_key(auth, interruption):
    from app.repository.session_cache import CachedSession, RevokedSessionError
    from app.schemas.user import UserRead

    service, clock = auth
    _, token = await register_and_login(service)
    digest = token_hash(token)
    replacement = None

    async def interrupt_after_commit():
        nonlocal replacement
        if interruption == "logout":
            await service.cache.revoke(digest, service.settings.session_ttl_seconds)
        else:
            service.cache.redis.records.clear()
            if interruption == "replacement":
                row = next(iter(service.sessions.records.values()))
                user = service.users.records[row.user_id]
                replacement = CachedSession(
                    id=row.id, user=UserRead.model_validate(user), expires_at=row.expires_at
                )
                await service.cache.put(digest, replacement, 300)

    service.transaction.commit.side_effect = interrupt_after_commit
    await service.authenticate(token)
    if interruption == "logout":
        with pytest.raises(RevokedSessionError):
            await service.cache.get(digest)
    elif interruption == "redis_loss":
        assert await service.cache.get(digest) is None
    else:
        assert (await service.cache.get(digest)).write_id == replacement.write_id
