from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi.middleware.cors import CORSMiddleware

from app.api.dependencies import get_auth_service
from app.core.config import Settings, get_settings
from app.main import app
from tests.fakes import make_service

ORIGIN = "https://app.example.com"
HEADERS = {"Origin": ORIGIN}
BODY = {"login": "User", "password": "secret"}


@pytest.fixture
def clock():
    return SimpleNamespace(now=datetime(2026, 10, 17, tzinfo=UTC))


@pytest.fixture
def auth_service(clock):
    return make_service(lambda: clock.now)


@pytest.fixture
def settings():
    return Settings(_env_file=None, allowed_origins=[ORIGIN])


@pytest.fixture
def application(settings, monkeypatch):
    # Reset request overrides and rebuild middleware for this test's origins.
    cors = next(item for item in app.user_middleware if item.cls is CORSMiddleware)
    monkeypatch.setitem(cors.kwargs, "allow_origins", settings.allowed_origins)
    monkeypatch.setattr(app, "middleware_stack", None)
    monkeypatch.setattr(app, "dependency_overrides", {get_settings: lambda: settings})
    return app


@pytest.fixture
async def client(auth_service, application):
    app = application
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    # No lifespan, engine, SQL session, or database connection is used.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://api.example.com"
    ) as client:
        yield client


async def test_full_http_flow_with_fake_repositories(client):
    response = await client.post("/api/v1/auth/register", json=BODY, headers=HEADERS)
    assert response.status_code == 201
    assert set(response.json()) == {"id", "login", "created_at"}
    assert not client.cookies
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    response = await client.post("/api/v1/auth/login", json=BODY, headers=HEADERS)
    assert response.status_code == 200
    assert "HttpOnly" in response.headers["set-cookie"]
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"
    assert (await client.get("/api/v1/auth/me")).json()["login"] == "User"
    response = await client.post("/api/v1/auth/logout", headers=HEADERS)
    assert response.status_code == 204
    assert response.content == b""
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_registration_does_not_require_origin_or_csrf_header(client):
    response = await client.post("/api/v1/auth/register", json=BODY)
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"


async def test_invalid_body_uses_fastapi_validation(client):
    response = await client.post("/api/v1/auth/register", data=BODY, headers=HEADERS)
    assert response.status_code == 422


async def test_validation_does_not_echo_password(client):
    response = await client.post(
        "/api/v1/auth/register",
        json={"login": "User", "password": "s3cr!"},
        headers=HEADERS,
    )
    assert response.status_code == 422
    assert "s3cr!" not in response.text
    assert response.headers["cache-control"] == "no-store"


async def test_cors_preflight(client):
    response = await client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ORIGIN
    response = await client.options(
        "/api/v1/auth/login",
        headers={"Origin": "https://evil.example.com", "Access-Control-Request-Method": "POST"},
    )
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


async def test_logout_clears_cookie(client, clock):
    await client.post("/api/v1/auth/register", json=BODY, headers=HEADERS)
    await client.post("/api/v1/auth/login", json=BODY, headers=HEADERS)
    token = client.cookies.get("__Host-session")
    clock.now += timedelta(days=1)
    response = await client.post("/api/v1/auth/logout", headers=HEADERS)
    assert response.status_code == 204
    assert response.content == b""
    assert "Max-Age=0" in response.headers.get_list("set-cookie")[-1]
    assert client.cookies.get("__Host-session") is None
    response = await client.get("/api/v1/auth/me", headers={"Cookie": f"__Host-session={token}"})
    assert response.status_code == 401


async def test_health_without_database(client):
    assert (await client.get("/health")).json() == {"status": "ok"}


async def test_expired_session_does_not_refresh_cookie(client, clock):
    await client.post("/api/v1/auth/register", json=BODY, headers=HEADERS)
    await client.post("/api/v1/auth/login", json=BODY, headers=HEADERS)
    clock.now += timedelta(days=30)
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert "set-cookie" not in response.headers


async def test_service_errors_keep_http_contract(client):
    await client.post("/api/v1/auth/register", json=BODY, headers=HEADERS)
    duplicate = await client.post("/api/v1/auth/register", json=BODY, headers=HEADERS)
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "Login already taken"}

    failures = []
    for login in ["User", "Missing"]:
        result = await client.post(
            "/api/v1/auth/login",
            json={"login": login, "password": "an incorrect password"},
            headers=HEADERS,
        )
        assert result.status_code == 401
        failures.append(result.json())
    assert failures == [{"detail": "Invalid login or password"}] * 2

    for response in [duplicate, result]:
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["access-control-allow-origin"] == ORIGIN


async def test_json_with_charset_accepted(client):
    result = await client.post(
        "/api/v1/auth/register",
        json=BODY,
        headers={**HEADERS, "Content-Type": "application/json; charset=utf-8"},
    )
    assert result.status_code == 201


async def test_activity_renews_cookie_and_database_session(client, clock, auth_service):
    await client.post("/api/v1/auth/register", json=BODY)
    response = await client.post("/api/v1/auth/login", json=BODY)
    assert "Max-Age=2592000" in response.headers["set-cookie"]
    token = client.cookies.get("__Host-session")
    for _ in range(3):
        clock.now += timedelta(days=29)
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 200
        assert "Max-Age=2592000" in response.headers["set-cookie"]
        assert client.cookies.get("__Host-session") == token
        record = next(iter(auth_service.sessions.records.values()))
        assert record.expires_at == clock.now + timedelta(days=30)
    clock.now += timedelta(days=30)
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert "set-cookie" not in response.headers


async def test_logout_requires_authentication(client):
    response = await client.post("/api/v1/auth/logout")
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"


def test_api_has_only_basic_auth_routes(application):
    paths = {path for path in application.openapi()["paths"] if path.startswith("/api/v1/auth")}
    assert paths == {
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/me",
        "/api/v1/auth/logout",
    }


async def test_settings_override_controls_cookies_and_auth(client, application, auth_service):
    settings = Settings(_env_file=None, allow_insecure_cookies=True, session_ttl_seconds=60)
    application.dependency_overrides[get_settings] = lambda: settings
    auth_service.settings = settings
    await client.post("/api/v1/auth/register", json=BODY)
    response = await client.post("/api/v1/auth/login", json=BODY)
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("session=")
    assert "Max-Age=60" in cookie
    assert "Secure" not in cookie
    assert (await client.get("/api/v1/auth/me")).status_code == 200
    response = await client.post("/api/v1/auth/logout")
    assert response.status_code == 204
    assert response.headers["set-cookie"].startswith("session=")
    assert "Max-Age=0" in response.headers["set-cookie"]


async def test_cached_cookie_does_not_outlive_database_session(client, clock):
    await client.post("/api/v1/auth/register", json=BODY)
    await client.post("/api/v1/auth/login", json=BODY)
    await client.get("/api/v1/auth/me")
    clock.now += timedelta(seconds=150)
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 200
    assert "Max-Age=2591850" in response.headers["set-cookie"]
    clock.now += timedelta(seconds=150)
    response = await client.get("/api/v1/auth/me")
    assert "Max-Age=2592000" in response.headers["set-cookie"]


async def test_unavailable_cache_returns_503(client, auth_service):
    from unittest.mock import AsyncMock

    from redis.exceptions import ConnectionError

    await client.post("/api/v1/auth/register", json=BODY)
    await client.post("/api/v1/auth/login", json=BODY)
    auth_service.cache.redis.get = AsyncMock(side_effect=ConnectionError("unavailable"))
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 503
    assert response.json() == {"detail": "Session cache unavailable"}
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers
