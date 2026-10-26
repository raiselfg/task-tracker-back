from http.cookies import SimpleCookie

import pytest
from fastapi import Response
from pydantic import ValidationError

from app.api.cookies import clear_session_cookie, set_session_cookie
from app.core.config import Settings
from app.core.security import (
    hash_password,
    needs_rehash,
    new_token,
    password_hasher,
    token_hash,
    valid_token,
    verify_password,
)
from app.schemas.auth import Credentials


@pytest.mark.parametrize("login", ["User", "user", "ABC", "123", "a-b_c.d", "A" * 32])
def test_login_preserves_case(login):
    assert Credentials(login=login, password="long secure password").login == login


@pytest.mark.parametrize(
    "login",
    [
        "ab",
        "A" * 33,
        " User",
        "User ",
        "a b",
        "_abc",
        "-abc",
        ".abc",
        "юзер",
        "abc\n",
    ],
)
def test_invalid_login(login):
    with pytest.raises(ValidationError):
        Credentials(login=login, password="long secure password")


@pytest.mark.parametrize("password", ["x" * 5, "x" * 129])
def test_password_length(password):
    with pytest.raises(ValidationError):
        Credentials(login="User", password=password)


def test_password_preserves_spaces_and_is_redacted():
    data = Credentials(login="User", password="  long password  ")
    assert data.password.get_secret_value() == "  long password  "
    assert "long password" not in repr(data)


async def test_password_hashing_and_dummy_verification():
    secret = "long secure password"
    first = await hash_password(secret)
    second = await hash_password(secret)
    assert first != second
    assert first.startswith("$argon2id$")
    assert await verify_password(first, secret)
    assert not await verify_password(first, secret + "wrong")
    assert not await verify_password(None, secret)
    assert not await verify_password("broken hash", secret)
    assert not needs_rehash(first)
    assert password_hasher.memory_cost >= 19456
    assert password_hasher.time_cost >= 2


def test_tokens():
    token = new_token()
    assert token != new_token()
    assert valid_token(token)
    assert len(token_hash(token)) == 64
    assert token_hash(token) == token_hash(token)
    assert token not in token_hash(token)
    for invalid in ["", "abc", "x" * 44, "я" * 43, " " * 43]:
        assert not valid_token(invalid)


def test_production_cookie_and_deletion():
    settings = Settings(
        _env_file=None, app_env="production", allowed_origins=["https://app.example.com"]
    )
    response = Response()
    set_session_cookie(response, settings, new_token())
    cookie = SimpleCookie()
    cookie.load(response.headers["set-cookie"])
    item = cookie["__Host-session"]
    assert item["secure"] and item["httponly"]
    assert item["samesite"] == "lax"
    assert item["path"] == "/"
    assert not item["domain"]
    assert int(item["max-age"]) == 2592000
    response = Response()
    clear_session_cookie(response, settings)
    cookie.load(response.headers["set-cookie"])
    assert cookie["__Host-session"]["max-age"] == "0"


def test_insecure_cookie_requires_explicit_setting():
    settings = Settings(_env_file=None)
    assert settings.cookie_name == "__Host-session"
    assert Settings(_env_file=None, allow_insecure_cookies=True).cookie_name == "session"


@pytest.mark.parametrize(
    "values",
    [
        {"app_env": "production"},
        {
            "app_env": "production",
            "allowed_origins": ["https://app.example.com"],
            "allow_insecure_cookies": True,
        },
        {"app_env": "production", "allowed_origins": ["http://app.example.com"]},
        {"allowed_origins": ["*"]},
        {"allowed_origins": ["https://app.example.com/"]},
        {"allowed_origins": ["https://app.example.com/path"]},
        {"allowed_origins": ["https://user:pass@app.example.com"]},
        {"allowed_origins": ["https://*.example.com"]},
        {"session_ttl_seconds": 0},
        {"redis_url": "http://localhost:6379"},
        {"database_url": "sqlite:///test.db"},
        {"database_url": "postgresql+psycopg://auth:auth@localhost:5432/auth"},
    ],
)
def test_invalid_settings(values):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


@pytest.mark.parametrize("scheme", ["postgresql", "postgresql+asyncpg"])
def test_database_url_selects_asyncpg_and_preserves_credentials(scheme):
    url = f"{scheme}://demo:example%40password@192.0.2.10:5434/postgres"
    settings = Settings(_env_file=None, database_url=url)
    assert settings.database_url.get_secret_value() == (
        "postgresql+asyncpg://demo:example%40password@192.0.2.10:5434/postgres"
    )
    assert "example%40password" not in repr(settings)


def test_database_url_from_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://demo:example@db:5432/postgres")
    settings = Settings(_env_file=None)
    assert settings.database_url.get_secret_value() == (
        "postgresql+asyncpg://demo:example@db:5432/postgres"
    )


@pytest.mark.parametrize("length", [6, 128])
def test_password_accepts_boundary_lengths(length):
    password = "x" * length
    assert Credentials(login="User", password=password).password.get_secret_value() == password
