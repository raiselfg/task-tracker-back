from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", hide_input_in_errors=True)

    app_env: Literal["development", "production"] = "development"
    database_url: SecretStr = SecretStr("postgresql://auth:auth@localhost:5432/auth")
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")
    allowed_origins: list[str] = Field(default_factory=list)
    allow_insecure_cookies: bool = False
    session_cache_ttl_seconds: int = Field(default=300, gt=0)
    session_ttl_seconds: int = Field(default=30 * 24 * 3600, gt=0)

    @model_validator(mode="after")
    def validate_security(self):
        database_url = self.database_url.get_secret_value()
        if database_url.startswith("postgresql://"):
            database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if not database_url.startswith("postgresql+asyncpg://"):
            raise ValueError("DATABASE_URL must use postgresql:// or postgresql+asyncpg://")
        self.database_url = SecretStr(database_url)
        if urlsplit(self.redis_url.get_secret_value()).scheme not in {"redis", "rediss"}:
            raise ValueError("REDIS_URL must use redis:// or rediss://")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or "*" in origin
            ):
                raise ValueError("ALLOWED_ORIGINS must contain exact HTTP(S) origins")
            # Accessing port also validates its syntax.
            _ = parsed.port
            if self.app_env == "production" and parsed.scheme != "https":
                raise ValueError("Production origins must use HTTPS")
        if self.app_env == "production":
            if self.allow_insecure_cookies:
                raise ValueError("Insecure cookies are forbidden in production")
            if not self.allowed_origins:
                raise ValueError("Production requires explicit ALLOWED_ORIGINS")
        return self

    @property
    def cookie_name(self) -> str:
        return "session" if self.allow_insecure_cookies else "__Host-session"


@lru_cache
def get_settings() -> Settings:
    return Settings()
