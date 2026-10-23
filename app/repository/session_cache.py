from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from redis.asyncio import Redis

from app.schemas.user import UserRead


class CachedSession(BaseModel):
    write_id: UUID = Field(default_factory=uuid4)
    id: UUID
    user: UserRead
    expires_at: datetime


class SessionCache:
    def __init__(self, redis: Redis):
        self.redis = redis

    @staticmethod
    def key(digest: str) -> str:
        return f"auth:session:{digest}"

    async def get(self, digest: str) -> CachedSession | None:
        value = await self.redis.get(self.key(digest))
        if value == "revoked":
            raise RevokedSessionError
        return CachedSession.model_validate_json(value) if value is not None else None

    async def put(self, digest: str, entry: CachedSession, ttl: int) -> str | None:
        # A concurrent logout's marker must never be overwritten by a cache fill.
        value = entry.model_dump_json()
        stored = await self.redis.set(self.key(digest), value, ex=ttl, nx=True)
        if not stored:
            await self.get(digest)
            return None
        return value

    async def confirm(self, digest: str, expected: str, entry: CachedSession, ttl: int) -> None:
        # Publish the committed expiry only if our provisional record still exists.
        # A lost key, another fill, or a logout marker must never be overwritten.
        await self.redis.eval(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then "
            "return redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3]) end "
            "return nil",
            1,
            self.key(digest),
            expected,
            entry.model_dump_json(),
            ttl,
        )

    async def revoke(self, digest: str, ttl: int) -> None:
        # Keep the marker for the session lifetime to block late concurrent fills.
        await self.redis.set(self.key(digest), "revoked", ex=ttl)


class RevokedSessionError(Exception):
    pass
