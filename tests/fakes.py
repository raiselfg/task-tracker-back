from datetime import timedelta
from unittest.mock import AsyncMock

from app.core.config import Settings
from app.services.auth import AuthService


class Users:
    def __init__(self):
        self.records = {}
        self.lookups = []

    async def by_login(self, login):
        self.lookups.append(login)
        return next((u for u in self.records.values() if u.login == login), None)

    async def by_id(self, user_id):
        return self.records.get(user_id)

    def add(self, user):
        self.records[user.id] = user


class Sessions:
    def __init__(self):
        self.records = {}

    def add(self, session):
        self.records[session.id] = session

    async def get_active(self, digest, now):
        return next(
            (
                item
                for item in self.records.values()
                if item.token_hash == digest and item.expires_at > now
            ),
            None,
        )

    async def refresh(self, session_id, now, expires_at):
        session = self.records.get(session_id)
        if session is None or session.expires_at <= now:
            return None
        session.expires_at = max(session.expires_at, expires_at)
        return session

    async def delete(self, session_id):
        self.records.pop(session_id, None)


class MemoryRedis:
    def __init__(self, clock):
        self.clock = clock
        self.records = {}

    async def get(self, key):
        record = self.records.get(key)
        if record is None:
            return None
        value, expires_at = record
        if expires_at <= self.clock():
            self.records.pop(key)
            return None
        return value

    async def set(self, key, value, *, ex):
        self.records[key] = (value, self.clock() + timedelta(seconds=ex))
        return True

    async def delete(self, key):
        return int(self.records.pop(key, None) is not None)


def make_service(clock):
    service = AuthService(
        AsyncMock(),
        Settings(_env_file=None, allowed_origins=["https://app.example.com"]),
        redis=MemoryRedis(clock),
        clock=clock,
    )
    service.users = Users()
    service.sessions = Sessions()
    return service
