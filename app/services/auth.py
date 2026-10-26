from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from math import floor
from uuid import uuid4

from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import (
    hash_password,
    needs_rehash,
    new_token,
    token_hash,
    utc_now,
    valid_token,
    verify_password,
)
from app.models.session import Session
from app.models.user import User
from app.repository.session import SessionRepository
from app.repository.user import UserRepository
from app.schemas.session import CachedSession
from app.schemas.user import UserRead


class LoginAlreadyExistsError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class AuthenticationRequiredError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    user: User | UserRead
    session: Session

redis_auth_prefix = "auth:session"

class AuthService:
    def __init__(
        self,
        transaction: AsyncSession,
        settings: Settings,
        redis: Redis,
        clock: Callable[[], datetime] = utc_now
    ):
        self.users = UserRepository(transaction)
        self.sessions = SessionRepository(transaction)
        self.transaction = transaction
        self.settings = settings
        self.redis = redis
        self.clock = clock

    async def register(self, login: str, password: str) -> User:
        if await self.users.by_login(login) is not None:
            raise LoginAlreadyExistsError("Login already taken")

        user = User(
            id=uuid4(),
            login=login,
            password_hash=await hash_password(password),
            created_at=self.clock(),
        )

        try:
            self.users.add(user)
            await self.transaction.commit()
        except IntegrityError as exc:
            await self.transaction.rollback()
            # SQLAlchemy wraps the asyncpg error and keeps it as the cause.
            cause = getattr(exc.orig, "__cause__", None)
            if getattr(cause, "constraint_name", None) == "uq_users_login":
                raise LoginAlreadyExistsError("Login already taken") from None
            raise

        return user

    async def login(self, login: str, password: str) -> tuple[User, str]:
        user = await self.users.by_login(login)
        verified = await verify_password(user.password_hash if user else None, password)

        if user is None or not verified:
            raise InvalidCredentialsError("Invalid login or password")
        if needs_rehash(user.password_hash):
            user.password_hash = await hash_password(password)

        now = self.clock()
        token = new_token()
        session = Session(
            id=uuid4(),
            user_id=user.id,
            token_hash=token_hash(token),
            expires_at=now + timedelta(seconds=self.settings.session_ttl_seconds),
        )

        self.sessions.add(session)
        await self.transaction.commit()

        return user, token

    async def verify_session(self, token: str | None) -> Principal:
        if token is None or not valid_token(token):
            raise AuthenticationRequiredError("Authentication required")

        now = self.clock()
        digest = token_hash(token)
        key = f"{redis_auth_prefix}:{digest}"

        try:
            value = await self.redis.get(key)
            cached = CachedSession.model_validate_json(value) if value is not None else None
        except (RedisError, ValidationError):
            cached = None

        if cached is not None and cached.expires_at > now:
            return Principal(
                cached.user,
                Session(
                    id=cached.id,
                    user_id=cached.user.id,
                    token_hash=digest,
                    expires_at=cached.expires_at,
                ),
            )
            
        session = await self.sessions.get_active(digest, now)

        if session is None:
            raise AuthenticationRequiredError("Authentication required")

        user = await self.users.by_id(session.user_id)

        if user is None:
            raise AuthenticationRequiredError("Authentication required")

        session = await self.sessions.refresh(
            session.id, now, now + timedelta(seconds=self.settings.session_ttl_seconds)
        )

        if session is None:
            raise AuthenticationRequiredError("Authentication required")

        await self.transaction.commit()

        entry = CachedSession(
            id=session.id,
            user=UserRead.model_validate(user),
            expires_at=session.expires_at,
        )
        ttl = min(60, floor((session.expires_at - self.clock()).total_seconds()))

        if ttl > 15:
            try:
                await self.redis.set(key, entry.model_dump_json(), ex=ttl)
            except RedisError:
                pass

        return Principal(user, session)

    async def logout(self, principal: Principal) -> None:
        await self.sessions.delete(principal.session.id)
        await self.transaction.commit()

        try:
            await self.redis.delete(f"{redis_auth_prefix}:{principal.session.token_hash}")
        except RedisError:
            pass
