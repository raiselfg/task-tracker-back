import hashlib
import re
import secrets
from datetime import UTC, datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from starlette.concurrency import run_in_threadpool


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def valid_token(token: str) -> bool:
    return re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is not None


password_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
dummy_password_hash = password_hasher.hash(new_token())


async def hash_password(password: str) -> str:
    return await run_in_threadpool(password_hasher.hash, password)


async def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        verified = await run_in_threadpool(
            password_hasher.verify, password_hash or dummy_password_hash, password
        )
        return bool(verified and password_hash is not None)
    except VerificationError, InvalidHashError:
        return False


def needs_rehash(password_hash: str) -> bool:
    return password_hasher.check_needs_rehash(password_hash)
