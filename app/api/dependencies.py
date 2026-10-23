from typing import Annotated

from fastapi import Depends, HTTPException, Request, Response
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.cookies import set_session_cookie
from app.core.config import Settings, get_settings
from app.db.redis import get_redis
from app.db.session import get_db
from app.repository.session_cache import SessionCache
from app.services.auth import AuthenticationRequiredError, AuthService, Principal

SettingsDep = Annotated[Settings, Depends(get_settings)]


def get_auth_service(
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: SettingsDep,
    redis: Annotated[Redis, Depends(get_redis)],
) -> AuthService:
    return AuthService(session, settings, cache=SessionCache(redis))


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


async def get_current_principal(
    request: Request, response: Response, auth: AuthServiceDep, settings: SettingsDep
) -> Principal:
    response.headers["Cache-Control"] = "no-store"
    token = request.cookies.get(settings.cookie_name)
    try:
        principal = await auth.authenticate(token)
    except AuthenticationRequiredError:
        raise HTTPException(status_code=401, detail="Authentication required") from None
    remaining = max(0, int((principal.session.expires_at - auth.clock()).total_seconds()))
    set_session_cookie(response, settings, token, max_age=remaining)
    return principal


CurrentPrincipalDep = Annotated[Principal, Depends(get_current_principal)]
