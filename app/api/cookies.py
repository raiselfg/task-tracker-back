from fastapi import Response

from app.core.config import Settings


def set_session_cookie(
    response: Response, settings: Settings, token: str, max_age: int | None = None
) -> None:
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        max_age=settings.session_ttl_seconds if max_age is None else max_age,
        secure=not settings.allow_insecure_cookies,
        httponly=True,
        samesite="lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.cookie_name,
        path="/",
        secure=not settings.allow_insecure_cookies,
        httponly=True,
        samesite="lax",
    )
    response.headers["Cache-Control"] = "no-store"
