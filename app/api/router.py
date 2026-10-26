from fastapi import APIRouter, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from app.api.routers.auth import router as auth_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth_router)


async def http_error(request: Request, exc: HTTPException):
    response = await http_exception_handler(request, exc)
    response.headers["Cache-Control"] = "no-store"
    return response


async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # FastAPI's default response includes input values, including invalid passwords.
    return JSONResponse(
        status_code=422,
        headers={"Cache-Control": "no-store"},
        content={
            "detail": [
                {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
                for error in exc.errors()
            ]
        },
    )
