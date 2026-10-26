from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException

from app.api.router import api_router, http_error, validation_error
from app.api.routers.health import router as health_router
from app.core.config import get_settings
from app.lifespan import lifespan

settings = get_settings()

app = FastAPI(
    lifespan=lifespan,
    exception_handlers={
        HTTPException: http_error,
        RequestValidationError: validation_error,
    },
)

app.include_router(api_router)
app.include_router(health_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
    allow_headers=["Content-Type"],
)
