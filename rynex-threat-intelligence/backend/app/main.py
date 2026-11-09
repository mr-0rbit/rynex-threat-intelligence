"""RTIP FastAPI application entrypoint."""

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import analytics, auth, intel
from app.core.config import settings
from app.core.logging import setup_logging

setup_logging()
logger = logging.getLogger("rtip.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dev convenience: create tables when they don't exist. Alembic owns real migrations.
    if settings.ENVIRONMENT == "development":
        from app.core.database import engine
        from app.models import Base

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await bootstrap_admin()
    yield


async def bootstrap_admin() -> None:
    """Create the initial admin account only when no users exist."""
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.core.security import hash_password
    from app.models import User

    async with AsyncSessionLocal() as db:
        has_users = (await db.execute(select(User.id).limit(1))).scalar_one_or_none()
        if has_users is None:
            db.add(
                User(
                    email=settings.ADMIN_EMAIL.lower(),
                    hashed_password=hash_password(settings.ADMIN_PASSWORD),
                    role="admin",
                    full_name="Platform Administrator",
                )
            )
            await db.commit()
            logger.warning(
                "bootstrapped initial admin account; change the default password immediately"
            )


app = FastAPI(
    title=settings.APP_NAME,
    description=f"{settings.APP_NAME} API — {settings.APP_TAGLINE}",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    # Never leak internals to clients
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(intel.router, prefix=settings.API_V1_PREFIX)
app.include_router(analytics.router, prefix=settings.API_V1_PREFIX)


@app.get("/api/health", tags=["health"])
async def health() -> dict:
    return {"status": "ok", "service": "rtip-backend", "environment": settings.ENVIRONMENT}
