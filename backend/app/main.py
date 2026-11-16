"""RTIP FastAPI application entrypoint with enterprise extensions."""

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import taxii
from app.api.v1 import (
    admin,
    analytics,
    assets,
    auth,
    darkweb,
    edl,
    intel,
    investigations,
    metrics,
    mitre,
    realtime,
    watchlists,
)
from app.core.config import settings
from app.core.logging import setup_logging
from app.services.events import start_redis_bridge, stop_redis_bridge

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

    # Start enterprise Redis Pub/Sub WebSocket event bridge
    start_redis_bridge()

    yield

    # Stop Redis Pub/Sub listener
    stop_redis_bridge()


async def bootstrap_admin() -> None:
    """Create the initial admin account only when no users exist."""
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.core.security import hash_password
    from app.models import AuditChainHead, Organization, User
    from app.models.organization import DEFAULT_ORGANIZATION_ID

    async with AsyncSessionLocal() as db:
        audit_head = await db.get(AuditChainHead, 1)
        if audit_head is None:
            from app.services.audit import GENESIS_HMAC

            db.add(AuditChainHead(id=1, last_sequence=0, last_hmac=GENESIS_HMAC))
        organization = (
            await db.execute(select(Organization).where(Organization.slug == "default"))
        ).scalar_one_or_none()
        if organization is None:
            organization = Organization(
                id=DEFAULT_ORGANIZATION_ID,
                name=settings.DEFAULT_ORGANIZATION_NAME,
                slug="default",
                enabled=True,
            )
            db.add(organization)
            await db.flush()
        has_users = (await db.execute(select(User.id).limit(1))).scalar_one_or_none()
        if has_users is None:
            db.add(
                User(
                    email=settings.ADMIN_EMAIL.lower(),
                    organization_id=organization.id,
                    hashed_password=hash_password(settings.ADMIN_PASSWORD),
                    role="admin",
                    full_name="Platform Administrator",
                    is_platform_admin=True,
                )
            )
        await db.commit()
        if has_users is None:
            logger.warning(
                "bootstrapped initial admin account; change the default password immediately"
            )


app = FastAPI(
    title=settings.APP_NAME,
    description=f"{settings.APP_NAME} API — {settings.APP_TAGLINE}",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-API-Key",
        "X-CSRF-Client",
        "X-Request-ID",
        "Accept",
        "If-None-Match",
    ],
    expose_headers=["ETag", "X-Total-Count"],
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


# Core Intel & Admin routers
app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(intel.router, prefix=settings.API_V1_PREFIX)
app.include_router(analytics.router, prefix=settings.API_V1_PREFIX)
app.include_router(darkweb.router, prefix=settings.API_V1_PREFIX)
app.include_router(assets.router, prefix=settings.API_V1_PREFIX)
app.include_router(watchlists.router, prefix=settings.API_V1_PREFIX)
app.include_router(investigations.router, prefix=settings.API_V1_PREFIX)
app.include_router(admin.router, prefix=settings.API_V1_PREFIX)
app.include_router(metrics.router, prefix=settings.API_V1_PREFIX)
app.include_router(realtime.router, prefix=settings.API_V1_PREFIX)

# Enterprise CTI & Standards routers
app.include_router(edl.router, prefix=settings.API_V1_PREFIX)
app.include_router(mitre.router, prefix=settings.API_V1_PREFIX)
app.include_router(taxii.router)  # /taxii2/...


# ---------- Enterprise Health Probes ----------

@app.get("/healthz", tags=["health"])
@app.get("/livez", tags=["health"])
async def liveness() -> dict:
    """Kubernetes liveness probe: indicates process is responsive."""
    return {"status": "ok", "service": "rtip-backend", "alive": True}


@app.get("/readyz", tags=["health"])
async def readiness() -> JSONResponse:
    """Kubernetes deep readiness probe: verifies DB and Redis dependencies."""
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal

    checks: dict[str, Any] = {"service": "rtip-backend", "status": "ok", "checks": {}}
    all_healthy = True

    # 1. Database connection check
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        checks["checks"]["database"] = {"status": "healthy"}
    except Exception as exc:  # noqa: BLE001
        checks["checks"]["database"] = {"status": "unhealthy", "error": str(exc)}
        all_healthy = False

    # 2. Redis connection check
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.REDIS_URL, socket_timeout=1.0)
        pong = await r.ping()
        await r.aclose()
        checks["checks"]["redis"] = {"status": "healthy" if pong else "unresponsive"}
    except Exception as exc:  # noqa: BLE001
        checks["checks"]["redis"] = {"status": "degraded_or_unavailable", "note": str(exc)}

    status_code = status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=status_code, content=checks)


@app.get("/api/health", tags=["health"])
@app.get("/health", tags=["health"], include_in_schema=False)
async def health() -> dict:
    return {"status": "ok", "service": "rtip-backend", "environment": settings.ENVIRONMENT}
