"""FastAPI dependencies: DB session, current user (JWT or service API key), RBAC."""

import hashlib
import uuid
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import Permission, Role, decode_token, has_permission
from app.core.timeutil import ensure_aware
from app.models import ApiToken, Organization, User

bearer_scheme = HTTPBearer(auto_error=False)


def _hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def _resolve_api_token(request: Request, db: AsyncSession) -> User | None:
    raw = request.headers.get("X-API-Key")
    if not raw:
        return None
    token = (
        await db.execute(select(ApiToken).where(ApiToken.key_hash == _hash_api_key(raw)))
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    expires_at = ensure_aware(token.expires_at) if token else None
    if (
        token is None
        or token.revoked_at is not None
        or (expires_at and expires_at < now)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired API key")
    owner = await db.get(User, token.owner_user_id)
    if owner is None or not owner.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key owner inactive")
    token.last_used_at = now
    return owner


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    # 1) Service API key (machine access: SOAR/SIEM pulls, integrations)
    user = await _resolve_api_token(request, db)
    if user is None:
        if credentials is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
        payload = decode_token(credentials.credentials, token_types=("access",))
        if not payload:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
        user_id = payload.get("sub")
        try:
            user = await db.get(User, uuid.UUID(user_id)) if user_id else None
        except (ValueError, TypeError):
            user = None
        if user is None or not user.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
        issued_version = payload.get("ver")
        if issued_version is not None and int(issued_version) != int(user.token_version or 0):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revoked — please sign in again")

    organization = await db.get(Organization, user.organization_id)
    if organization is None or not organization.enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Organization is disabled")
    return user


def require_role(*roles: Role):
    async def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in [r.value for r in roles]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return checker


def require_permission(permission: Permission):
    """Enforce fine-grained enterprise permission on an endpoint."""
    async def checker(user: User = Depends(get_current_user)) -> User:
        if not has_permission(user.role, permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Insufficient permissions: requires {permission.value}",
            )
        return user

    return checker


def require_platform_admin():
    async def checker(user: User = Depends(get_current_user)) -> User:
        if not user.is_platform_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Platform administrator permissions required")
        return user

    return checker


admin_required = require_role(Role.ADMIN)
platform_admin_required = require_platform_admin()
analyst_required = require_permission(Permission.INTEL_WRITE)
asset_manager_required = require_permission(Permission.ASSETS_MANAGE)
watchlist_manager_required = require_permission(Permission.WATCHLISTS_MANAGE)
investigation_writer_required = require_permission(Permission.INVESTIGATIONS_WRITE)
alert_triage_required = require_permission(Permission.ALERTS_TRIAGE)
