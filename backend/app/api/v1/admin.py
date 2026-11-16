"""Admin endpoints: service API keys, audit log, user listing.

API keys authenticate with `X-API-Key` or `Authorization: Bearer`; only the
SHA-256 hash is stored. Keys inherit the role of their owning user and can be revoked at any
time. Machine clients (SOAR/SIEM) use these instead of interactive JWTs.
"""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import admin_required, platform_admin_required, require_permission
from app.core.database import get_db
from app.core.security import Permission
from app.models import ApiToken, AuditLog, Organization, User
from app.services.audit import record_audit

router = APIRouter(prefix="/admin", tags=["admin"])

API_KEY_PREFIX = "rtip_"


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    expires_in_days: int | None = Field(None, ge=1, le=3650)


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _token_out(t: ApiToken, raw_key: str | None = None) -> dict:
    out = {
        "id": str(t.id),
        "name": t.name,
        "key_prefix": t.key_prefix,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
        "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
    }
    if raw_key is not None:
        out["api_key"] = raw_key  # shown exactly once
    return out


# ---------- API keys ----------

@router.post("/api-keys", status_code=201)
async def create_api_key(
    body: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(admin_required),
) -> dict:
    raw = API_KEY_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken(
        name=body.name.strip(),
        key_hash=__import__("hashlib").sha256(raw.encode()).hexdigest(),
        key_prefix=raw[:12],
        owner_user_id=user.id,
        expires_at=(
            datetime.now(UTC) + timedelta(days=body.expires_in_days) if body.expires_in_days else None
        ),
    )
    db.add(token)
    await record_audit(
        db, action="apikey.create", actor_email=user.email, resource_type="api_token",
        detail={"name": token.name, "prefix": token.key_prefix},
    )
    await db.commit()  # key must be usable immediately after the 201
    await db.refresh(token)
    return _token_out(token, raw_key=raw)


@router.get("/api-keys")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(admin_required),
) -> list[dict]:
    tokens = (
        await db.execute(
            select(ApiToken)
            .join(User, ApiToken.owner_user_id == User.id)
            .where(User.organization_id == user.organization_id)
            .order_by(ApiToken.created_at.desc())
        )
    ).scalars().all()
    return [_token_out(t) for t in tokens]


@router.delete("/api-keys/{token_id}")
async def revoke_api_key(
    token_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(admin_required),
) -> dict:
    token = (
        await db.execute(
            select(ApiToken)
            .join(User, ApiToken.owner_user_id == User.id)
            .where(
                ApiToken.id == token_id,
                User.organization_id == user.organization_id,
            )
        )
    ).scalar_one_or_none()
    if token is None:
        raise HTTPException(404, "API key not found")
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
        await record_audit(
            db, action="apikey.revoke", actor_email=user.email, resource_type="api_token",
            resource_id=str(token.id), detail={"name": token.name},
        )
        await db.commit()  # revocation must be visible to the very next request
    return _token_out(token)


# ---------- Audit log ----------

@router.get("/audit-logs")
async def list_audit_logs(
    action: str | None = None,
    actor: str | None = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.AUDIT_READ)),
) -> dict:
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if not user.is_platform_admin:
        stmt = stmt.where(AuditLog.organization_id == user.organization_id)
    if action:
        stmt = stmt.where(AuditLog.action.ilike(f"{action}%"))
    if actor:
        stmt = stmt.where(AuditLog.actor_email.ilike(f"%{actor}%"))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    rows = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": str(r.id),
                "actor_email": r.actor_email,
                "organization_id": str(r.organization_id) if r.organization_id else None,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "detail": r.detail,
                "ip_address": r.ip_address,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.get("/audit-logs/verify")
async def verify_audit_trail(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(platform_admin_required),
) -> dict:
    """Verify cryptographic HMAC integrity chain of all stored audit logs."""
    from app.services.audit import verify_audit_log_chain

    return await verify_audit_log_chain(db)


@router.get("/audit-logs/export")
async def export_audit_logs(
    export_format: str = Query("cef", alias="format", description="cef, syslog, or json"),
    limit: int = Query(500, le=5000),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_permission(Permission.AUDIT_READ)),
):
    """Export audit trail for enterprise SIEM ingestion (ArcSight CEF / RFC 5424 Syslog)."""
    from fastapi.responses import PlainTextResponse
    from app.services.audit import format_cef_audit, format_rfc5424_audit

    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
    if not user.is_platform_admin:
        stmt = stmt.where(AuditLog.organization_id == user.organization_id)
    stmt = stmt.limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    if export_format == "cef":
        lines = [format_cef_audit(r) for r in rows]
        return PlainTextResponse("\n".join(lines), media_type="text/plain")
    elif export_format == "syslog":
        lines = [format_rfc5424_audit(r) for r in rows]
        return PlainTextResponse("\n".join(lines), media_type="text/plain")
    else:
        return [
            {
                "id": str(r.id),
                "actor": r.actor_email,
                "organization_id": str(r.organization_id) if r.organization_id else None,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "detail": r.detail,
                "ip": r.ip_address,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]



# ---------- Users (admin overview) ----------

@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(admin_required),
) -> list[dict]:
    users = (
        await db.execute(
            select(User)
            .where(User.organization_id == user.organization_id)
            .order_by(User.email)
        )
    ).scalars().all()
    return [
        {
            "id": str(u.id),
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "is_active": u.is_active,
            "mfa_enabled": u.mfa_enabled,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        }
        for u in users
    ]


@router.post("/organizations", status_code=201)
async def create_organization(
    body: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(platform_admin_required),
) -> dict:
    existing = (
        await db.execute(select(Organization).where(Organization.slug == body.slug))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Organization slug already exists")
    organization = Organization(name=body.name.strip(), slug=body.slug)
    db.add(organization)
    await db.flush()
    await record_audit(
        db,
        action="organization.create",
        actor_email=user.email,
        organization_id=organization.id,
        resource_type="organization",
        detail={"name": organization.name, "slug": organization.slug},
    )
    await db.commit()
    await db.refresh(organization)
    return {
        "id": str(organization.id),
        "name": organization.name,
        "slug": organization.slug,
        "enabled": organization.enabled,
    }


@router.get("/organizations")
async def list_organizations(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(platform_admin_required),
) -> list[dict]:
    organizations = (
        await db.execute(select(Organization).order_by(Organization.name))
    ).scalars().all()
    return [
        {
            "id": str(org.id),
            "name": org.name,
            "slug": org.slug,
            "enabled": org.enabled,
        }
        for org in organizations
    ]
