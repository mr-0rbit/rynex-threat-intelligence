"""Admin endpoints: service API keys, audit log, user listing.

API keys authenticate with `X-API-Key: rtip_<random>`; only the SHA-256 hash is
stored. Keys inherit the role of their owning user and can be revoked at any
time. Machine clients (SOAR/SIEM) use these instead of interactive JWTs.
"""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import admin_required, get_current_user
from app.core.database import get_db
from app.models import ApiToken, AuditLog, User
from app.services.audit import record_audit

router = APIRouter(prefix="/admin", tags=["admin"])

API_KEY_PREFIX = "rtip_"


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    expires_in_days: int | None = Field(None, ge=1, le=3650)


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
    tokens = (await db.execute(select(ApiToken).order_by(ApiToken.created_at.desc()))).scalars().all()
    return [_token_out(t) for t in tokens]


@router.delete("/api-keys/{token_id}")
async def revoke_api_key(
    token_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(admin_required),
) -> dict:
    token = await db.get(ApiToken, token_id)
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
    user: User = Depends(admin_required),
) -> dict:
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())
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


# ---------- Users (admin overview) ----------

@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(admin_required),
) -> list[dict]:
    users = (await db.execute(select(User).order_by(User.email))).scalars().all()
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
