"""Asset inventory CRUD — the org's own attack surface that intel is matched against."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import analyst_required, get_current_user
from app.core.database import get_db
from app.models import Asset, User
from app.models.asset import ASSET_TYPES
from app.services.audit import record_audit

router = APIRouter(tags=["assets"])

CRITICALITIES = {"low", "medium", "high", "critical"}


class AssetIn(BaseModel):
    type: str = Field(..., description="domain|ipv4|ipv6|cidr|product|vendor|keyword")
    value: str = Field(..., min_length=1, max_length=512)
    display_name: str | None = Field(None, max_length=255)
    criticality: str = Field("medium")
    owner_team: str | None = Field(None, max_length=128)
    notes: str | None = None
    tags: list[str] | None = None
    enabled: bool = True


class AssetPatch(BaseModel):
    display_name: str | None = None
    criticality: str | None = None
    owner_team: str | None = None
    notes: str | None = None
    tags: list[str] | None = None
    enabled: bool | None = None


def _asset_out(a: Asset) -> dict:
    return {
        "id": str(a.id),
        "type": a.type,
        "value": a.value,
        "display_name": a.display_name,
        "criticality": a.criticality,
        "owner_team": a.owner_team,
        "notes": a.notes,
        "tags": a.tags,
        "enabled": a.enabled,
        "match_count": a.match_count,
        "last_matched_at": a.last_matched_at.isoformat() if a.last_matched_at else None,
        "created_by_email": a.created_by_email,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


@router.get("/assets")
async def list_assets(
    type_filter: str | None = Query(None, alias="type"),
    criticality: str | None = None,
    q: str | None = Query(None, max_length=200, description="substring match on value/name"),
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    stmt = select(Asset).order_by(Asset.match_count.desc(), Asset.value.asc())
    if type_filter:
        stmt = stmt.where(Asset.type == type_filter)
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if q:
        stmt = stmt.where(Asset.value.ilike(f"%{q}%") | Asset.display_name.ilike(f"%{q}%"))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    assets = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [_asset_out(a) for a in assets]}


@router.post("/assets", status_code=201)
async def create_asset(
    body: AssetIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    if body.type not in ASSET_TYPES:
        raise HTTPException(422, f"Invalid asset type; one of {', '.join(ASSET_TYPES)}")
    if body.criticality not in CRITICALITIES:
        raise HTTPException(422, "criticality must be one of low|medium|high|critical")
    value = body.value.strip()
    dup = (
        await db.execute(select(Asset).where(Asset.type == body.type, Asset.value == value))
    ).scalar_one_or_none()
    if dup:
        raise HTTPException(409, "Asset of this type and value already exists")
    asset = Asset(
        type=body.type,
        value=value,
        display_name=body.display_name or value,
        criticality=body.criticality,
        owner_team=body.owner_team,
        notes=body.notes,
        tags=body.tags,
        enabled=body.enabled,
        created_by_email=user.email,
    )
    db.add(asset)
    await record_audit(
        db, action="asset.create", actor_email=user.email, resource_type="asset",
        detail={"type": asset.type, "value": asset.value},
    )
    await db.commit()  # visible to the next list request (frontend reloads after create)
    await db.refresh(asset)
    return _asset_out(asset)


@router.patch("/assets/{asset_id}")
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetPatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    if body.criticality is not None and body.criticality not in CRITICALITIES:
        raise HTTPException(422, "criticality must be one of low|medium|high|critical")
    for field in ("display_name", "criticality", "owner_team", "notes", "tags", "enabled"):
        if getattr(body, field) is not None:
            setattr(asset, field, getattr(body, field))
    await record_audit(
        db, action="asset.update", actor_email=user.email, resource_type="asset",
        resource_id=str(asset.id),
    )
    await db.commit()
    await db.refresh(asset)
    return _asset_out(asset)


@router.delete("/assets/{asset_id}")
async def delete_asset(
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    await db.delete(asset)
    await record_audit(
        db, action="asset.delete", actor_email=user.email, resource_type="asset",
        resource_id=str(asset_id), detail={"value": asset.value},
    )
    await db.commit()
    return {"status": "deleted", "id": str(asset_id)}
