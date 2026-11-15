"""Watchlist CRUD — analyst-defined entities that trigger `watchlist_mention` alerts."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import analyst_required, get_current_user
from app.core.database import get_db
from app.models import User, Watchlist, WatchlistItem
from app.services.audit import record_audit

router = APIRouter(tags=["watchlists"])

ITEM_TYPES = {"organization", "domain", "actor", "cve", "keyword"}


class WatchlistIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    enabled: bool = True


class WatchlistItemIn(BaseModel):
    item_type: str = Field(..., description="organization|domain|actor|cve|keyword")
    value: str = Field(..., min_length=1, max_length=512)
    notes: str | None = None


def _wl_out(w: Watchlist, item_count: int | None = None) -> dict:
    return {
        "id": str(w.id),
        "name": w.name,
        "description": w.description,
        "enabled": w.enabled,
        "owner_email": w.owner_email,
        "item_count": item_count,
    }


def _item_out(i: WatchlistItem) -> dict:
    return {
        "id": str(i.id),
        "watchlist_id": str(i.watchlist_id),
        "item_type": i.item_type,
        "value": i.value,
        "notes": i.notes,
        "last_matched_at": i.last_matched_at.isoformat() if i.last_matched_at else None,
    }


@router.get("/watchlists")
async def list_watchlists(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    watchlists = (await db.execute(select(Watchlist).order_by(Watchlist.name))).scalars().all()
    counts = {
        str(wid): cnt
        for wid, cnt in (
            await db.execute(
                select(WatchlistItem.watchlist_id, func.count()).group_by(WatchlistItem.watchlist_id)
            )
        ).all()
    }
    return [_wl_out(w, counts.get(str(w.id), 0)) for w in watchlists]


@router.post("/watchlists", status_code=201)
async def create_watchlist(
    body: WatchlistIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    wl = Watchlist(name=body.name.strip(), description=body.description, enabled=body.enabled, owner_email=user.email)
    db.add(wl)
    await record_audit(
        db, action="watchlist.create", actor_email=user.email, resource_type="watchlist",
        detail={"name": wl.name},
    )
    await db.commit()
    await db.refresh(wl)
    return _wl_out(wl, 0)


@router.delete("/watchlists/{watchlist_id}")
async def delete_watchlist(
    watchlist_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    wl = await db.get(Watchlist, watchlist_id)
    if wl is None:
        raise HTTPException(404, "Watchlist not found")
    await db.execute(WatchlistItem.__table__.delete().where(WatchlistItem.watchlist_id == watchlist_id))
    await db.delete(wl)
    await record_audit(
        db, action="watchlist.delete", actor_email=user.email, resource_type="watchlist",
        resource_id=str(watchlist_id),
    )
    await db.commit()
    return {"status": "deleted"}


@router.get("/watchlists/{watchlist_id}/items")
async def list_watchlist_items(
    watchlist_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    wl = await db.get(Watchlist, watchlist_id)
    if wl is None:
        raise HTTPException(404, "Watchlist not found")
    items = (
        await db.execute(
            select(WatchlistItem).where(WatchlistItem.watchlist_id == watchlist_id).order_by(WatchlistItem.value)
        )
    ).scalars().all()
    return [_item_out(i) for i in items]


@router.post("/watchlists/{watchlist_id}/items", status_code=201)
async def add_watchlist_item(
    watchlist_id: uuid.UUID,
    body: WatchlistItemIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    wl = await db.get(Watchlist, watchlist_id)
    if wl is None:
        raise HTTPException(404, "Watchlist not found")
    if body.item_type not in ITEM_TYPES:
        raise HTTPException(422, f"item_type must be one of {', '.join(sorted(ITEM_TYPES))}")
    dup = (
        await db.execute(
            select(WatchlistItem).where(
                WatchlistItem.watchlist_id == watchlist_id,
                WatchlistItem.item_type == body.item_type,
                WatchlistItem.value == body.value.strip(),
            )
        )
    ).scalar_one_or_none()
    if dup:
        raise HTTPException(409, "Item already on this watchlist")
    item = WatchlistItem(
        watchlist_id=watchlist_id,
        item_type=body.item_type,
        value=body.value.strip(),
        notes=body.notes,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return _item_out(item)


@router.delete("/watchlists/{watchlist_id}/items/{item_id}")
async def delete_watchlist_item(
    watchlist_id: uuid.UUID,
    item_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    item = await db.get(WatchlistItem, item_id)
    if item is None or item.watchlist_id != watchlist_id:
        raise HTTPException(404, "Item not found")
    await db.delete(item)
    await record_audit(
        db, action="watchlist.item_delete", actor_email=user.email, resource_type="watchlist_item",
        resource_id=str(item_id),
    )
    await db.commit()
    return {"status": "deleted"}
