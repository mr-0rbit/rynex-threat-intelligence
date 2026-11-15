"""Investigations: analyst case management over intelligence entities."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import analyst_required, get_current_user
from app.core.database import get_db
from app.models import Investigation, User
from app.services.audit import record_audit

router = APIRouter(tags=["investigations"])

INVESTIGATION_STATUSES = {"open", "in_progress", "closed", "reported"}


class InvestigationIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    status: str = Field("open")
    severity: str | None = Field(None, description="critical|high|medium|low|informational")
    summary: str | None = None
    entity_refs: dict | None = Field(
        None, description='{"iocs": ["..."], "cves": ["CVE-..."], "orgs": ["..."], "alert_ids": [...]}'
    )
    assigned_to: uuid.UUID | None = None


class InvestigationPatch(BaseModel):
    title: str | None = Field(None, max_length=512)
    status: str | None = None
    severity: str | None = None
    summary: str | None = None
    entity_refs: dict | None = None
    assigned_to: uuid.UUID | None = None


class NoteIn(BaseModel):
    note: str = Field(..., min_length=1)


def _inv_out(i: Investigation) -> dict:
    return {
        "id": str(i.id),
        "title": i.title,
        "status": i.status,
        "severity": i.severity,
        "summary": i.summary,
        "entity_refs": i.entity_refs,
        "analyst_notes": i.analyst_notes,
        "assigned_to": str(i.assigned_to) if i.assigned_to else None,
        "confidence": i.confidence,
        "created_at": i.created_at.isoformat() if i.created_at else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
    }


@router.get("/investigations")
async def list_investigations(
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    stmt = select(Investigation).order_by(Investigation.updated_at.desc().nullslast())
    if status_filter:
        stmt = stmt.where(Investigation.status == status_filter)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    items = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [_inv_out(i) for i in items]}


@router.post("/investigations", status_code=201)
async def create_investigation(
    body: InvestigationIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    if body.status not in INVESTIGATION_STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(sorted(INVESTIGATION_STATUSES))}")
    inv = Investigation(
        title=body.title.strip(),
        status=body.status,
        severity=body.severity,
        summary=body.summary,
        entity_refs=body.entity_refs,
        assigned_to=body.assigned_to,
        analyst_notes=[{"author": user.email, "note": "Investigation opened", "at": _now_iso()}],
    )
    db.add(inv)
    await record_audit(
        db, action="investigation.create", actor_email=user.email, resource_type="investigation",
        detail={"title": inv.title},
    )
    await db.commit()
    await db.refresh(inv)
    return _inv_out(inv)


@router.get("/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    inv = await db.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    return _inv_out(inv)


@router.patch("/investigations/{investigation_id}")
async def update_investigation(
    investigation_id: uuid.UUID,
    body: InvestigationPatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    inv = await db.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    if body.status is not None and body.status not in INVESTIGATION_STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(sorted(INVESTIGATION_STATUSES))}")
    for field in ("title", "status", "severity", "summary", "entity_refs", "assigned_to"):
        if getattr(body, field) is not None:
            setattr(inv, field, getattr(body, field))
    await record_audit(
        db, action="investigation.update", actor_email=user.email, resource_type="investigation",
        resource_id=str(inv.id),
    )
    await db.commit()
    await db.refresh(inv)
    return _inv_out(inv)


@router.post("/investigations/{investigation_id}/notes")
async def add_investigation_note(
    investigation_id: uuid.UUID,
    body: NoteIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    inv = await db.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    notes = list(inv.analyst_notes or [])
    notes.append({"author": user.email, "note": body.note, "at": _now_iso()})
    inv.analyst_notes = notes  # reassign so the JSON column change is detected
    await db.commit()
    await db.refresh(inv)
    return _inv_out(inv)


@router.delete("/investigations/{investigation_id}")
async def delete_investigation(
    investigation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    inv = await db.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    await db.delete(inv)
    await record_audit(
        db, action="investigation.delete", actor_email=user.email, resource_type="investigation",
        resource_id=str(investigation_id),
    )
    await db.commit()
    return {"status": "deleted"}


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
