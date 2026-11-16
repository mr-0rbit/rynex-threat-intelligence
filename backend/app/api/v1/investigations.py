"""Investigations: analyst case management over intelligence entities."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, investigation_writer_required
from app.core.database import get_db
from app.models import CorrelationEvent, Investigation, InvestigationTimeline, User
from app.services.audit import record_audit
from app.services.correlation import CorrelationEngine

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
    stmt = (
        select(Investigation)
        .where(Investigation.organization_id == user.organization_id)
        .order_by(Investigation.updated_at.desc().nullslast())
    )
    if status_filter:
        stmt = stmt.where(Investigation.status == status_filter)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    items = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [_inv_out(i) for i in items]}


@router.post("/investigations", status_code=201)
async def create_investigation(
    body: InvestigationIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(investigation_writer_required),
) -> dict:
    if body.status not in INVESTIGATION_STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(sorted(INVESTIGATION_STATUSES))}")
    if body.assigned_to:
        assignee = (
            await db.execute(
                select(User).where(
                    User.id == body.assigned_to,
                    User.organization_id == user.organization_id,
                    User.is_active.is_(True),
                )
            )
        ).scalar_one_or_none()
        if assignee is None:
            raise HTTPException(422, "Assignee must be an active user in this organization")
    inv = Investigation(
        organization_id=user.organization_id,
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
    inv = (
        await db.execute(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.organization_id == user.organization_id,
            )
        )
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    return _inv_out(inv)


@router.patch("/investigations/{investigation_id}")
async def update_investigation(
    investigation_id: uuid.UUID,
    body: InvestigationPatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(investigation_writer_required),
) -> dict:
    inv = (
        await db.execute(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.organization_id == user.organization_id,
            )
        )
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    if body.status is not None and body.status not in INVESTIGATION_STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(sorted(INVESTIGATION_STATUSES))}")
    if body.assigned_to:
        assignee = (
            await db.execute(
                select(User).where(
                    User.id == body.assigned_to,
                    User.organization_id == user.organization_id,
                    User.is_active.is_(True),
                )
            )
        ).scalar_one_or_none()
        if assignee is None:
            raise HTTPException(422, "Assignee must be an active user in this organization")
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
    user: User = Depends(investigation_writer_required),
) -> dict:
    inv = (
        await db.execute(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.organization_id == user.organization_id,
            )
        )
    ).scalar_one_or_none()
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
    user: User = Depends(investigation_writer_required),
) -> dict:
    inv = (
        await db.execute(
            select(Investigation).where(
                Investigation.id == investigation_id,
                Investigation.organization_id == user.organization_id,
            )
        )
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(404, "Investigation not found")
    await db.delete(inv)
    await record_audit(
        db, action="investigation.delete", actor_email=user.email, resource_type="investigation",
        resource_id=str(investigation_id),
    )
    await db.commit()
    return {"status": "deleted"}


@router.post("/investigations/{investigation_id}/timeline")
async def generate_investigation_timeline(
    investigation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(investigation_writer_required),
) -> dict:
    """Auto-populate the investigation timeline from cross-source correlation."""
    engine = CorrelationEngine(db, user.organization_id)
    entries = await engine.generate_investigation_timeline(investigation_id)
    return {
        "generated": len(entries),
        "entries": [
            {
                "id": str(entry.id),
                "event_type": entry.event_type,
                "title": entry.title,
                "occurred_at": entry.occurred_at.isoformat(),
            }
            for entry in entries
        ],
    }


@router.get("/investigations/{investigation_id}/timeline")
async def get_investigation_timeline(
    investigation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    items = (
        await db.execute(
            select(InvestigationTimeline)
            .where(
                InvestigationTimeline.investigation_id == investigation_id,
                InvestigationTimeline.organization_id == user.organization_id,
            )
            .order_by(InvestigationTimeline.occurred_at.asc())
        )
    ).scalars().all()
    return {
        "items": [
            {
                "id": str(entry.id),
                "event_type": entry.event_type,
                "entity_key": entry.entity_key,
                "entity_type": entry.entity_type,
                "title": entry.title,
                "detail": entry.detail,
                "evidence_refs": entry.evidence_refs,
                "occurred_at": entry.occurred_at.isoformat() if entry.occurred_at else None,
            }
            for entry in items
        ]
    }


@router.get("/correlations")
async def list_correlations(
    entity_type: str | None = Query(None),
    min_confidence: float = Query(0.0),
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    stmt = (
        select(CorrelationEvent)
        .where(CorrelationEvent.organization_id == user.organization_id)
        .order_by(CorrelationEvent.confidence.desc())
    )
    if entity_type:
        stmt = stmt.where(CorrelationEvent.entity_type == entity_type)
    if min_confidence > 0:
        stmt = stmt.where(CorrelationEvent.confidence >= min_confidence)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    items = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": str(entry.id),
                "entity_key": entry.entity_key,
                "entity_type": entry.entity_type,
                "correlation_type": entry.correlation_type,
                "confidence": entry.confidence,
                "source_count": entry.source_count,
                "sources": entry.sources,
                "related_alert_ids": entry.related_alert_ids,
                "related_breach_ids": entry.related_breach_ids,
                "related_cve_ids": entry.related_cve_ids,
                "first_seen_at": (
                    entry.first_seen_at.isoformat() if entry.first_seen_at else None
                ),
                "last_seen_at": (
                    entry.last_seen_at.isoformat() if entry.last_seen_at else None
                ),
                "timeline": entry.timeline,
            }
            for entry in items
        ],
    }


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
