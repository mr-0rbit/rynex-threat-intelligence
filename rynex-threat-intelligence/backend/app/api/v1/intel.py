"""Intelligence endpoints: dashboard overview, IOCs, vulnerabilities, breaches, news, alerts, sources."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import admin_required, analyst_required, get_current_user
from app.core.database import get_db
from app.models import (
    Alert,
    BreachIncident,
    CollectionJob,
    IntelligenceSource,
    IOC,
    NewsArticle,
    User,
    Vulnerability,
)
from app.services.ingestion import run_collector

router = APIRouter(tags=["intelligence"])


# ---------- Dashboard ----------

@router.get("/dashboard/overview")
async def dashboard_overview(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    now = datetime.now(UTC)
    day_ago = now - timedelta(hours=24)

    async def count(model, *filters):
        stmt = select(func.count()).select_from(model)
        for f in filters:
            stmt = stmt.where(f)
        return (await db.execute(stmt)).scalar() or 0

    active_alerts = await count(Alert, Alert.status.in_(["new", "acknowledged", "investigating"]))
    new_alerts_24h = await count(Alert, Alert.detected_at >= day_ago)
    breaches_24h = await count(BreachIncident, BreachIncident.published_at >= day_ago)
    critical_vulns = await count(Vulnerability, Vulnerability.severity == "critical")
    kev_count = await count(Vulnerability, Vulnerability.in_kev.is_(True))
    ioc_count = await count(IOC)
    ioc_new_24h = await count(IOC, IOC.last_seen_at >= day_ago)
    sources_total = await count(IntelligenceSource, IntelligenceSource.enabled.is_(True))
    sources_failing = await count(
        IntelligenceSource, IntelligenceSource.health_status.in_(["degraded", "failing"])
    )

    latest_news = (
        await db.execute(
            select(NewsArticle).order_by(NewsArticle.published_at.desc().nullslast()).limit(10)
        )
    ).scalars().all()

    return {
        "alerts": {
            "active": active_alerts,
            "new_today": new_alerts_24h,
        },
        "breaches": {"reported_24h": breaches_24h},
        "vulnerabilities": {"critical_open": critical_vulns, "known_exploited": kev_count},
        "iocs": {"total": ioc_count, "new_24h": ioc_new_24h},
        "sources": {"connected": sources_total, "failing": sources_failing},
        "latest_news": [
            {
                "headline": a.headline,
                "publisher": a.publisher,
                "url": a.url,
                "published_at": a.published_at.isoformat() if a.published_at else None,
            }
            for a in latest_news
        ],
        "generated_at": now.isoformat(),
    }


# ---------- Alerts ----------

class AlertStatusUpdate(BaseModel):
    status: str
    assigned_to: uuid.UUID | None = None


ALERT_STATUSES = {"new", "acknowledged", "investigating", "confirmed", "false_positive", "resolved"}


@router.get("/alerts")
async def list_alerts(
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = None,
    category: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    stmt = select(Alert).order_by(Alert.detected_at.desc())
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if category:
        stmt = stmt.where(Alert.category == category)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    alerts = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": str(a.id),
                "title": a.title,
                "category": a.category,
                "severity": a.severity,
                "status": a.status,
                "confidence": a.confidence,
                "detected_at": a.detected_at.isoformat(),
                "first_published_at": a.first_published_at.isoformat() if a.first_published_at else None,
                "occurrence_count": a.occurrence_count,
                "recommended_action": a.recommended_action,
                "evidence_sources": a.evidence_sources,
            }
            for a in alerts
        ],
    }


@router.post("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: uuid.UUID,
    body: AlertStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    if body.status not in ALERT_STATUSES:
        raise HTTPException(422, f"status must be one of {sorted(ALERT_STATUSES)}")
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = body.status
    if body.assigned_to:
        alert.assigned_to = body.assigned_to
    return {"id": str(alert.id), "status": alert.status}


# ---------- Sources & collection ----------

@router.get("/sources")
async def list_sources(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    sources = (await db.execute(select(IntelligenceSource).order_by(IntelligenceSource.name))).scalars().all()
    return {
        "total": len(sources),
        "items": [
            {
                "slug": s.slug,
                "name": s.name,
                "category": s.category,
                "enabled": s.enabled,
                "health_status": s.health_status,
                "last_success_at": s.last_success_at.isoformat() if s.last_success_at else None,
                "last_failure_at": s.last_failure_at.isoformat() if s.last_failure_at else None,
                "consecutive_failures": s.consecutive_failures,
                "total_records_collected": s.total_records_collected,
                "collection_interval_minutes": s.collection_interval_minutes,
                "commercial_use_status": s.commercial_use_status,
                "api_key_configured": s.api_key_setting is not None,
            }
            for s in sources
        ]
    }


@router.get("/sources/{slug}/jobs")
async def source_jobs(
    slug: str, limit: int = Query(20, le=100), db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)
) -> dict:
    jobs = (
        await db.execute(
            select(CollectionJob)
            .where(CollectionJob.source_slug == slug)
            .order_by(CollectionJob.started_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    return {
        "items": [
            {
                "id": str(j.id),
                "status": j.status,
                "trigger": j.trigger,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "duration_seconds": j.duration_seconds,
                "records_received": j.records_received,
                "records_stored": j.records_stored,
                "records_rejected": j.records_rejected,
                "error": j.error,
            }
            for j in jobs
        ]
    }


@router.post("/sources/{slug}/collect")
async def trigger_collection(
    slug: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(analyst_required),
) -> dict:
    try:
        result = await run_collector(slug, db, trigger="manual")
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return result


# ---------- IOCs ----------

@router.get("/iocs")
async def list_iocs(
    type_filter: str | None = Query(None, alias="type"),
    q: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    stmt = select(IOC).order_by(IOC.last_seen_at.desc().nullslast())
    if type_filter:
        stmt = stmt.where(IOC.type == type_filter)
    if q:
        stmt = stmt.where(IOC.value.ilike(f"%{q}%"))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    iocs = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": str(i.id),
                "value": i.value,
                "type": i.type,
                "source_slug": i.source_slug,
                "confidence": i.confidence,
                "confidence_reasons": i.confidence_reasons,
                "malware_family": i.malware_family,
                "first_seen_at": i.first_seen_at.isoformat() if i.first_seen_at else None,
                "last_seen_at": i.last_seen_at.isoformat() if i.last_seen_at else None,
                "reports_count": i.reports_count,
            }
            for i in iocs
        ],
    }


# ---------- Vulnerabilities ----------

@router.get("/vulnerabilities")
async def list_vulnerabilities(
    severity: str | None = None,
    kev: bool | None = None,
    q: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    stmt = select(Vulnerability).order_by(Vulnerability.published_at.desc().nullslast())
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    if kev is not None:
        stmt = stmt.where(Vulnerability.in_kev.is_(kev))
    if q:
        stmt = stmt.where(Vulnerability.cve_id.ilike(f"%{q}%") | Vulnerability.title.ilike(f"%{q}%"))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    vulns = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "cve_id": v.cve_id,
                "title": v.title,
                "severity": v.severity,
                "cvss_base_score": v.cvss_base_score,
                "epss_score": v.epss_score,
                "in_kev": v.in_kev,
                "kev_date_added": v.kev_date_added.isoformat() if v.kev_date_added else None,
                "known_ransomware_use": v.kev_known_ransomware_use,
                "published_at": v.published_at.isoformat() if v.published_at else None,
            }
            for v in vulns
        ],
    }


# ---------- Breaches ----------

@router.get("/breaches")
async def list_breaches(
    verification: str | None = None,
    q: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    stmt = select(BreachIncident).order_by(BreachIncident.published_at.desc().nullslast())
    if verification:
        stmt = stmt.where(BreachIncident.verification_status == verification)
    if q:
        stmt = stmt.where(BreachIncident.organization_name.ilike(f"%{q}%"))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    breaches = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "id": str(b.id),
                "organization_name": b.organization_name,
                "organization_domain": b.organization_domain,
                "industry": b.industry,
                "country": b.country,
                "threat_actor_name": b.threat_actor_name,
                "claimed_data_types": b.claimed_data_types,
                "published_at": b.published_at.isoformat() if b.published_at else None,
                "verification_status": b.verification_status,
                "confidence": b.confidence,
                "confidence_reasons": b.confidence_reasons,
                "source_slug": b.source_slug,
                "source_url": b.source_url,
            }
            for b in breaches
        ],
    }


# ---------- News ----------

@router.get("/news")
async def list_news(
    publisher: str | None = None,
    q: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    stmt = select(NewsArticle).order_by(NewsArticle.published_at.desc().nullslast())
    if publisher:
        stmt = stmt.where(NewsArticle.publisher == publisher)
    if q:
        stmt = stmt.where(NewsArticle.headline.ilike(f"%{q}%"))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar()
    articles = (await db.execute(stmt.limit(limit).offset(offset))).scalars().all()
    return {
        "total": total,
        "items": [
            {
                "headline": a.headline,
                "url": a.url,
                "publisher": a.publisher,
                "summary": a.summary,
                "published_at": a.published_at.isoformat() if a.published_at else None,
                "collected_at": a.collected_at.isoformat(),
                "categories": a.categories,
            }
            for a in articles
        ],
    }
