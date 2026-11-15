"""Prometheus /metrics endpoint — hand-rolled text exposition (no extra dep).

Authentication required (JWT or service API key) so deployment metrics are not
publicly exposed; Prometheus can scrape with an API key via X-API-Key.
"""

from fastapi import APIRouter, Depends, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models import (
    Alert,
    BreachIncident,
    CollectionJob,
    IOC,
    IntelligenceSource,
    NewsArticle,
    User,
    Vulnerability,
)

router = APIRouter(tags=["ops"])


def _fmt_metric(name: str, mtype: str, help_text: str, samples: list[tuple[dict, float]]) -> str:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {mtype}"]
    for labels, value in samples:
        label_str = ""
        if labels:
            parts = ",".join(f'{k}="{v}"' for k, v in labels.items())
            label_str = "{" + parts + "}"
        lines.append(f"{name}{label_str} {value}")
    return "\n".join(lines)


async def _counts(db: AsyncSession) -> dict[str, float]:
    async def count(stmt) -> float:
        return float((await db.execute(stmt)).scalar() or 0)

    out = {}
    out["alerts_total"] = await count(select(func.count()).select_from(Alert))
    out["iocs_total"] = await count(select(func.count()).select_from(IOC))
    out["vulnerabilities_total"] = await count(select(func.count()).select_from(Vulnerability))
    out["kev_total"] = await count(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.in_kev.is_(True))
    )
    out["breaches_total"] = await count(select(func.count()).select_from(BreachIncident))
    out["news_total"] = await count(select(func.count()).select_from(NewsArticle))
    out["users_total"] = await count(select(func.count()).select_from(User))
    out["sources_failing"] = await count(
        select(func.count())
        .select_from(IntelligenceSource)
        .where(IntelligenceSource.health_status.in_(["degraded", "failing"]))
    )
    return out


async def _severity_samples(db: AsyncSession) -> list[tuple[dict, float]]:
    rows = (await db.execute(select(Alert.severity, func.count()).group_by(Alert.severity))).all()
    return [({"severity": sev}, float(c)) for sev, c in rows if sev is not None]


async def _source_health_samples(db: AsyncSession) -> list[tuple[dict, float]]:
    rows = (
        await db.execute(select(IntelligenceSource.slug, IntelligenceSource.health_status))
    ).all()
    return [({"slug": slug, "health": health or "unknown"}, 1.0) for slug, health in rows]


async def _recent_job_samples(db: AsyncSession) -> list[tuple[dict, float]]:
    rows = (
        await db.execute(
            select(CollectionJob.source_slug, CollectionJob.status, func.max(CollectionJob.started_at))
            .group_by(CollectionJob.source_slug, CollectionJob.status)
        )
    ).all()
    return [({"slug": slug, "status": status}, 1.0) for slug, status, _ in rows]


@router.get("/metrics")
async def metrics(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    sections = []

    counts = await _counts(db)
    sections.append(
        _fmt_metric(
            "rtip_records_total", "gauge",
            "Total records stored per entity type",
            [({"kind": k}, v) for k, v in counts.items()],
        )
    )
    sections.append(
        _fmt_metric(
            "rtip_alerts_by_severity", "gauge",
            "Alerts grouped by severity",
            await _severity_samples(db),
        )
    )
    sections.append(
        _fmt_metric(
            "rtip_source_health", "gauge",
            "1 = source in this health state",
            await _source_health_samples(db),
        )
    )
    sections.append(
        _fmt_metric(
            "rtip_collection_job_status", "gauge",
            "1 = job exists in this status",
            await _recent_job_samples(db),
        )
    )

    body = "\n\n".join(sections) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
