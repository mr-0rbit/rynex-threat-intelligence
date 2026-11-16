"""Prometheus /metrics endpoint — hand-rolled text exposition (no extra dep).

Authentication required (JWT or service API key) so deployment metrics are not
publicly exposed. Prometheus can use a service API key as a Bearer credential.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.timeutil import ensure_aware
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


def _escape_label_value(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt_metric(name: str, mtype: str, help_text: str, samples: list[tuple[dict, float]]) -> str:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {mtype}"]
    for labels, value in samples:
        label_str = ""
        if labels:
            parts = ",".join(f'{k}="{_escape_label_value(v)}"' for k, v in labels.items())
            label_str = "{" + parts + "}"
        lines.append(f"{name}{label_str} {value}")
    return "\n".join(lines)


async def _counts(db: AsyncSession, organization_id) -> dict[str, float]:
    async def count(stmt) -> float:
        return float((await db.execute(stmt)).scalar() or 0)

    out = {}
    out["alerts_total"] = await count(
        select(func.count()).select_from(Alert).where(Alert.organization_id == organization_id)
    )
    out["iocs_total"] = await count(select(func.count()).select_from(IOC))
    out["vulnerabilities_total"] = await count(select(func.count()).select_from(Vulnerability))
    out["kev_total"] = await count(
        select(func.count()).select_from(Vulnerability).where(Vulnerability.in_kev.is_(True))
    )
    out["breaches_total"] = await count(select(func.count()).select_from(BreachIncident))
    out["news_total"] = await count(select(func.count()).select_from(NewsArticle))
    out["users_total"] = await count(
        select(func.count()).select_from(User).where(User.organization_id == organization_id)
    )
    out["sources_failing"] = await count(
        select(func.count())
        .select_from(IntelligenceSource)
        .where(IntelligenceSource.health_status.in_(["degraded", "failing"]))
    )
    return out


OPEN_ALERT_STATUSES = ("new", "acknowledged", "investigating")


async def _severity_samples(db: AsyncSession, organization_id) -> list[tuple[dict, float]]:
    rows = (
        await db.execute(
            select(Alert.severity, func.count())
            .where(
                Alert.organization_id == organization_id,
                Alert.status.in_(OPEN_ALERT_STATUSES),
            )
            .group_by(Alert.severity)
        )
    ).all()
    return [({"severity": sev}, float(c)) for sev, c in rows if sev is not None]


async def _source_health_samples(db: AsyncSession) -> list[tuple[dict, float]]:
    rows = (
        await db.execute(select(IntelligenceSource.slug, IntelligenceSource.health_status))
    ).all()
    return [({"slug": slug, "health": health or "unknown"}, 1.0) for slug, health in rows]


async def _recent_job_samples(db: AsyncSession) -> list[tuple[dict, float]]:
    one_hour_ago = datetime.now(UTC) - timedelta(hours=1)
    rows = (
        await db.execute(
            select(CollectionJob.source_slug, CollectionJob.status, func.count())
            .where(CollectionJob.started_at >= one_hour_ago)
            .group_by(CollectionJob.source_slug, CollectionJob.status)
        )
    ).all()
    return [({"slug": slug, "status": status}, float(count)) for slug, status, count in rows]


async def _last_collection_samples(db: AsyncSession) -> list[tuple[dict, float]]:
    rows = (
        await db.execute(
            select(IntelligenceSource.slug, IntelligenceSource.last_success_at).where(
                IntelligenceSource.enabled.is_(True)
            )
        )
    ).all()
    samples = []
    for slug, last_success_at in rows:
        timestamp = ensure_aware(last_success_at)
        samples.append(
            (
                {"slug": slug},
                float(timestamp.timestamp()) if timestamp is not None else 0.0,
            )
        )
    return samples


@router.get("/metrics")
async def metrics(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    sections = []

    counts = await _counts(db, user.organization_id)
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
            "Open alerts (new, acknowledged, investigating) grouped by severity",
            await _severity_samples(db, user.organization_id),
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
            "Collection jobs by source and status in the last hour",
            await _recent_job_samples(db),
        )
    )
    sections.append(
        _fmt_metric(
            "rtip_last_collection_timestamp_seconds",
            "gauge",
            "Unix timestamp of the most recent successful collection by source; 0 means never",
            await _last_collection_samples(db),
        )
    )

    body = "\n\n".join(sections) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
