"""Dashboard chart aggregates, global search, and report generation.

Every aggregate is computed from actual database records — no mock data.
"""

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import (
    Alert,
    BreachIncident,
    IOC,
    NewsArticle,
    User,
    Vulnerability,
)
from app.api.deps import get_current_user

router = APIRouter(tags=["analytics"])


# ---------- Chart aggregates ----------

@router.get("/dashboard/charts")
async def dashboard_charts(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    now = datetime.now(UTC)
    fourteen_days_ago = now - timedelta(days=14)

    # Alerts per day (14d)
    alert_rows = (
        await db.execute(
            select(func.date(Alert.detected_at), func.count())
            .where(Alert.detected_at >= fourteen_days_ago)
            .group_by(func.date(Alert.detected_at))
        )
    ).all()

    # Alert severity distribution
    severity_rows = (await db.execute(select(Alert.severity, func.count()).group_by(Alert.severity))).all()

    # IOC types
    ioc_rows = (await db.execute(select(IOC.type, func.count()).group_by(IOC.type))).all()

    # Source contribution (records collected per source)
    source_rows = (
        await db.execute(
            select(IOC.source_slug, func.count())
            .group_by(IOC.source_slug)
        )
    ).all()
    breach_source_rows = (
        await db.execute(
            select(BreachIncident.source_slug, func.count()).group_by(BreachIncident.source_slug)
        )
    ).all()
    news_source_rows = (
        await db.execute(select(NewsArticle.publisher, func.count()).group_by(NewsArticle.publisher))
    ).all()

    # Breach verification statuses
    breach_rows = (
        await db.execute(
            select(BreachIncident.verification_status, func.count()).group_by(BreachIncident.verification_status)
        )
    ).all()

    # CVE severity distribution
    cve_rows = (
        await db.execute(
            select(Vulnerability.severity, func.count())
            .group_by(Vulnerability.severity)
        )
    ).all()

    # News per day (14d)
    news_rows = (
        await db.execute(
            select(func.date(NewsArticle.collected_at), func.count())
            .where(NewsArticle.collected_at >= fourteen_days_ago)
            .group_by(func.date(NewsArticle.collected_at))
        )
    ).all()

    def rows_to_pairs(rows):
        return [{"label": str(label), "value": int(count)} for label, count in rows if label is not None]

    return {
        "alerts_over_time": rows_to_pairs(alert_rows),
        "alert_severity": rows_to_pairs(severity_rows),
        "ioc_types": rows_to_pairs(ioc_rows),
        "source_contribution": rows_to_pairs(source_rows + breach_source_rows),
        "news_by_publisher": rows_to_pairs(news_source_rows),
        "breaches_by_verification": rows_to_pairs(breach_rows),
        "cve_severity": rows_to_pairs(cve_rows),
        "news_over_time": rows_to_pairs(news_rows),
        "generated_at": now.isoformat(),
    }


# ---------- Global search ----------

@router.get("/search")
async def global_search(
    q: str = Query(min_length=2, max_length=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    like = f"%{q}%"
    iocs = (
        await db.execute(select(IOC).where(IOC.value.ilike(like)).limit(10))
    ).scalars().all()
    vulns = (
        await db.execute(
            select(Vulnerability).where(Vulnerability.cve_id.ilike(like) | Vulnerability.title.ilike(like)).limit(10)
        )
    ).scalars().all()
    breaches = (
        await db.execute(
            select(BreachIncident).where(BreachIncident.organization_name.ilike(like)).limit(10)
        )
    ).scalars().all()
    news = (
        await db.execute(select(NewsArticle).where(NewsArticle.headline.ilike(like)).limit(10))
    ).scalars().all()
    alerts = (
        await db.execute(select(Alert).where(Alert.title.ilike(like)).limit(10))
    ).scalars().all()

    return {
        "query": q,
        "results": {
            "iocs": [{"value": i.value, "type": i.type, "confidence": i.confidence, "source": i.source_slug} for i in iocs],
            "vulnerabilities": [
                {"cve_id": v.cve_id, "severity": v.severity, "cvss": v.cvss_base_score, "in_kev": v.in_kev, "title": v.title}
                for v in vulns
            ],
            "breaches": [
                {
                    "organization": b.organization_name,
                    "actor": b.threat_actor_name,
                    "verification": b.verification_status,
                    "published_at": b.published_at.isoformat() if b.published_at else None,
                }
                for b in breaches
            ],
            "news": [
                {"headline": n.headline, "publisher": n.publisher, "url": n.url,
                 "published_at": n.published_at.isoformat() if n.published_at else None}
                for n in news
            ],
            "alerts": [{"title": a.title, "severity": a.severity, "status": a.status, "id": str(a.id)} for a in alerts],
        },
    }


# ---------- Reports ----------

REPORT_TYPES = {"breaches", "vulnerabilities", "iocs", "alerts"}


def _to_csv(rows: list[list]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(rows)
    return buf.getvalue()


@router.get("/reports/{report_type}", response_model=None)
async def generate_report(
    report_type: str,
    format: str = Query("json", pattern="^(json|csv|md)$"),
    limit: int = Query(500, le=2000),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> StreamingResponse | dict:
    if report_type not in REPORT_TYPES:
        from fastapi import HTTPException

        raise HTTPException(404, f"report_type must be one of {sorted(REPORT_TYPES)}")

    now = datetime.now(UTC).strftime("%Y-%m-%d")
    headers_out = {
        "breaches": "breach_intelligence",
        "vulnerabilities": "vulnerability_intelligence",
        "iocs": "ioc_intelligence",
        "alerts": "alert_history",
    }

    if report_type == "breaches":
        rows_iter = (await db.execute(select(BreachIncident).order_by(BreachIncident.published_at.desc()).limit(limit))).scalars().all()
        head = ["organization", "domain", "industry", "country", "threat_actor", "verification", "confidence", "published_at", "source_url"]
        records = [
            [b.organization_name, b.organization_domain or "", b.industry or "", b.country or "",
             b.threat_actor_name or "", b.verification_status, b.confidence,
             b.published_at.date().isoformat() if b.published_at else "", b.source_url or ""]
            for b in rows_iter
        ]
    elif report_type == "vulnerabilities":
        rows_iter = (await db.execute(select(Vulnerability).order_by(Vulnerability.published_at.desc()).limit(limit))).scalars().all()
        head = ["cve_id", "severity", "cvss", "epss", "in_kev", "published_at", "title"]
        records = [
            [v.cve_id, v.severity or "", v.cvss_base_score or "", v.epss_score if v.epss_score is not None else "",
             v.in_kev, v.published_at.date().isoformat() if v.published_at else "", (v.title or "")[:200]]
            for v in rows_iter
        ]
    elif report_type == "iocs":
        rows_iter = (await db.execute(select(IOC).order_by(IOC.last_seen_at.desc().nullslast()).limit(limit))).scalars().all()
        head = ["value", "type", "confidence", "malware", "source", "last_seen"]
        records = [
            [i.value, i.type, i.confidence, i.malware_family or "", i.source_slug,
             i.last_seen_at.isoformat() if i.last_seen_at else ""]
            for i in rows_iter
        ]
    else:
        rows_iter = (await db.execute(select(Alert).order_by(Alert.detected_at.desc()).limit(limit))).scalars().all()
        head = ["detected_at", "severity", "category", "status", "confidence", "title"]
        records = [
            [a.detected_at.date().isoformat(), a.severity, a.category, a.status, a.confidence, a.title]
            for a in rows_iter
        ]

    title = f"RTIP {headers_out[report_type].replace('_', ' ').title()} Report — {now}"
    if format == "json":
        return {"report": headers_out[report_type], "title": title, "generated_at": datetime.now(UTC).isoformat(),
                "record_count": len(records), "columns": head, "rows": records}
    if format == "csv":
        csv_text = _to_csv([head] + records)
        return StreamingResponse(
            iter([csv_text]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="rtip_{report_type}_{now}.csv"'},
        )
    # markdown
    md = [f"# {title}", "", f"_Generated: {datetime.now(UTC).isoformat()} — {len(records)} records_", "",
          "| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for r in records[:200]:
        md.append("| " + " | ".join(str(c).replace("|", "/") for c in r) + " |")
    if len(records) > 200:
        md.append(f"_(truncated to first 200 rows of {len(records)})_")
    md.append("")
    md.append("## Sources")
    md.append("All records retain original source provenance in the platform database (RTIP).")
    return PlainTextResponse("\n".join(md), media_type="text/markdown")
