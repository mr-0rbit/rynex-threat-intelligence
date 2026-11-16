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
    IntelligenceSource,
    NewsArticle,
    ThreatActor,
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
            .where(
                Alert.organization_id == user.organization_id,
                Alert.detected_at >= fourteen_days_ago,
            )
            .group_by(func.date(Alert.detected_at))
        )
    ).all()

    # Alert severity distribution
    severity_rows = (
        await db.execute(
            select(Alert.severity, func.count())
            .where(Alert.organization_id == user.organization_id)
            .group_by(Alert.severity)
        )
    ).all()

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
        await db.execute(
            select(Alert)
            .where(Alert.organization_id == user.organization_id, Alert.title.ilike(like))
            .limit(10)
        )
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
        rows_iter = (
            await db.execute(
                select(Alert)
                .where(Alert.organization_id == user.organization_id)
                .order_by(Alert.detected_at.desc())
                .limit(limit)
            )
        ).scalars().all()
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


# ---------- STIX 2.1 export ----------

_STIX_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace, deterministic IDs


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type == "ipv6":
        return f"[ipv6-addr:value = '{value}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc_type == "url":
        return f"[url:value = '{value}']"
    if ioc_type in ("md5", "sha1", "sha256"):
        algo = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[ioc_type]
        return f"[file:hashes.'{algo}' = '{value}']"
    if ioc_type == "email":
        return f"[email-addr:value = '{value}']"
    return None


def _stix_ts(dt) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else None


@router.get("/export/stix")
async def export_stix(
    limit: int = Query(2000, le=5000),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    """STIX 2.1 bundle: IOCs as indicators, CVEs as vulnerabilities,
    breaches as x-rtip-breach custom objects, actors as threat-actors.
    Deterministic uuid5 IDs so re-exports are diffable."""
    import uuid as _uuid

    objects: list[dict] = []
    now = _stix_ts(datetime.now(UTC))

    iocs = (
        await db.execute(
            select(IOC).order_by(IOC.last_seen_at.desc().nullslast()).limit(limit)
        )
    ).scalars().all()
    for ioc in iocs:
        pattern = _stix_pattern(ioc.type, ioc.value)
        if not pattern:
            continue
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{_uuid.uuid5(_STIX_NAMESPACE, f'rtip:ioc:{ioc.type}:{ioc.value}')}",
                "created": _stix_ts(ioc.first_seen_at) or now,
                "modified": _stix_ts(ioc.last_seen_at) or now,
                "name": f"{ioc.type.upper()}: {ioc.value[:200]}",
                "description": ioc.description,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": _stix_ts(ioc.first_seen_at) or now,
                "confidence": int(round((ioc.confidence or 0) * 100)),
                "labels": (ioc.tags or []) + ([ioc.malware_family] if ioc.malware_family else []),
                "x_rtip_source": ioc.source_slug,
                "x_rtip_reports_count": ioc.reports_count,
                "x_rtip_corroborating_sources": ioc.corroborating_sources,
            }
        )

    vulns = (
        await db.execute(
            select(Vulnerability).order_by(Vulnerability.published_at.desc().nullslast()).limit(limit)
        )
    ).scalars().all()
    for v in vulns:
        objects.append(
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{_uuid.uuid5(_STIX_NAMESPACE, f'rtip:cve:{v.cve_id}')}",
                "created": _stix_ts(v.published_at) or now,
                "modified": _stix_ts(v.modified_at) or now,
                "name": v.cve_id,
                "description": v.description,
                "external_references": [{"source_name": "cve", "external_id": v.cve_id}],
                "x_rtip_cvss_base_score": v.cvss_base_score,
                "x_rtip_epss_score": v.epss_score,
                "x_rtip_in_kev": v.in_kev,
            }
        )

    breaches = (
        await db.execute(
            select(BreachIncident).order_by(BreachIncident.published_at.desc().nullslast()).limit(limit // 2 or 1)
        )
    ).scalars().all()
    for b in breaches:
        objects.append(
            {
                "type": "x-rtip-breach",
                "spec_version": "2.1",
                "id": f"x-rtip-breach--{_uuid.uuid5(_STIX_NAMESPACE, f'rtip:breach:{b.fingerprint}')}",
                "created": _stix_ts(b.published_at) or now,
                "modified": _stix_ts(b.published_at) or now,
                "name": f"Breach claim: {b.organization_name[:200]}",
                "description": b.summary,
                "x_rtip_organization": b.organization_name,
                "x_rtip_organization_domain": b.organization_domain,
                "x_rtip_threat_actor": b.threat_actor_name,
                "x_rtip_verification_status": b.verification_status,
                "x_rtip_confidence": b.confidence,
                "x_rtip_record_count": b.record_count,
                "x_rtip_source": b.source_slug,
                "x_rtip_source_url": b.source_url,
            }
        )

    actors = (
        await db.execute(select(ThreatActor).limit(limit // 10 or 1))
    ).scalars().all()
    for a in actors:
        objects.append(
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": f"threat-actor--{_uuid.uuid5(_STIX_NAMESPACE, f'rtip:actor:{a.name}')}",
                "created": now,
                "modified": now,
                "name": a.name,
                "description": a.description,
                "x_rtip_attribution_status": a.attribution_status,
            }
        )

    return {
        "type": "bundle",
        "id": f"bundle--{_uuid.uuid5(_STIX_NAMESPACE, f'rtip:export:{now}')}",
        "objects": objects,
    }


# ---------- Executive report ----------

@router.get("/executive-report")
async def executive_report(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> PlainTextResponse:
    """Management-level posture summary. Markdown, deterministic, no AI prose."""
    now = datetime.now(UTC)
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    async def count(stmt) -> int:
        return (await db.execute(stmt)).scalar() or 0

    def cnt(model, *filters):
        stmt = select(func.count()).select_from(model)
        for f in filters:
            stmt = stmt.where(f)
        return stmt

    active_by_severity = dict(
        (await db.execute(
            select(Alert.severity, func.count())
            .where(
                Alert.organization_id == user.organization_id,
                Alert.status.in_(["new", "acknowledged", "investigating"]),
            )
            .group_by(Alert.severity)
        )).all()
    )
    new_alerts_24h = await count(
        cnt(Alert, Alert.organization_id == user.organization_id, Alert.detected_at >= day_ago)
    )
    kev_count = await count(cnt(Vulnerability, Vulnerability.in_kev.is_(True)))
    kev_ransomware = await count(cnt(Vulnerability, Vulnerability.in_kev.is_(True), Vulnerability.kev_known_ransomware_use.is_(True)))
    critical_cves = await count(cnt(Vulnerability, Vulnerability.severity == "critical"))
    breaches_week = await count(cnt(BreachIncident, BreachIncident.published_at >= week_ago))
    sources_failing = await count(
        cnt(IntelligenceSource, IntelligenceSource.health_status.in_(["degraded", "failing"]))
    )
    sources_total = await count(cnt(IntelligenceSource, IntelligenceSource.enabled.is_(True)))

    # Asset-relevant alerts: the alerts that touch owned assets
    asset_alerts = (
        (await db.execute(
            select(Alert)
            .where(
                Alert.organization_id == user.organization_id,
                Alert.status.in_(["new", "acknowledged", "investigating"]),
            )
            .order_by(Alert.detected_at.desc())
            .limit(200)
        )).scalars().all()
    )
    asset_relevant = [a for a in asset_alerts if (a.affected_entities or {}).get("matched_assets")]

    top_alerts = sorted(
        asset_alerts,
        key=lambda a: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(a.severity, 5), a.detected_at or now),
    )[:5]

    verification_rows = (
        await db.execute(select(BreachIncident.verification_status, func.count()).group_by(BreachIncident.verification_status))
    ).all()

    def _sev_line(name: str) -> str:
        return f"- {name}: {active_by_severity.get(name, 0)}"

    def _tbl(rows: list[list[str]]) -> str:
        head = rows[0]
        out = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
        out += ["| " + " | ".join(r) + " |" for r in rows[1:]]
        return "\n".join(out)

    md = [
        "# Executive Report — Threat Intelligence Posture",
        "",
        f"_Generated: {now.strftime('%Y-%m-%d %H:%M UTC')} | Period: last 24 hours for alerts, 7 days for breaches_",
        "",
        "## Posture snapshot",
        "",
        f"- Active alerts: **{sum(active_by_severity.values())}** ({new_alerts_24h} new in last 24h)",
        f"- Known exploited vulnerabilities tracked: **{kev_count}** (ransomware-associated: {kev_ransomware})",
        f"- Critical-severity CVEs tracked: **{critical_cves}**",
        f"- Breach disclosures (7 days): **{breaches_week}**",
        f"- Intel sources: **{sources_total}** enabled, **{sources_failing}** degraded/failing",
        "",
        "## Active alerts by severity",
        "",
        "\n".join(_sev_line(s) for s in ("critical", "high", "medium", "low", "informational")),
        "",
        "## Asset-relevant intelligence",
        "",
        f"**{len(asset_relevant)}** active alerts touch assets in the organization inventory."
        + ("" if asset_relevant else " No active alerts currently match inventoried assets — asset inventory drives this metric."),
        "",
        "## Top active alerts",
        "",
        _tbl([["Severity", "Category", "Alert"]] + [[a.severity, a.category, (a.title or "")[:110]] for a in top_alerts]),
        "",
        "## Breach verification quality",
        "",
        _tbl([["Status", "Count"]] + [[status or "unknown", str(c)] for status, c in verification_rows]),
        "",
        "## Recommended focus",
        "",
    ]
    if asset_relevant:
        md.append("1. Triage asset-matched alerts first — they concern infrastructure you operate.")
    if kev_count:
        md.append("2. Reconcile KEV entries against deployed software; prioritize ransomware-associated CVEs.")
    if sources_failing:
        md.append(f"3. {sources_failing} intel source(s) degraded — coverage may have blind spots until resolved.")
    if breaches_week:
        md.append("4. Review this week's breach disclosures for third-party/supply-chain exposure.")
    if not md[-1].startswith(("1.", "2.", "3.", "4.")):
        md.append("No critical items flagged in this period.")
    md.append("")
    md.append("---")
    md.append("_Deterministic aggregation of platform records; no AI-generated content._")

    return PlainTextResponse("\n".join(md), media_type="text/markdown")
