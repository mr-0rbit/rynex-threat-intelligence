"""Correlation Engine: Cross-source entity correlation & timeline generation.

Scans intelligence tables (IOCs, breach incidents, vulnerabilities, alerts) and builds or
updates deterministic `CorrelationEvent` records whenever distinct sources report the same
entity (IP, domain, CVE, threat actor, organization).
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.timeutil import ensure_aware
from app.models import (
    Alert,
    BreachIncident,
    CorrelationEvent,
    Investigation,
    InvestigationTimeline,
    IOC,
    Vulnerability,
)

logger = logging.getLogger("rtip.correlation")

MAX_ENTITY_KEY_LENGTH = 255


def _timeline_key(
    event_type: str, entity_key: str | None, occurred_at: datetime
) -> tuple[str, str | None, str]:
    """Stable identity for a timeline entry so regeneration is idempotent."""
    normalized = ensure_aware(occurred_at)
    return (event_type, entity_key, normalized.isoformat() if normalized else "")


def _parse_timestamp(value: str) -> datetime | None:
    return ensure_aware(datetime.fromisoformat(value))


class CorrelationEngine:
    def __init__(self, db: AsyncSession, organization_id: uuid.UUID):
        self.db = db
        self.org_id = organization_id

    async def correlate_entity(
        self, entity_key: str, entity_type: str, *, commit: bool = True
    ) -> CorrelationEvent | None:
        """Find all intel records related to an entity key and update/create correlation event.

        Set ``commit=False`` when the caller wants to batch several correlations
        into a single transaction (see :meth:`generate_investigation_timeline`).
        """
        entity_key_lower = entity_key.lower().strip()
        if not entity_key_lower:
            return None
        if len(entity_key_lower) > MAX_ENTITY_KEY_LENGTH:
            logger.warning(
                "skipping correlation for entity key longer than %d characters",
                MAX_ENTITY_KEY_LENGTH,
            )
            return None

        sources: set[str] = set()
        alert_ids: list[str] = []
        breach_ids: list[str] = []
        cve_ids: list[str] = []
        timeline_events: list[dict[str, Any]] = []

        # 1. IOC matches
        iocs = (
            (
                await self.db.execute(
                    select(IOC).where(IOC.value == entity_key_lower)
                )
            )
            .scalars()
            .all()
        )
        for ioc in iocs:
            sources.add(ioc.source_slug)
            if ioc.corroborating_sources:
                sources.update(ioc.corroborating_sources)
            timeline_events.append({
                "timestamp": ioc.last_seen_at.isoformat() if ioc.last_seen_at else ioc.created_at.isoformat(),
                "type": "ioc_detected",
                "source": ioc.source_slug,
                "summary": f"IOC {ioc.type}:{ioc.value} recorded with confidence {ioc.confidence:.2f}",
                "id": str(ioc.id),
            })

        # 2. Vulnerability / CVE matches
        if entity_type == "cve" or entity_key_lower.startswith("cve-"):
            vuln = (
                await self.db.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == entity_key_lower.upper())
                )
            ).scalar_one_or_none()
            if vuln:
                cve_ids.append(vuln.cve_id)
                sources.add(vuln.source_slug)
                if vuln.in_kev:
                    sources.add("cisa-kev")
                timeline_events.append({
                    "timestamp": vuln.published_at.isoformat() if vuln.published_at else vuln.created_at.isoformat(),
                    "type": "vulnerability_published",
                    "source": vuln.source_slug,
                    "summary": f"Vulnerability {vuln.cve_id} (CVSS: {vuln.cvss_base_score or 'N/A'}, EPSS: {vuln.epss_score or 'N/A'})",
                    "id": str(vuln.id),
                })

        # 3. Breach matches
        breaches = (
            (
                await self.db.execute(
                    select(BreachIncident).where(
                        or_(
                            BreachIncident.organization_name.ilike(f"%{entity_key_lower}%"),
                            BreachIncident.organization_domain == entity_key_lower,
                            BreachIncident.threat_actor_name == entity_key_lower,
                        )
                    )
                )
            )
            .scalars()
            .all()
        )
        for breach in breaches:
            breach_ids.append(str(breach.id))
            sources.add(breach.source_slug)
            timeline_events.append({
                "timestamp": breach.published_at.isoformat() if breach.published_at else breach.created_at.isoformat(),
                "type": "breach_reported",
                "source": breach.source_slug,
                "summary": f"Breach claimed against {breach.organization_name} by {breach.threat_actor_name or 'unknown actor'}",
                "id": str(breach.id),
            })

        # 4. Related alerts
        alerts = (
            (
                await self.db.execute(
                    select(Alert).where(
                        Alert.organization_id == self.org_id,
                        Alert.title.ilike(f"%{entity_key_lower}%"),
                    )
                )
            )
            .scalars()
            .all()
        )
        for alert in alerts:
            alert_ids.append(str(alert.id))
            if alert.evidence_sources:
                for src in alert.evidence_sources:
                    if isinstance(src, dict) and "source_slug" in src:
                        sources.add(src["source_slug"])
            timeline_events.append({
                "timestamp": alert.detected_at.isoformat() if alert.detected_at else alert.created_at.isoformat(),
                "type": "alert_triggered",
                "source": "rtip_alert_engine",
                "summary": f"Alert [{alert.severity.upper()}] {alert.title}",
                "id": str(alert.id),
            })

        if not sources and not timeline_events:
            return None

        # Sort chronologically. SQLite returns naive datetimes and PostgreSQL
        # returns aware ones, so normalize before comparing.
        timeline_events.sort(
            key=lambda event: _parse_timestamp(event["timestamp"]) or datetime.now(UTC)
        )
        if timeline_events:
            first_seen = _parse_timestamp(timeline_events[0]["timestamp"]) or datetime.now(UTC)
            last_seen = _parse_timestamp(timeline_events[-1]["timestamp"]) or datetime.now(UTC)
        else:
            first_seen = last_seen = datetime.now(UTC)

        source_count = len(sources)

        # Confidence formula: base score proportional to source count & evidence depth
        # 1 source = 0.4, 2 = 0.65, 3 = 0.8, 4+ = 0.95
        confidence = min(0.95, 0.4 + (source_count - 1) * 0.25) if source_count > 0 else 0.2
        correlation_type = "same_entity" if source_count > 1 else "single_source"

        # Upsert CorrelationEvent
        existing = (
            await self.db.execute(
                select(CorrelationEvent).where(
                    CorrelationEvent.organization_id == self.org_id,
                    CorrelationEvent.entity_key == entity_key_lower,
                    CorrelationEvent.entity_type == entity_type,
                )
            )
        ).scalar_one_or_none()

        if existing:
            existing.correlation_type = correlation_type
            existing.confidence = confidence
            existing.source_count = source_count
            existing.sources = sorted(sources)
            existing.related_alert_ids = alert_ids
            existing.related_breach_ids = breach_ids
            existing.related_cve_ids = cve_ids
            existing.first_seen_at = first_seen
            existing.last_seen_at = last_seen
            existing.timeline = timeline_events
            event = existing
        else:
            event = CorrelationEvent(
                organization_id=self.org_id,
                entity_key=entity_key_lower,
                entity_type=entity_type,
                correlation_type=correlation_type,
                confidence=confidence,
                source_count=source_count,
                sources=sorted(sources),
                related_alert_ids=alert_ids,
                related_breach_ids=breach_ids,
                related_cve_ids=cve_ids,
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                timeline=timeline_events,
            )
            self.db.add(event)

        await self.db.flush()
        if commit:
            await self.db.commit()
            await self.db.refresh(event)
        return event

    async def generate_investigation_timeline(
        self, investigation_id: uuid.UUID
    ) -> list[InvestigationTimeline]:
        """Auto-populate an investigation's timeline based on its entity_refs.

        Generation is idempotent: entries already materialized for this
        investigation are skipped, so an analyst can re-run it after new
        intelligence arrives without duplicating history.
        """
        inv = await self.db.get(Investigation, investigation_id)
        if inv is None or inv.organization_id != self.org_id:
            return []

        existing_keys = {
            _timeline_key(row.event_type, row.entity_key, row.occurred_at)
            for row in (
                await self.db.execute(
                    select(InvestigationTimeline).where(
                        InvestigationTimeline.investigation_id == investigation_id
                    )
                )
            )
            .scalars()
            .all()
        }

        new_entries: list[InvestigationTimeline] = []

        for entity_type, keys in (inv.entity_refs or {}).items():
            if not isinstance(keys, list):
                continue
            for key in keys:
                corr = await self.correlate_entity(str(key), entity_type, commit=False)
                if not corr or not corr.timeline:
                    continue
                for item in corr.timeline:
                    occurred_at = _parse_timestamp(item["timestamp"])
                    if occurred_at is None:
                        continue
                    event_type = str(item.get("type", "intel_event"))[:64]
                    entry_key = _timeline_key(event_type, corr.entity_key, occurred_at)
                    if entry_key in existing_keys:
                        continue
                    existing_keys.add(entry_key)
                    entry = InvestigationTimeline(
                        organization_id=self.org_id,
                        investigation_id=investigation_id,
                        event_type=event_type,
                        entity_key=corr.entity_key,
                        entity_type=corr.entity_type[:32],
                        title=(item.get("summary") or f"Event related to {key}")[:512],
                        detail=(
                            f"Source: {item.get('source', 'unknown')} — "
                            f"Correlation Confidence: {corr.confidence:.2f}"
                        ),
                        evidence_refs=[{"source": item.get("source"), "ref_id": item.get("id")}],
                        occurred_at=occurred_at,
                    )
                    self.db.add(entry)
                    new_entries.append(entry)

        await self.db.commit()
        return new_entries
