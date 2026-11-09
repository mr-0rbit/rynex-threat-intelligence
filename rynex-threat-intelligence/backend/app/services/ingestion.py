"""Ingestion pipeline: persist normalized CollectedRecords with dedup + alerting."""

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import BreachIncident, CollectionJob, IntelligenceSource, IOC, NewsArticle, Vulnerability
from app.models.alert import Alert
from app.services.alert_engine import AlertEngine, IntelligenceEvent, should_update_existing_alert
from app.services.confidence import ConfidenceBreakdown, score_ioc

logger = logging.getLogger("rtip.ingest")


class IngestionService:
    def __init__(self, db: AsyncSession, alerting: bool = True):
        self.db = db
        self.alerting = alerting
        self.alert_engine = AlertEngine()

    async def store_result(self, result) -> int:
        stored = 0
        for record in result.records:
            try:
                handlers = {
                    "ioc": self._store_ioc,
                    "vulnerability": self._store_vulnerability,
                    "breach": self._store_breach,
                    "news": self._store_news,
                }
                handler = handlers.get(record.kind)
                if handler is None:
                    continue
                if await handler(record):
                    stored += 1
            except Exception:  # noqa: BLE001 — one bad record never blocks the batch
                logger.exception("failed to store record from %s", result.source_slug)
        return stored

    async def _store_ioc(self, record) -> bool:
        d = record.data
        existing = (
            await self.db.execute(
                select(IOC).where(IOC.value == d["value"], IOC.type == d["type"])
            )
        ).scalar_one_or_none()
        if existing:
            existing.reports_count += 1
            if d.get("last_seen_at") and (existing.last_seen_at is None or d["last_seen_at"] > existing.last_seen_at):
                existing.last_seen_at = d["last_seen_at"]
            return False
        cb: ConfidenceBreakdown = score_ioc(
            source_credibility=0.85,
            corroborating_sources=1,
            last_seen=d.get("last_seen_at"),
            first_seen=d.get("first_seen_at"),
        )
        ioc = IOC(
            value=d["value"],
            type=d["type"],
            source_slug=d["source_slug"],
            source_url=d.get("source_url"),
            confidence=cb.score,
            confidence_reasons={"reasons": cb.reasons},
            source_reputation=d.get("source_reputation"),
            malware_family=d.get("malware_family"),
            tags=d.get("tags"),
            first_seen_at=d.get("first_seen_at"),
            last_seen_at=d.get("last_seen_at") or datetime.now(UTC),
            description=d.get("description"),
        )
        self.db.add(ioc)
        # Alerting for high-value network indicators
        if ioc.type in ("ipv4", "ipv6") and ioc.confidence >= 0.5:
            await self._raise_alert(
                IntelligenceEvent(
                    category="malicious_ip",
                    title=f"Malicious IP observed: {ioc.value}",
                    description=ioc.description or "Indicator reported by threat intelligence feed",
                    severity="medium",
                    confidence=ioc.confidence,
                    source_slug=ioc.source_slug,
                    source_url=ioc.source_url,
                    published_at=ioc.last_seen_at,
                    entities={"ips": [ioc.value]},
                )
            )
        elif ioc.type in ("domain", "url"):
            await self._raise_alert(
                IntelligenceEvent(
                    category="malicious_domain_url",
                    title=f"Malicious {'URL' if ioc.type == 'url' else 'domain'} observed: {ioc.value[:120]}",
                    description=ioc.description or "Indicator reported by threat intelligence feed",
                    severity="medium",
                    confidence=ioc.confidence,
                    source_slug=ioc.source_slug,
                    source_url=ioc.source_url,
                    published_at=ioc.last_seen_at,
                    entities={"urls" if ioc.type == "url" else "domains": [ioc.value]},
                )
            )
        return True

    async def _store_vulnerability(self, record) -> bool:
        d = record.data
        existing = (
            await self.db.execute(select(Vulnerability).where(Vulnerability.cve_id == d["cve_id"]))
        ).scalar_one_or_none()
        if existing:
            # Enrich, never downgrade KEV status
            if d.get("in_kev") and not existing.in_kev:
                existing.in_kev = True
                existing.kev_date_added = d.get("kev_date_added")
                existing.kev_due_date = d.get("kev_due_date")
                existing.kev_known_ransomware_use = d.get("kev_known_ransomware_use")
            if d.get("epss_score") is not None:
                existing.epss_score = d["epss_score"]
            return False
        vuln = Vulnerability(
            cve_id=d["cve_id"],
            title=d.get("title"),
            description=d.get("description"),
            cvss_base_score=d.get("cvss_base_score"),
            cvss_vector=d.get("cvss_vector"),
            severity=d.get("severity"),
            in_kev=d.get("in_kev", False),
            kev_date_added=d.get("kev_date_added"),
            kev_due_date=d.get("kev_due_date"),
            kev_known_ransomware_use=d.get("kev_known_ransomware_use"),
            affected_products=d.get("affected_products"),
            references=d.get("references"),
            cwes=d.get("cwes"),
            published_at=d.get("published_at"),
            modified_at=d.get("modified_at"),
            source_slug=d.get("source_slug", "unknown"),
            source_url=d.get("source_url"),
        )
        self.db.add(vuln)
        if vuln.in_kev:
            sev = "high"
            if (vuln.cvss_base_score or 0) >= 9 or vuln.kev_known_ransomware_use:
                sev = "critical"
            await self._raise_alert(
                IntelligenceEvent(
                    category="new_kev_entry",
                    title=f"Actively exploited vulnerability added to CISA KEV: {vuln.cve_id}",
                    description=vuln.description or f"{vuln.title} — known exploited per CISA",
                    severity=sev,
                    confidence=0.95,
                    source_slug=vuln.source_slug,
                    source_url=vuln.source_url,
                    published_at=vuln.kev_date_added,
                    entities={"cves": [vuln.cve_id]},
                )
            )
        elif (vuln.cvss_base_score or 0) >= 9.0:
            await self._raise_alert(
                IntelligenceEvent(
                    category="critical_vulnerability",
                    title=f"Critical vulnerability published: {vuln.cve_id}",
                    description=vuln.description or f"CVSS {vuln.cvss_base_score}",
                    severity="critical",
                    confidence=0.8,
                    source_slug=vuln.source_slug,
                    source_url=vuln.source_url,
                    published_at=vuln.published_at,
                    entities={"cves": [vuln.cve_id]},
                )
            )
        return True

    async def _store_breach(self, record) -> bool:
        d = record.data
        existing = (
            await self.db.execute(select(BreachIncident).where(BreachIncident.fingerprint == d["fingerprint"]))
        ).scalar_one_or_none()
        if existing:
            existing.last_intel_update = datetime.now(UTC) if hasattr(existing, "last_intel_update") else None
            return False
        breach = BreachIncident(
            fingerprint=d["fingerprint"],
            organization_name=d["organization_name"],
            organization_domain=d.get("organization_domain"),
            industry=d.get("industry"),
            country=d.get("country"),
            region=d.get("region"),
            reported_date=d.get("reported_date"),
            published_at=d.get("published_at"),
            detection_date=d.get("detection_date"),
            threat_actor_name=d.get("threat_actor_name"),
            claimed_data_types=d.get("claimed_data_types"),
            record_count=d.get("record_count"),
            record_count_reliability=d.get("record_count_reliability"),
            summary=d.get("summary"),
            source_slug=d["source_slug"],
            source_url=d.get("source_url"),
            evidence_references=d.get("evidence_references"),
            verification_status=d.get("verification_status", "unverified"),
            confidence=d.get("confidence", 0.4),
            confidence_reasons=d.get("confidence_reasons"),
        )
        self.db.add(breach)
        category = "ransomware_victim" if breach.threat_actor_name else "data_breach_disclosure"
        await self._raise_alert(
            IntelligenceEvent(
                category=category,
                title=(
                    f"Ransomware claim: {breach.threat_actor_name} lists {breach.organization_name}"
                    if breach.threat_actor_name
                    else f"Data breach disclosure: {breach.organization_name}"
                ),
                description=breach.summary or f"Reported by {breach.source_slug}; verification status: {breach.verification_status}",
                severity="high",
                confidence=breach.confidence,
                source_slug=breach.source_slug,
                source_url=breach.source_url,
                published_at=breach.published_at,
                entities={
                    "org": breach.organization_name,
                    "actor": breach.threat_actor_name,
                    "domain": breach.organization_domain,
                },
            )
        )
        return True

    async def _store_news(self, record) -> bool:
        d = record.data
        existing = (
            await self.db.execute(select(NewsArticle).where(NewsArticle.url_hash == d["url_hash"]))
        ).scalar_one_or_none()
        if existing:
            return False
        article = NewsArticle(
            url_hash=d["url_hash"],
            url=d["url"],
            headline=d["headline"],
            summary=d.get("summary"),
            publisher=d["publisher"],
            author=d.get("author"),
            published_at=d.get("published_at"),
            collected_at=datetime.now(UTC),
            categories=d.get("categories"),
            entities=d.get("entities"),
            source_slug=d["source_slug"],
        )
        self.db.add(article)
        return True

    async def _raise_alert(self, event: IntelligenceEvent) -> None:
        if not self.alerting:
            return  # baseline run: ingest history without flooding alerts
        candidate = self.alert_engine.evaluate(event)
        if candidate is None:
            return
        existing = (
            await self.db.execute(select(Alert).where(Alert.fingerprint == candidate.fingerprint))
        ).scalars().first()
        if existing:
            if should_update_existing_alert(existing.evidence_hash, candidate.evidence_hash):
                existing.occurrence_count += 1
                existing.last_evidence_at = datetime.now(UTC)
                existing.evidence_hash = candidate.evidence_hash
                existing.evidence_sources = (existing.evidence_sources or []) + [
                    {"source_slug": candidate.source_slug, "url": candidate.source_url}
                ]
            return
        alert = Alert(
            fingerprint=candidate.fingerprint,
            evidence_hash=candidate.evidence_hash,
            title=candidate.title,
            description=candidate.description,
            category=candidate.category,
            severity=candidate.severity,
            confidence=candidate.confidence,
            affected_entities=candidate.entities,
            evidence_sources=[{"source_slug": candidate.source_slug, "url": candidate.source_url}],
            detected_at=candidate.detected_at,
            first_published_at=candidate.published_at,
            last_evidence_at=candidate.detected_at,
            status="new",
            recommended_action=self._recommended_action(candidate),
        )
        self.db.add(alert)

    @staticmethod
    def _recommended_action(candidate) -> str:
        actions = {
            "new_kev_entry": "Verify whether affected software is deployed in your environment; apply vendor patches. CISA federal deadline applies to federal agencies.",
            "critical_vulnerability": "Review affected product usage, apply mitigations and monitor for exploitation.",
            "ransomware_victim": "Treat as an unverified claim; check for corroboration, assess supply-chain exposure to the named victim.",
            "data_breach_disclosure": "Verify disclosure; if related to your organization or partners, activate incident response review.",
            "malicious_ip": "Review perimeter logs for the indicator; consider blocking with allowlist checks first.",
            "malicious_domain_url": "Check DNS/proxy logs for the indicator; block at egress controls where appropriate.",
        }
        return actions.get(candidate.category, "Triage the alert and gather corroborating evidence.")


async def run_collector(slug: str, db: AsyncSession, trigger: str = "scheduled") -> dict:
    """Run one collector and ingest its results. Used by Celery tasks and API trigger."""
    from app.collectors.registry import get_connector

    connector = get_connector(slug)
    if connector is None:
        raise ValueError(f"unknown collector: {slug}")
    # Baseline runs (first successful collection from a source) ingest history
    # without generating alerts; alerting starts from the second run onward.
    from sqlalchemy import select

    prior_success = (
        await db.execute(
            select(CollectionJob.id)
            .where(CollectionJob.source_slug == slug, CollectionJob.status == "success")
            .limit(1)
        )
    ).scalar_one_or_none()
    is_baseline = prior_success is None

    result = await connector.run(db, trigger=trigger)
    stored = await IngestionService(db, alerting=not is_baseline).store_result(result)
    await db.commit()
    logger.info(
        "collection run complete",
        extra={"source_id": slug, "records": stored, "error": "; ".join(result.errors) or None},
    )
    return {
        "source": slug,
        "received": len(result.records),
        "stored": stored,
        "baseline": is_baseline,
        "errors": result.errors,
    }
