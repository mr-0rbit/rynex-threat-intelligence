"""Ingestion pipeline: persist normalized CollectedRecords with dedup, alerting,
asset-relevance matching, watchlist correlation and cross-source corroboration.

Enterprise features wired here:
- Asset matching: intel touching owned domains/IPs/products escalates severity
  and names the affected asset in the alert payload.
- Watchlist correlation: orgs/actors/CVEs/domains on analyst watchlists raise
  dedicated `watchlist_mention` alerts.
- Corroboration: the same (value, type) reported by distinct sources re-scores
  IOC confidence deterministically.
- DB alert rules: rows in `alert_rules` override the built-in defaults.
- Live feed: every created alert is published to the WebSocket event bus.
"""

import logging
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AlertRule,
    Asset,
    BreachIncident,
    CollectionJob,
    IOC,
    NewsArticle,
    ThreatActor,
    Vulnerability,
    WatchlistItem,
)
from app.models.alert import Alert
from app.services import events
from app.core.timeutil import ensure_aware
from app.services.alert_engine import AlertEngine, IntelligenceEvent, should_update_existing_alert
from app.services.confidence import ConfidenceBreakdown, score_ioc
from app.services.relevance import match_assets, match_watchlists, severity_for_asset_match

logger = logging.getLogger("rtip.ingest")

EPSS_ALERT_THRESHOLD = 0.5


class IngestionService:
    def __init__(self, db: AsyncSession, alerting: bool = True):
        self.db = db
        self.alerting = alerting
        self.alert_engine = AlertEngine()
        self._assets: list[Asset] = []
        self._watchlist_items: list[WatchlistItem] = []
        self._asset_hit_counts: dict[str, int] = {}  # asset id str -> matched record count
        self._context_loaded = False

    # ---------------- context (loaded lazily, once per batch) ----------------

    async def _load_context(self) -> None:
        if self._context_loaded:
            return
        self._assets = (
            (await self.db.execute(select(Asset).where(Asset.enabled.is_(True)))).scalars().all()
        )
        self._watchlist_items = (await self.db.execute(select(WatchlistItem))).scalars().all()
        rules = (
            (await self.db.execute(select(AlertRule).where(AlertRule.enabled.is_(True))))
            .scalars()
            .all()
        )
        if rules:
            # DB-configured rules are the operator's source of truth; defaults apply
            # only while no rules have been created.
            self.alert_engine = AlertEngine(
                rules=[
                    {
                        "name": r.name,
                        "category": r.category,
                        "min_severity": r.min_severity,
                        "min_confidence": r.min_confidence or 0.0,
                        "enabled": True,
                    }
                    for r in rules
                ]
            )
        self._context_loaded = True

    async def store_result(self, result) -> int:
        await self._load_context()
        stored = 0
        for record in result.records:
            try:
                handlers = {
                    "ioc": self._store_ioc,
                    "vulnerability": self._store_vulnerability,
                    "breach": self._store_breach,
                    "news": self._store_news,
                    "actor": self._store_actor,
                }
                handler = handlers.get(record.kind)
                if handler is None:
                    continue
                if await handler(record):
                    stored += 1
            except Exception:  # noqa: BLE001 — one bad record never blocks the batch
                logger.exception("failed to store record from %s", result.source_slug)
        await self._apply_asset_counters()
        return stored

    async def _apply_asset_counters(self) -> None:
        if not self._asset_hit_counts:
            return
        now = datetime.now(UTC)
        for asset in self._assets:
            count = self._asset_hit_counts.get(str(asset.id))
            if count:
                asset.match_count = (asset.match_count or 0) + count
                asset.last_matched_at = now

    # ---------------- relevance helpers ----------------

    def _note_asset_hits(self, matched: list[dict]) -> None:
        for m in matched:
            key = str(m.get("id") or "")
            if key:
                self._asset_hit_counts[key] = self._asset_hit_counts.get(key, 0) + 1

    @staticmethod
    def _product_text(d: dict) -> str | None:
        parts = [d.get("title") or ""]
        products = d.get("affected_products")
        if isinstance(products, list):
            parts.extend(str(p) for p in products)
        elif isinstance(products, str):
            parts.append(products)
        text = " ".join(parts).strip()
        return text or None

    @staticmethod
    def _host_from_url(url: str | None) -> str | None:
        if not url:
            return None
        try:
            return urlsplit(url).hostname
        except ValueError:
            return None

    async def _raise_watchlist_alert(
        self,
        matches: list[dict],
        *,
        context_title: str,
        source_slug: str,
        source_url: str | None,
        published_at,
        extra_entities: dict | None = None,
    ) -> None:
        """One `watchlist_mention` alert per distinct watchlist value (dedup via fingerprint)."""
        for m in matches:
            value = m.get("value") or ""
            entities = {
                "watchlist_value": value,
                "item_type": m.get("item_type"),
                "matched_via": context_title,
                **(extra_entities or {}),
            }
            await self._raise_alert(
                IntelligenceEvent(
                    category="watchlist_mention",
                    title=f"Watchlist match: {value[:120]}",
                    description=f"Watchlist item '{value}' ({m.get('item_type')}) matched new intelligence: {context_title}",
                    severity="informational",
                    confidence=0.9,
                    source_slug=source_slug,
                    source_url=source_url,
                    published_at=published_at,
                    entities=entities,
                )
            )

    # ---------------- handlers ----------------

    async def _store_ioc(self, record) -> bool:
        d = record.data
        existing = (
            await self.db.execute(
                select(IOC).where(IOC.value == d["value"], IOC.type == d["type"])
            )
        ).scalar_one_or_none()
        if existing:
            existing.reports_count += 1
            new_seen = ensure_aware(d.get("last_seen_at"))
            existing_seen = ensure_aware(existing.last_seen_at)
            if new_seen and (existing_seen is None or new_seen > existing_seen):
                existing.last_seen_at = new_seen
                existing_seen = new_seen
            # Cross-source corroboration: track distinct reporting slugs, re-score.
            sources = list(existing.corroborating_sources or [existing.source_slug])
            slug = d["source_slug"]
            if slug not in sources:
                sources.append(slug)
                existing.corroborating_sources = sources
                cb: ConfidenceBreakdown = score_ioc(
                    source_credibility=float(d.get("source_credibility") or 0.85),
                    corroborating_sources=len(sources),
                    first_seen=ensure_aware(existing.first_seen_at),
                    last_seen=existing_seen,
                )
                existing.confidence = cb.score
                existing.confidence_reasons = {"reasons": cb.reasons}
            return False

        ioc = IOC(
            value=d["value"],
            type=d["type"],
            source_slug=d["source_slug"],
            source_url=d.get("source_url"),
            confidence=0.0,
            confidence_reasons={"reasons": []},
            source_reputation=d.get("source_reputation"),
            malware_family=d.get("malware_family"),
            tags=d.get("tags"),
            first_seen_at=d.get("first_seen_at"),
            last_seen_at=d.get("last_seen_at") or datetime.now(UTC),
            corroborating_sources=[d["source_slug"]],
            description=d.get("description"),
        )
        cb = score_ioc(
            source_credibility=float(d.get("source_credibility") or 0.85),
            corroborating_sources=1,
            last_seen=ioc.last_seen_at,
            first_seen=ioc.first_seen_at,
        )
        ioc.confidence = cb.score
        ioc.confidence_reasons = {"reasons": cb.reasons}
        self.db.add(ioc)

        # Asset relevance: does this indicator touch our own surface?
        domains = [ioc.value] if ioc.type == "domain" else ([self._host_from_url(ioc.value)] if ioc.type == "url" else [])
        ips = [ioc.value] if ioc.type in ("ipv4", "ipv6") else []
        matched_assets = match_assets(self._assets, domains=[x for x in domains if x], ips=ips)
        self._note_asset_hits(matched_assets)
        watch_matches = match_watchlists(
            self._watchlist_items,
            domain=domains[0] if domains else None,
            text=ioc.description,
        )

        # Alerting for high-value network indicators (severity escalates with asset matches)
        if ioc.type in ("ipv4", "ipv6") and ioc.confidence >= 0.5:
            base_sev = severity_for_asset_match("medium", matched_assets)
            await self._raise_alert(
                IntelligenceEvent(
                    category="malicious_ip",
                    title=f"Malicious IP observed: {ioc.value}",
                    description=ioc.description or "Indicator reported by threat intelligence feed",
                    severity=base_sev,
                    confidence=ioc.confidence,
                    source_slug=ioc.source_slug,
                    source_url=ioc.source_url,
                    published_at=ioc.last_seen_at,
                    entities={
                        "ips": [ioc.value],
                        "matched_assets": matched_assets,
                        "watchlist_matches": watch_matches,
                    },
                )
            )
        elif ioc.type in ("domain", "url"):
            label = "URL" if ioc.type == "url" else "domain"
            base_sev = severity_for_asset_match("medium", matched_assets)
            await self._raise_alert(
                IntelligenceEvent(
                    category="malicious_domain_url",
                    title=f"Malicious {label} observed: {ioc.value[:120]}",
                    description=ioc.description or "Indicator reported by threat intelligence feed",
                    severity=base_sev,
                    confidence=ioc.confidence,
                    source_slug=ioc.source_slug,
                    source_url=ioc.source_url,
                    published_at=ioc.last_seen_at,
                    entities={
                        "urls" if ioc.type == "url" else "domains": [ioc.value],
                        "matched_assets": matched_assets,
                        "watchlist_matches": watch_matches,
                    },
                )
            )
        if watch_matches:
            await self._raise_watchlist_alert(
                watch_matches,
                context_title=f"{ioc.type}:{ioc.value}",
                source_slug=ioc.source_slug,
                source_url=ioc.source_url,
                published_at=ioc.last_seen_at,
            )
        return True

    async def _store_vulnerability(self, record) -> bool:
        d = record.data
        # Enrichment-only records (e.g. EPSS bulk feed) update existing rows and
        # never insert 250k bare CVEs into the vulnerability table.
        if d.get("enrichment_only"):
            existing = (
                await self.db.execute(select(Vulnerability).where(Vulnerability.cve_id == d["cve_id"]))
            ).scalar_one_or_none()
            if existing:
                changed = False
                if d.get("epss_score") is not None:
                    existing.epss_score = d["epss_score"]
                    changed = True
                if changed:
                    await self._raise_epss_alert(existing)
                return False
            return False

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

        matched_assets = match_assets(
            self._assets, product_text=self._product_text(d)
        )
        self._note_asset_hits(matched_assets)
        watch_matches = match_watchlists(
            self._watchlist_items,
            cves=[vuln.cve_id],
            text=" ".join(x for x in (vuln.title, vuln.description) if x),
        )

        if vuln.in_kev:
            sev = "high"
            if (vuln.cvss_base_score or 0) >= 9 or vuln.kev_known_ransomware_use:
                sev = "critical"
            sev = severity_for_asset_match(sev, matched_assets)
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
                    entities={
                        "cves": [vuln.cve_id],
                        "matched_assets": matched_assets,
                        "watchlist_matches": watch_matches,
                    },
                )
            )
        elif (vuln.cvss_base_score or 0) >= 9.0:
            sev = severity_for_asset_match("critical", matched_assets)
            await self._raise_alert(
                IntelligenceEvent(
                    category="critical_vulnerability",
                    title=f"Critical vulnerability published: {vuln.cve_id}",
                    description=vuln.description or f"CVSS {vuln.cvss_base_score}",
                    severity=sev,
                    confidence=0.8,
                    source_slug=vuln.source_slug,
                    source_url=vuln.source_url,
                    published_at=vuln.published_at,
                    entities={
                        "cves": [vuln.cve_id],
                        "matched_assets": matched_assets,
                        "watchlist_matches": watch_matches,
                    },
                )
            )
        await self._raise_epss_alert(vuln)
        if watch_matches:
            await self._raise_watchlist_alert(
                watch_matches,
                context_title=vuln.cve_id,
                source_slug=vuln.source_slug,
                source_url=vuln.source_url,
                published_at=vuln.published_at,
            )
        return True

    async def _raise_epss_alert(self, vuln) -> None:
        """EPSS >= threshold on a tracked CVE means high exploitation probability."""
        if (vuln.epss_score or 0) >= EPSS_ALERT_THRESHOLD:
            await self._raise_alert(
                IntelligenceEvent(
                    category="high_epss_vulnerability",
                    title=f"High exploitation probability: {vuln.cve_id} (EPSS {vuln.epss_score:.2f})",
                    description=vuln.description
                    or "EPSS probability of exploitation within 30 days exceeded threshold",
                    severity="high",
                    confidence=min(1.0, vuln.epss_score),
                    source_slug=getattr(vuln, "source_slug", "epss") or "epss",
                    source_url=getattr(vuln, "source_url", None),
                    published_at=datetime.now(UTC),
                    entities={"cves": [vuln.cve_id], "epss": vuln.epss_score},
                )
            )

    async def _store_breach(self, record) -> bool:
        d = record.data
        existing = (
            await self.db.execute(select(BreachIncident).where(BreachIncident.fingerprint == d["fingerprint"]))
        ).scalar_one_or_none()
        if existing:
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

        matched_assets = match_assets(
            self._assets,
            domains=[breach.organization_domain] if breach.organization_domain else [],
            org_name=breach.organization_name,
        )
        self._note_asset_hits(matched_assets)
        watch_matches = match_watchlists(
            self._watchlist_items,
            org_name=breach.organization_name,
            domain=breach.organization_domain,
            actor=breach.threat_actor_name,
            text=breach.summary,
        )

        category = "ransomware_victim" if breach.threat_actor_name else "data_breach_disclosure"
        sev = severity_for_asset_match("high", matched_assets)
        await self._raise_alert(
            IntelligenceEvent(
                category=category,
                title=(
                    f"Ransomware claim: {breach.threat_actor_name} lists {breach.organization_name}"
                    if breach.threat_actor_name
                    else f"Data breach disclosure: {breach.organization_name}"
                ),
                description=breach.summary or f"Reported by {breach.source_slug}; verification status: {breach.verification_status}",
                severity=sev,
                confidence=breach.confidence,
                source_slug=breach.source_slug,
                source_url=breach.source_url,
                published_at=breach.published_at,
                entities={
                    "org": breach.organization_name,
                    "actor": breach.threat_actor_name,
                    "domain": breach.organization_domain,
                    "matched_assets": matched_assets,
                    "watchlist_matches": watch_matches,
                },
            )
        )
        if watch_matches:
            await self._raise_watchlist_alert(
                watch_matches,
                context_title=f"breach: {breach.organization_name}",
                source_slug=breach.source_slug,
                source_url=breach.source_url,
                published_at=breach.published_at,
            )
        return True

    async def _store_actor(self, record) -> bool:
        d = record.data
        existing = (
            await self.db.execute(select(ThreatActor).where(ThreatActor.name == d["name"]))
        ).scalar_one_or_none()
        if existing:
            if d.get("description") and not existing.description:
                existing.description = d["description"]
            return False
        actor = ThreatActor(
            name=d["name"],
            aliases=d.get("aliases"),
            motivations=d.get("motivations"),
            targeted_industries=d.get("targeted_industries"),
            targeted_regions=d.get("targeted_regions"),
            associated_malware=d.get("associated_malware"),
            attack_techniques=d.get("attack_techniques"),
            first_observed_at=d.get("_first_seen"),
            last_observed_at=d.get("_last_seen"),
            description=d.get("description"),
            attribution_status=d.get("attribution_status", "unverified"),
            source_slug=d.get("source_slug"),
            source_url=d.get("source_url"),
        )
        self.db.add(actor)
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
        await self.db.flush()

        # Live WebSocket feed (single-worker). Multi-worker deployments need a
        # Redis pub/sub bridge — see docs/ARCHITECTURE.md.
        try:
            events.publish_alert(
                {
                    "id": str(alert.id),
                    "title": alert.title,
                    "category": alert.category,
                    "severity": alert.severity,
                    "confidence": alert.confidence,
                    "detected_at": alert.detected_at.isoformat() if alert.detected_at else None,
                    "entities": alert.affected_entities,
                }
            )
        except Exception:  # noqa: BLE001
            logger.exception("websocket publish failed for alert %s", alert.id)

        # Fire-and-forget notifications; delivery never blocks ingestion
        from app.services import notifications

        if notifications.configured_channels():
            try:
                delivered = await notifications.dispatch_alert(alert)
                alert.notified_channels = delivered
            except Exception:  # noqa: BLE001
                logger.exception("notification dispatch failed for alert %s", alert.id)

    @staticmethod
    def _recommended_action(candidate) -> str:
        actions = {
            "new_kev_entry": "Verify whether affected software is deployed in your environment; apply vendor patches. CISA federal deadline applies to federal agencies.",
            "critical_vulnerability": "Review affected product usage, apply mitigations and monitor for exploitation.",
            "high_epss_vulnerability": "Prioritize patching: exploitation probability is high. Check exposure of the affected product in your environment.",
            "ransomware_victim": "Treat as an unverified claim; check for corroboration, assess supply-chain exposure to the named victim.",
            "data_breach_disclosure": "Verify disclosure; if related to your organization or partners, activate incident response review.",
            "malicious_ip": "Review perimeter logs for the indicator; consider blocking with allowlist checks first.",
            "malicious_domain_url": "Check DNS/proxy logs for the indicator; block at egress controls where appropriate.",
            "watchlist_mention": "Review the matched intelligence against the watchlist item; escalate to incident response if relevant.",
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
