"""Intelligence domain models: IOCs, vulnerabilities, breaches, news, threat actors.

Provenance rule: every intelligence record keeps its original source reference
(source_slug + external URL + publication timestamp) so evidence is traceable.
"""

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class IOC(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "iocs"
    __table_args__ = (
        Index("ix_iocs_value_type", "value", "type"),
        Index("ix_iocs_last_seen", "last_seen_at"),
    )

    # Normalized canonical value; uniqueness enforced per (value, type)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)  # ipv4|ipv6|domain|url|md5|sha1|sha256|email
    source_slug: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024))
    external_id: Mapped[str | None] = mapped_column(String(255))

    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)  # platform score 0..1
    confidence_reasons: Mapped[dict | None] = mapped_column(JSON)
    source_reputation: Mapped[str | None] = mapped_column(String(255))  # provider's own label, kept separate

    malware_family: Mapped[str | None] = mapped_column(String(255), index=True)
    threat_actor_name: Mapped[str | None] = mapped_column(String(255), index=True)
    tags: Mapped[list | None] = mapped_column(JSON)

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reports_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Cross-source corroboration: ordered list of distinct source slugs that
    # reported this exact (value, type). Drives the confidence re-score.
    corroborating_sources: Mapped[list | None] = mapped_column(JSON)

    description: Mapped[str | None] = mapped_column(Text)


class Vulnerability(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)

    cvss_base_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    cvss_version: Mapped[str | None] = mapped_column(String(16))
    severity: Mapped[str | None] = mapped_column(String(16), index=True)  # critical|high|medium|low|none

    epss_score: Mapped[float | None] = mapped_column(Float)  # 0..1 probability
    epss_percentile: Mapped[float | None] = mapped_column(Float)

    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_known_ransomware_use: Mapped[bool | None] = mapped_column(Boolean)

    affected_products: Mapped[list | None] = mapped_column(JSON)
    references: Mapped[list | None] = mapped_column(JSON)
    cwes: Mapped[list | None] = mapped_column(JSON)

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    source_slug: Mapped[str] = mapped_column(String(64), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024))


class BreachIncident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "breach_incidents"

    # Deduplication fingerprint (normalized org + event key)
    fingerprint: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)

    organization_name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    organization_domain: Mapped[str | None] = mapped_column(String(255), index=True)
    industry: Mapped[str | None] = mapped_column(String(128), index=True)
    country: Mapped[str | None] = mapped_column(String(128), index=True)
    region: Mapped[str | None] = mapped_column(String(64), index=True)

    reported_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    detection_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    threat_actor_name: Mapped[str | None] = mapped_column(String(255), index=True)
    claimed_data_types: Mapped[list | None] = mapped_column(JSON)
    record_count: Mapped[int | None] = mapped_column(Integer)
    record_count_reliability: Mapped[str | None] = mapped_column(String(32))  # sourced|estimated|unknown

    summary: Mapped[str | None] = mapped_column(Text)
    source_slug: Mapped[str] = mapped_column(String(64), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=False)
    evidence_references: Mapped[list | None] = mapped_column(JSON)

    # confirmed|reported|claimed|unverified|disputed  — never auto-promote to confirmed
    verification_status: Mapped[str] = mapped_column(String(32), default="unverified", nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.4, nullable=False)
    confidence_reasons: Mapped[dict | None] = mapped_column(JSON)


class NewsArticle(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "news_articles"

    url_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    headline: Mapped[str] = mapped_column(String(1024), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    publisher: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    author: Mapped[str | None] = mapped_column(String(255))

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    categories: Mapped[list | None] = mapped_column(JSON)
    entities: Mapped[list | None] = mapped_column(JSON)  # orgs, actors, CVEs, malware mentioned
    source_slug: Mapped[str] = mapped_column(String(64), nullable=False)


class ThreatActor(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "threat_actors"

    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    aliases: Mapped[list | None] = mapped_column(JSON)
    motivations: Mapped[list | None] = mapped_column(JSON)
    targeted_industries: Mapped[list | None] = mapped_column(JSON)
    targeted_regions: Mapped[list | None] = mapped_column(JSON)
    associated_malware: Mapped[list | None] = mapped_column(JSON)
    attack_techniques: Mapped[list | None] = mapped_column(JSON)  # MITRE ATT&CK IDs
    first_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    description: Mapped[str | None] = mapped_column(Text)
    attribution_status: Mapped[str] = mapped_column(String(32), default="unverified", nullable=False)
    source_slug: Mapped[str | None] = mapped_column(String(64))
    source_url: Mapped[str | None] = mapped_column(String(1024))


class Investigation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "investigations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    severity: Mapped[str | None] = mapped_column(String(16))
    summary: Mapped[str | None] = mapped_column(Text)
    entity_refs: Mapped[dict | None] = mapped_column(JSON)  # {"iocs": [...], "cves": [...], ...}
    analyst_notes: Mapped[list | None] = mapped_column(JSON)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    confidence: Mapped[float | None] = mapped_column(Float)
    confidence_reasons: Mapped[dict | None] = mapped_column(JSON)


class CorrelationEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Cross-source entity correlation.

    One row per (organization, entity_key, entity_type) — the canonical record
    that the same real-world entity is reported by multiple sources.
    """

    __tablename__ = "correlation_events"
    __table_args__ = (
        Index("ix_correlation_events_org_entity", "organization_id", "entity_key"),
        Index(
            "ix_correlation_events_org_type",
            "organization_id",
            "entity_type",
            "correlation_type",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(32), nullable=False)  # ioc|breach|cve|actor|asset
    correlation_type: Mapped[str] = mapped_column(String(32), nullable=False)  # same_entity|single_source|co_occurrence|attribution
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    source_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sources: Mapped[list | None] = mapped_column(JSON)
    related_alert_ids: Mapped[list | None] = mapped_column(JSON)
    related_breach_ids: Mapped[list | None] = mapped_column(JSON)
    related_cve_ids: Mapped[list | None] = mapped_column(JSON)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeline: Mapped[list | None] = mapped_column(JSON)


class InvestigationTimeline(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Chronological event log attached to an investigation."""

    __tablename__ = "investigation_timelines"
    __table_args__ = (
        Index("ix_investigation_timelines_inv", "investigation_id", "occurred_at"),
        Index("ix_investigation_timelines_org", "organization_id", "occurred_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_key: Mapped[str | None] = mapped_column(String(255))
    entity_type: Mapped[str | None] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    evidence_refs: Mapped[list | None] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
