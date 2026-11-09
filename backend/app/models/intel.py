"""Intelligence domain models: IOCs, vulnerabilities, breaches, news, threat actors.

Provenance rule: every intelligence record keeps its original source reference
(source_slug + external URL + publication timestamp) so evidence is traceable.
"""

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, Text, Uuid
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

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False, index=True)
    severity: Mapped[str | None] = mapped_column(String(16))
    summary: Mapped[str | None] = mapped_column(Text)
    entity_refs: Mapped[dict | None] = mapped_column(JSON)  # {"iocs": [...], "cves": [...], ...}
    analyst_notes: Mapped[list | None] = mapped_column(JSON)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    confidence: Mapped[float | None] = mapped_column(Float)
    confidence_reasons: Mapped[dict | None] = mapped_column(JSON)
