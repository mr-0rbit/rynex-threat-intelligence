"""Alerts, alert rules, notifications and watchlists."""

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Alert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_fingerprint_status", "fingerprint", "status"),)

    # Deduplication fingerprint (category + stable entity key); changes when new evidence arrives
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    evidence_hash: Mapped[str | None] = mapped_column(String(64))

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)  # critical|high|medium|low|informational
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    confidence_reasons: Mapped[dict | None] = mapped_column(JSON)

    affected_entities: Mapped[list | None] = mapped_column(JSON)
    evidence_sources: Mapped[list | None] = mapped_column(JSON)  # [{source_slug, url, published_at}]

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_evidence_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False, index=True)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    notified_channels: Mapped[list | None] = mapped_column(JSON)


class AlertRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "alert_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    min_severity: Mapped[str] = mapped_column(String(16), default="low", nullable=False)
    conditions: Mapped[dict | None] = mapped_column(JSON)  # structured matcher config
    min_confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    notify_channels: Mapped[list | None] = mapped_column(JSON)  # ["telegram","email","webhook","slack"]


class Watchlist(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "watchlists"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner_email: Mapped[str | None] = mapped_column(String(320))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class WatchlistItem(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "watchlist_items"

    watchlist_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True, nullable=False)
    item_type: Mapped[str] = mapped_column(String(32), nullable=False)  # organization|domain|actor|cve|keyword
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
