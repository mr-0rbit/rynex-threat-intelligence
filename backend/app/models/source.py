"""Intelligence source registry and collection job bookkeeping."""

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class IntelligenceSource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "intelligence_sources"

    # Identity
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    homepage_url: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)

    # Access & terms
    auth_method: Mapped[str] = mapped_column(String(32), default="none", nullable=False)
    api_key_setting: Mapped[str | None] = mapped_column(String(128))  # env var name, never the value
    commercial_use_status: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    terms_notes: Mapped[str | None] = mapped_column(Text)
    rate_limit_notes: Mapped[str | None] = mapped_column(Text)

    # Scheduling
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    collection_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)

    # Health
    health_status: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_records_collected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    avg_duration_seconds: Mapped[float | None] = mapped_column(Float)

    # Credibility (kept separate from per-record platform confidence)
    source_credibility: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)

    extra_config: Mapped[dict | None] = mapped_column(JSON)


class CollectionJob(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "collection_jobs"

    source_slug: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # success|failed|running
    trigger: Mapped[str] = mapped_column(String(16), default="scheduled", nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float)

    records_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_stored: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    checkpoint: Mapped[str | None] = mapped_column(Text)  # opaque incremental cursor
    error: Mapped[str | None] = mapped_column(Text)
