"""Asset inventory: the organization's own attack surface.

Asset-aware intelligence is the core enterprise feature: alerts become
actionable when they are matched against assets the organization actually
owns (domains, IP ranges, products, vendors).
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

ASSET_TYPES = ("domain", "ipv4", "ipv6", "cidr", "product", "vendor", "keyword")


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_type_value", "type", "value"),
    )

    # type: domain|ipv4|ipv6|cidr|product|vendor|keyword
    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    criticality: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)  # low|medium|high|critical
    owner_team: Mapped[str | None] = mapped_column(String(128))
    notes: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list | None] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    match_count: Mapped[int] = mapped_column(default=0, nullable=False)

    created_by_email: Mapped[str | None] = mapped_column(String(320))
