"""Base collector contract.

Every connector subclasses BaseCollector and implements fetch_batch(), which
returns normalized records. The framework owns: job bookkeeping, retries,
checkpointing, health tracking, and counters. A failing connector can never
take down the pipeline.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.http import CollectorHTTPError, shared_http
from app.models import CollectionJob, IntelligenceSource

logger = logging.getLogger("rtip.collectors")


@dataclass
class CollectedRecord:
    """A normalized intelligence record produced by a connector."""

    kind: str  # "ioc" | "vulnerability" | "breach" | "news" | "actor"
    data: dict[str, Any]
    external_id: str | None = None
    published_at: datetime | None = None
    raw: dict[str, Any] | None = field(default=None, repr=False)


@dataclass
class CollectorResult:
    source_slug: str
    records: list[CollectedRecord] = field(default_factory=list)
    rejected: int = 0
    checkpoint: str | None = None
    errors: list[str] = field(default_factory=list)


class BaseCollector(ABC):
    """Contract for all source connectors."""

    slug: str = ""
    name: str = ""
    category: str = ""
    homepage_url: str = ""
    description: str = ""
    auth_method: str = "none"  # none|api_key_header|api_key_query|bearer
    api_key_setting: str | None = None  # env var NAME only; value resolved at runtime
    commercial_use_status: str = "unknown"  # permitted|attribution_required|unknown|restricted
    terms_notes: str | None = None
    rate_limit_notes: str | None = None
    collection_interval_minutes: int = 60
    source_credibility: float = 0.5
    default_rate_limit_interval: float = 0.0  # min seconds between requests

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key
        self.http = shared_http

    @abstractmethod
    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        """Yield normalized records. Must be incremental when the source allows it."""
        raise NotImplementedError
        yield  # pragma: no cover  (keeps the method an async generator contract)

    async def run(self, db: AsyncSession, trigger: str = "scheduled") -> CollectorResult:
        """Execute a collection run with full job bookkeeping."""
        job = CollectionJob(
            source_slug=self.slug, status="running", trigger=trigger, started_at=datetime.now(UTC)
        )
        db.add(job)
        await db.flush()

        result = CollectorResult(source_slug=self.slug)
        start = time.monotonic()
        try:
            async for record in self.fetch_batch(job.checkpoint):
                if record is None:
                    result.rejected += 1
                    continue
                result.records.append(record)
            job.checkpoint = result.checkpoint or job.checkpoint
            job.status = "success"
        except (CollectorHTTPError, Exception) as exc:  # noqa: BLE001 — connector isolation
            job.status = "failed"
            job.error = str(exc)[:2000]
            result.errors.append(str(exc))
            logger.error("collector %s failed: %s", self.slug, exc, extra={"source_id": self.slug})

        duration = time.monotonic() - start
        job.finished_at = datetime.now(UTC)
        job.duration_seconds = round(duration, 3)
        job.records_received = len(result.records) + result.rejected
        job.records_rejected = result.rejected
        job.records_stored = len(result.records)

        await self._update_source_health(db, job, duration)
        await db.flush()
        return result

    async def _update_source_health(
        self, db: AsyncSession, job: CollectionJob, duration: float
    ) -> None:
        from sqlalchemy import select

        stmt = select(IntelligenceSource).where(IntelligenceSource.slug == self.slug)
        source = (await db.execute(stmt)).scalar_one_or_none()
        now = datetime.now(UTC)
        if source is None:
            source = IntelligenceSource(
                slug=self.slug,
                name=self.name,
                category=self.category,
                homepage_url=self.homepage_url,
                description=self.description,
                auth_method=self.auth_method,
                api_key_setting=self.api_key_setting,
                commercial_use_status=self.commercial_use_status,
                terms_notes=self.terms_notes,
                rate_limit_notes=self.rate_limit_notes,
                collection_interval_minutes=self.collection_interval_minutes,
                source_credibility=self.source_credibility,
                enabled=True,
                health_status="unknown",
                consecutive_failures=0,
                total_records_collected=0,
            )
            db.add(source)

        if job.status == "success":
            source.last_success_at = now
            source.consecutive_failures = 0
            source.health_status = "healthy"
            source.total_records_collected += job.records_stored
            source.avg_duration_seconds = (
                round((source.avg_duration_seconds or duration) + duration) / 2
                if source.avg_duration_seconds
                else round(duration, 3)
            )
        else:
            source.last_failure_at = now
            source.last_error = (job.error or "unknown error")[:2000]
            source.consecutive_failures = (source.consecutive_failures or 0) + 1
            source.health_status = "degraded" if source.consecutive_failures < 3 else "failing"
