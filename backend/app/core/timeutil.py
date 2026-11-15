"""Timezone helpers.

SQLite stores DateTime(timezone=True) columns as naive datetimes; PostgreSQL
returns aware ones. Every in-process datetime comparison must normalize first.
"""

from datetime import UTC, datetime


def ensure_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def utc_now() -> datetime:
    return datetime.now(UTC)
