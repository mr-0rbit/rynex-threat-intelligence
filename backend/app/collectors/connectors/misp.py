"""MISP collector — pulls published IOC attributes from a MISP instance.

MISP (Malware Information Sharing Platform) is the de-facto standard for
community/sector threat sharing. This connector talks to a single instance's
restSearch API (POST /events/restSearch) and yields already-published IOC
attributes (IPs, domains, URLs, hashes, emails) as CollectedRecords.

Optional source: requires MISP_URL and MISP_API_KEY env vars. It is NOT in the
Celery beat schedule — trigger manually via POST /api/v1/sources/misp/collect
(analyst+). TLP markings are preserved as tags; redistribution terms are set by
the sharing community that runs the instance, so commercial_use_status stays
"unknown" until the operator confirms the instance's policy.
"""

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer

# MISP attribute type → RTIP IOC type ("ip" auto-resolves to ipv4/ipv6)
MISP_TYPE_MAP = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
}


def _parse_misp_timestamp(value) -> datetime | None:
    """MISP timestamps are epoch seconds (int or str); never guess."""
    if value in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(float(value)), tz=UTC)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def parse_misp_attribute(
    attr: dict,
    event_tags: list[str] | None = None,
    source_url: str | None = None,
) -> dict | None:
    """Pure parser for one MISP attribute (restSearch JSON format).

    Returns a dict matching the IOC ingestion contract, or None when the
    attribute is not a supported IOC type or fails normalization.
    """
    if not isinstance(attr, dict):
        return None
    attr_type = (attr.get("type") or "").strip().lower()
    mapped = MISP_TYPE_MAP.get(attr_type)
    if mapped is None:
        return None
    raw = (attr.get("value") or "").strip()
    if not raw:
        return None
    # "value1|value2" forms (e.g. domain|ip) are not supported individually
    raw = raw.split("|")[0].strip()
    normalized = IOCNormalizer.normalize(raw, mapped)
    if normalized is None:
        return None
    value, vtype = normalized
    host = value.split("/")[2] if vtype == "url" else value
    if vtype in ("domain", "url") and IOCNormalizer.is_benign_domain(host):
        return None

    tags = ["misp"]
    for tag in (event_tags or []) + [
        t.get("name") or "" for t in (attr.get("Tag") or []) if isinstance(t, dict)
    ]:
        name = (tag or "").strip()
        if name and name not in tags:
            tags.append(name)

    ts = _parse_misp_timestamp(attr.get("timestamp"))
    first_seen = _parse_misp_timestamp(attr.get("first_seen")) or ts
    last_seen = _parse_misp_timestamp(attr.get("last_seen")) or ts

    return {
        "value": value,
        "type": vtype,
        "source_slug": "misp",
        "source_url": source_url,
        "tags": tags,
        "confidence": 0.75,  # shared community indicator; platform score applied at ingest
        "description": (attr.get("comment") or "").strip() or None,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "external_id": (attr.get("uuid") or None),
    }


class MISPCollector(BaseCollector):
    """Collector for a single MISP instance via restSearch."""

    slug = "misp"
    name = "MISP Instance"
    category = "ioc"
    homepage_url = "https://www.misp-project.org/"
    description = (
        "Published IOC attributes pulled from a private/community MISP instance "
        "via the restSearch API."
    )
    auth_method = "api_key_header"
    api_key_setting = "MISP_API_KEY"
    commercial_use_status = "unknown"
    terms_notes = (
        "Terms are set per instance by the sharing community that runs it; verify the "
        "instance's sharing policy and TLP markings before redistribution. Only "
        "already-published attributes are pulled. The instance must present a valid "
        "TLS certificate."
    )
    rate_limit_notes = "One restSearch call per run; manual trigger only."
    collection_interval_minutes = 360
    source_credibility = 0.8

    def __init__(self, api_key: str | None = None):
        super().__init__(api_key=api_key or os.getenv("MISP_API_KEY"))
        self.base_url = (os.getenv("MISP_URL") or "").rstrip("/")
        self.max_age_days = int(os.getenv("MISP_MAX_AGE_DAYS", "30"))

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        if not self.base_url:
            raise RuntimeError("MISP collector requires MISP_URL to be set")
        if not self.api_key:
            raise RuntimeError("MISP collector requires an API key — set MISP_API_KEY")

        since = int((datetime.now(UTC) - timedelta(days=self.max_age_days)).timestamp())
        body = {"returnFormat": "json", "published": 1, "timestamp": str(since), "limit": 500}
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        resp = await self.http.fetch(
            f"{self.base_url}/events/restSearch",
            method="POST",
            headers=headers,
            json_body=body,
            rate_limit_interval=2.0,
        )
        payload = resp.json()
        events = payload.get("response", []) if isinstance(payload, dict) else payload
        if not isinstance(events, list):
            return

        for item in events:
            event = item.get("Event", item) if isinstance(item, dict) else None
            if not isinstance(event, dict):
                continue
            event_id = event.get("id")
            event_url = f"{self.base_url}/events/view/{event_id}" if event_id else self.base_url
            event_tags = [
                t.get("name") or "" for t in (event.get("Tag") or []) if isinstance(t, dict)
            ]
            for attr in event.get("Attribute") or []:
                parsed = parse_misp_attribute(attr, event_tags=event_tags, source_url=event_url)
                if parsed is None:
                    continue
                external_id = parsed.pop("external_id", None)
                yield CollectedRecord(
                    kind="ioc",
                    data=parsed,
                    external_id=external_id,
                    published_at=parsed.get("last_seen_at"),
                )
