"""abuse.ch URLhaus — malicious URL feed.

Source: https://urlhaus-api.abuse.ch/v1/
Access: the classic /downloads/recent/ text feeds were retired (HTTP 410 Gone).
The JSON API v1 requires a free "Auth-Key" from https://auth.abuse.ch/ sent as
the Auth-Key header. abuse.ch data is free for any purpose with attribution;
commercial use may require the paid commercial API — see terms_notes.
"""

from collections.abc import AsyncIterator

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def parse_urlhaus_api_record(item: dict) -> dict | None:
    """Pure parser for one URLhaus API v1 url object — returns IOC payload or None."""
    normalized = IOCNormalizer.normalize(IOCNormalizer.refang(item.get("url") or ""), "url")
    if normalized is None:
        return None
    value, _ = normalized
    host = value.split("/")[2] if "://" in value else value
    if IOCNormalizer.is_benign_domain(host):
        return None
    tags = [t for t in (item.get("tags") or []) if isinstance(t, str)]
    threat = item.get("threat") or None
    if threat:
        tags.append(threat)
    ts = IOCNormalizer.parse_date(item.get("date_added") or item.get("last_online"))
    return {
        "value": value,
        "type": "url",
        "source_slug": "urlhaus",
        "source_url": item.get("urlhaus_reference") or "https://urlhaus.abuse.ch/browse/",
        "malware_family": None,
        "tags": tags or ["malware-distribution"],
        "confidence": 0.5,
        "source_reputation": "urlhaus",
        "last_seen_at": ts,
        "first_seen_at": None,
        "description": f"Malicious URL ({threat}) observed by URLhaus" if threat else "Malicious URL observed by URLhaus",
    }


class URLhausCollector(BaseCollector):
    slug = "urlhaus"
    name = "abuse.ch URLhaus"
    category = "ioc"
    homepage_url = "https://urlhaus.abuse.ch/"
    description = "Crowd-sourced feed of URLs distributing malware, operated by abuse.ch."
    auth_method = "api_key_header"
    api_key_setting = "URLHAUS_AUTH_KEY"
    commercial_use_status = "permitted"
    terms_notes = (
        "Free for any purpose with attribution; API v1 requires a free Auth-Key "
        "(https://auth.abuse.ch/). Commercial/for-profit use may require the paid "
        "commercial API — verify terms before commercial redistribution."
    )
    rate_limit_notes = "Keep API requests to a handful per minute; we poll once per interval."
    collection_interval_minutes = 15
    source_credibility = 0.85

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        if not self.api_key:
            raise RuntimeError(
                "URLhaus API v1 requires a free Auth-Key (https://auth.abuse.ch/) — set URLHAUS_AUTH_KEY"
            )
        headers = {"Auth-Key": self.api_key}
        resp = await self.http.fetch(
            URLHAUS_API_URL, method="POST", headers=headers, rate_limit_interval=5.0
        )
        payload = resp.json()
        if payload.get("query_status") != "ok":
            raise RuntimeError(f"URLhaus API error: {payload.get('query_status') or payload.get('error')}")
        for item in payload.get("urls") or payload.get("data") or []:
            if not isinstance(item, dict):
                continue
            parsed = parse_urlhaus_api_record(item)
            if parsed is None:
                continue
            yield CollectedRecord(
                kind="ioc",
                data=parsed,
                external_id=str(item.get("id")) if item.get("id") else None,
                published_at=parsed.get("last_seen_at"),
            )
