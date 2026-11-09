"""abuse.ch Feodo Tracker — C2 server IP feed for banking trojans.

Source: https://feodotracker.abuse.ch/
Access: free JSON/IP-blocklist feeds.
"""

from collections.abc import AsyncIterator

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer

FEODO_JSON_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def parse_feodo_record(item: dict) -> dict | None:
    normalized = IOCNormalizer.normalize(item.get("ip_address", ""), "ipv4")
    if normalized is None:
        return None
    value, _ = normalized
    ts = IOCNormalizer.parse_date(item.get("last_online"))
    return {
        "value": value,
        "type": "ipv4",
        "source_slug": "feodo-tracker",
        "source_url": f"https://feodotracker.abuse.ch/ipaddr/{value}/",
        "malware_family": item.get("malware"),
        "tags": ["c2", "banking-trojan"],
        "confidence": 0.8,
        "source_reputation": "feodo c2",
        "last_seen_at": ts,
        "first_seen_at": None,
        "description": f"C2 server for {item.get('malware') or 'botnet'} observed by Feodo Tracker",
    }


class FeodoTrackerCollector(BaseCollector):
    slug = "feodo-tracker"
    name = "abuse.ch Feodo Tracker"
    category = "ioc"
    homepage_url = "https://feodotracker.abuse.ch/"
    description = "List of command-and-control servers for Dridex/Emotet/QakBot/Bebloh and related botnets."
    commercial_use_status = "permitted"
    terms_notes = "Free for any purpose with attribution to abuse.ch."
    collection_interval_minutes = 30
    source_credibility = 0.85

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        resp = await self.http.fetch(FEODO_JSON_URL, rate_limit_interval=2.0)
        for item in resp.json() or []:
            if not isinstance(item, dict):
                continue
            parsed = parse_feodo_record(item)
            if parsed is None:
                continue
            yield CollectedRecord(kind="ioc", data=parsed, external_id=parsed["value"])
