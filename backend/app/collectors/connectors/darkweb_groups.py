"""Dark web intelligence via legitimate intermediaries.

POLICY (enforced by design, not just by documentation):
- RTIP does NOT connect to Tor, onion services, or marketplaces directly.
- We consume metadata (group names, victim claims, post titles, dates) from
  Ransomware.live, a legitimate research service that tracks PUBLIC leak-site
  disclosures. No stolen data is downloaded, stored, or redistributed.
- Every record remains classified as a threat-actor CLAIM until corroborated.
"""

from collections.abc import AsyncIterator

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer

GROUPS_URL = "https://api.ransomware.live/v2/groups"


def parse_group_record(item: dict) -> dict | None:
    """Pure parser for one ransomware group profile (metadata only)."""
    name = (item.get("name") or "").strip()
    if not name:
        return None
    return {
        "name": name,
        "aliases": [item["captcha"]] if item.get("captcha") else None,
        "motivations": ["financial"],
        "targeted_industries": None,
        "targeted_regions": None,
        "associated_malware": None,
        "attack_techniques": None,
        "description": (item.get("description") or "")[:2000] or None,
        "attribution_status": "claimed",
        "source_slug": "ransomware-live",
        "source_url": "https://www.ransomware.live/groups",
        "_leaksite": item.get("url") or None,
        "_first_seen": IOCNormalizer.parse_date(item.get("first_seen")),
        "_last_seen": IOCNormalizer.parse_date(item.get("last_seen")),
    }


class DarkWebGroupsCollector(BaseCollector):
    """Monitors ransomware group profiles (leak-site operators) as metadata."""

    slug = "darkweb-groups"
    name = "Dark Web Ransomware Group Monitor (via Ransomware.live)"
    category = "darkweb"
    homepage_url = "https://www.ransomware.live/groups"
    description = (
        "Metadata profiles of ransomware leak-site operators, sourced from the "
        "legitimate Ransomware.live research service. RTIP never connects to "
        "onion services directly."
    )
    auth_method = "api_key_header"
    api_key_setting = "RANSOMWARELIVE_API_KEY"
    commercial_use_status = "unknown"
    terms_notes = (
        "Metadata only; no stolen data handled. Verify Ransomware.live terms "
        "before commercial redistribution."
    )
    collection_interval_minutes = 720  # group profiles change slowly
    source_credibility = 0.7

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        headers = {"Auth-Key": self.api_key} if self.api_key else {}
        resp = await self.http.fetch(GROUPS_URL, headers=headers, rate_limit_interval=5.0)
        for item in resp.json() or []:
            if not isinstance(item, dict):
                continue
            parsed = parse_group_record(item)
            if parsed is None:
                continue
            yield CollectedRecord(
                kind="actor",
                data=parsed,
                external_id=parsed["name"].lower(),
            )
