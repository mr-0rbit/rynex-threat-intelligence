"""blocklist.de — aggregated abuse/attack IP list.

Source: https://www.blocklist.de/ — abuse reports from participating servers
(fail2ban reports, brute-force attempts, spam, scanning, bot activity).
Plain-text feed: one IPv4 per line, '#' comments. Free for any use; blocklist.de
asks operators to report abuse back where possible. Reports are volunteer-
sourced, so source_credibility is set below the abuse.ch feeds deliberately.
"""

from collections.abc import AsyncIterator

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer

BLOCKLISTDE_ALL_URL = "https://lists.blocklist.de/lists/all.txt"


def parse_blocklistde_lines(text: str) -> list[str]:
    """Pure parser: normalized, deduped IPv4 values in feed order."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        normalized = IOCNormalizer.normalize(line, "ipv4")
        if normalized is None:
            continue
        value, _ = normalized
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


class BlocklistDeCollector(BaseCollector):
    slug = "blocklist-de"
    name = "blocklist.de"
    category = "ioc"
    homepage_url = "https://www.blocklist.de/"
    description = "IPs reported for brute-force, abuse, spam and scanning attacks by participating servers."
    commercial_use_status = "permitted"
    terms_notes = "Free for any use; blocklist.de asks operators to report abuse back where possible."
    rate_limit_notes = "Poll at most once per hour — reports are aggregated upstream."
    collection_interval_minutes = 60
    source_credibility = 0.6

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        resp = await self.http.fetch(BLOCKLISTDE_ALL_URL, rate_limit_interval=2.0)
        for value in parse_blocklistde_lines(resp.text):
            yield CollectedRecord(
                kind="ioc",
                data={
                    "value": value,
                    "type": "ipv4",
                    "source_slug": self.slug,
                    "source_credibility": self.source_credibility,
                    "tags": ["attack-source", "abuse-report"],
                    "malware_family": None,
                    "last_seen_at": None,
                    "first_seen_at": None,
                    "source_url": f"https://www.blocklist.de/en/view/ip/{value}/",
                    "description": "IP reported for abusive behavior (brute-force/spam/scanning) via blocklist.de",
                },
                external_id=value,
            )
