"""abuse.ch URLhaus — malicious URL feed.

Source: https://urlhaus.abuse.ch/api/
Access: free CSV/text feeds; abuse.ch asks operators to register for an
"Auth-Key" (free) which we pass through when configured. Commercial use:
abuse.ch data is available for any purpose with attribution to the project.
"""

import csv
from collections.abc import AsyncIterator

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/recent/"


def parse_urlhaus_csv(text: str) -> list[tuple[str, str | None]]:
    """Parse URLhaus feeds.

    Handles both formats abuse.ch publishes:
    - recent/: one URL per line
    - full CSV: id,dateadded,url,url_status,threat,tags,urlhaus_link
    Returns [(url, malware_family_or_None)].
    """
    out: list[tuple[str, str | None]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            reader = csv.reader([line])
            row = next(reader)
            # Full CSV: url is the 3rd column
            if len(row) >= 3 and row[0].isdigit():
                url_raw, family = row[2], None
            else:
                url_raw, family = row[0], None
        else:
            url_raw, family = line, None
        normalized = IOCNormalizer.normalize(IOCNormalizer.refang(url_raw), "url")
        if normalized:
            out.append((normalized[0], family))
    return out


class URLhausCollector(BaseCollector):
    slug = "urlhaus"
    name = "abuse.ch URLhaus"
    category = "ioc"
    homepage_url = "https://urlhaus.abuse.ch/"
    description = "Crowd-sourced feed of URLs distributing malware, operated by abuse.ch."
    auth_method = "api_key_header"
    api_key_setting = "URLHAUS_AUTH_KEY"
    commercial_use_status = "permitted"
    terms_notes = "Free for any purpose; abuse.ch requests attribution and free registration for heavy use."
    rate_limit_notes = "Downloads limited to once per 5 minutes per feed."
    collection_interval_minutes = 15
    source_credibility = 0.85

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        headers = {"Auth-Key": self.api_key} if self.api_key else {}
        resp = await self.http.fetch(URLHAUS_CSV_URL, headers=headers, rate_limit_interval=300.0)
        text = resp.text
        for url, firstseen in parse_urlhaus_csv(text):
            yield CollectedRecord(
                kind="ioc",
                data={
                    "value": url,
                    "type": "url",
                    "source_slug": self.slug,
                    "tags": ["malware-distribution"],
                    "malware_family": firstseen,
                    "last_seen_at": None,
                    "source_url": "https://urlhaus.abuse.ch/browse/",
                    "description": None,
                },
                external_id=None,
            )
