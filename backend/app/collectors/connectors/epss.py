"""FIRST EPSS (Exploit Prediction Scoring System) bulk feed.

Source: https://api.first.org/data/v1/epss?csv=true — one bulk CSV covering
every tracked CVE (~250k rows). Records are marked `enrichment_only`: they
update `epss_score` on CVEs we already track and never insert bare rows.

EPSS is advisory data layered on top of authoritative CVE sources (NVD, KEV) —
the platform's deterministic-corroboration philosophy: enrichment never
inflates the record set.
"""

import csv
import io
from collections.abc import AsyncIterator

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import validate_cve_id

EPSS_URL = "https://api.first.org/data/v1/epss"


def parse_epss_csv(text: str) -> list[dict]:
    """Pure parser — EPSS bulk CSV → vulnerability payloads (enrichment_only).

    Header-order agnostic: column indices come from the header row, not position.
    """
    out: list[dict] = []
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return out
    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        if not validate_cve_id(cve_id):
            continue
        try:
            score = float(row.get("epss")) if row.get("epss") not in (None, "") else None
        except (TypeError, ValueError):
            score = None
        try:
            percentile = float(row.get("percentile")) if row.get("percentile") not in (None, "") else None
        except (TypeError, ValueError):
            percentile = None
        if score is None:
            continue
        out.append(
            {
                "cve_id": cve_id,
                "epss_score": score,
                "epss_percentile": percentile,
                "epss_date": row.get("date"),
                "enrichment_only": True,
                "source_slug": "epss",
                "source_url": "https://www.first.org/epss/",
            }
        )
    return out


class EPSSCollector(BaseCollector):
    slug = "epss"
    name = "FIRST EPSS"
    category = "vulnerability"
    homepage_url = "https://www.first.org/epss/"
    description = "Exploit Prediction Scoring System: probability that a CVE will be exploited in the wild within 30 days."
    commercial_use_status = "permitted"
    terms_notes = "Provided by FIRST; EPSS data is open. Attribution: EPSS by FIRST."
    rate_limit_notes = "Single bulk download per run; daily refresh is sufficient upstream."
    collection_interval_minutes = 1440
    source_credibility = 0.9

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        resp = await self.http.fetch(EPSS_URL, params={"csv": "true"}, rate_limit_interval=2.0)
        for payload in parse_epss_csv(resp.text):
            yield CollectedRecord(
                kind="vulnerability",
                data=payload,
                external_id=payload["cve_id"],
            )
