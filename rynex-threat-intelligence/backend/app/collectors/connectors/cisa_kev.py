"""CISA Known Exploited Vulnerabilities (KEV) catalog.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Access: public JSON catalog, free for any use (U.S. Government work).
Update cadence: source updates periodically; we poll hourly at most.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer, validate_cve_id

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def parse_kev_record(entry: dict) -> dict | None:
    """Pure parser — returns vulnerability payload or None when invalid."""
    cve_id = (entry.get("cveID") or "").strip().upper()
    if not validate_cve_id(cve_id):
        return None
    date_added = IOCNormalizer.parse_date(entry.get("dateAdded"))
    due_date = IOCNormalizer.parse_date(entry.get("dueDate"))
    cvss = entry.get("cvssScore")
    try:
        cvss = float(cvss) if cvss not in (None, "", "N/A") else None
    except (TypeError, ValueError):
        cvss = None
    severity = entry.get("severity")
    if severity:
        severity = severity.strip().lower()
    elif (cvss or 0) >= 9:
        severity = "critical"
    return {
        "cve_id": cve_id,
        "title": entry.get("vendorProject", "") + " " + entry.get("product", ""),
        "description": entry.get("shortDescription"),
        "cvss_base_score": cvss,
        "cvss_version": None,
        "severity": severity,
        "in_kev": True,
        "kev_date_added": date_added,
        "kev_due_date": due_date,
        "kev_known_ransomware_use": bool(entry.get("knownRansomwareCampaignUse", "").lower() == "known"),
        "affected_products": [
            {"vendor": entry.get("vendorProject"), "product": entry.get("product")}
        ],
        "references": [{"url": entry.get("requiredAction")}] if entry.get("requiredAction") else [],
        "cwes": [c.get("cwename") for c in entry.get("cwes", []) if isinstance(c, dict)] if entry.get("cwes") else None,
        "published_at": date_added,
        "modified_at": None,
        "source_slug": "cisa-kev",
        "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "_external_id": cve_id,
    }


class CisaKevCollector(BaseCollector):
    slug = "cisa-kev"
    name = "CISA Known Exploited Vulnerabilities"
    category = "vulnerability"
    homepage_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    description = "Authoritative U.S. government catalog of vulnerabilities confirmed to be actively exploited."
    commercial_use_status = "permitted"
    terms_notes = "Public domain / U.S. Government work; attribution requested via catalog citation."
    collection_interval_minutes = 60
    source_credibility = 1.0

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        resp = await self.http.fetch(KEV_URL, rate_limit_interval=1.0)
        catalog = resp.json()
        known_cves = set()
        for entry in catalog.get("vulnerabilities", []):
            parsed = parse_kev_record(entry)
            if parsed is None:
                continue
            if parsed["cve_id"] in known_cves:
                continue
            known_cves.add(parsed["cve_id"])
            ext_id = parsed.pop("_external_id", None)
            yield CollectedRecord(
                kind="vulnerability", data=parsed, external_id=ext_id, published_at=parsed.get("kev_date_added")
            )
