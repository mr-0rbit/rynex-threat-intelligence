"""NVD (National Vulnerability Database) API 2.0 connector.

Incremental by `lastModStartDate/lastModEndDate` (max 120-day window). An
optional API key raises the rate limit (https://nvd.nist.gov/developers/request-an-api-key);
without one we poll slowly (5 requests / 30 s rolling window).
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from app.collectors.base import BaseCollector, CollectedRecord
from app.services.ioc_normalizer import IOCNormalizer, validate_cve_id

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 120
MAX_PAGES = 100  # hard stop against runaway pagination
RESULTS_PER_PAGE = 2000

# Rate limits: 5 req / 30 s keyless, 50 req / 30 s with key — stay conservative.
NO_KEY_INTERVAL = 6.5
KEY_INTERVAL = 0.7


def parse_nvd_cve(item: dict) -> dict | None:
    """Pure parser — NVD API 2.0 CVE record → vulnerability payload or None."""
    cve_id = (item.get("id") or "").strip().upper()
    if not validate_cve_id(cve_id):
        return None

    # CVSS: prefer the newest metric version present
    metrics = item.get("metrics") or {}
    score = vector = severity = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            try:
                score = float(data["baseScore"]) if data.get("baseScore") is not None else None
            except (TypeError, ValueError):
                score = None
            vector = data.get("vectorString")
            severity = (data.get("baseSeverity") or "").strip().lower() or None
            break
    if severity is None and score is not None:
        severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"

    description = None
    for desc in item.get("descriptions") or []:
        if desc.get("lang") == "en" and desc.get("value"):
            description = desc["value"]
            break

    references = [
        {"url": ref.get("url"), "tags": ref.get("tags")}
        for ref in (item.get("references") or [])
        if ref.get("url")
    ]

    cwes = []
    for weakness in item.get("weaknesses") or []:
        for wdesc in weakness.get("description") or []:
            val = wdesc.get("value")
            if val and val not in ("NVD-CWE-noinfo", "NVD-CWE-Other") and val not in cwes:
                cwes.append(val)

    # CPE configurations → vendor/product pairs
    products: list[dict] = []
    seen: set[tuple] = set()
    for config in item.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") or ""
                parts = criteria.split(":")
                if len(parts) >= 5 and parts[0] == "cpe":
                    key = (parts[3], parts[4])
                    if key not in seen:
                        seen.add(key)
                        products.append({"vendor": parts[3], "product": parts[4]})

    return {
        "cve_id": cve_id,
        "title": None,
        "description": description,
        "cvss_base_score": score,
        "cvss_vector": vector,
        "severity": severity,
        "in_kev": False,  # KEV status comes from the CISA feed, never downgraded here
        "kev_date_added": None,
        "kev_due_date": None,
        "kev_known_ransomware_use": None,
        "affected_products": products or None,
        "references": references or None,
        "cwes": cwes or None,
        "published_at": IOCNormalizer.parse_date(item.get("published")),
        "modified_at": IOCNormalizer.parse_date(item.get("lastModified")),
        "source_slug": "nvd",
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _iso(dt: datetime) -> str:
    """NVD API 2.0 timestamp format (ISO-8601 with milliseconds and UTC offset)."""
    return dt.astimezone(UTC).isoformat(timespec="milliseconds")


class NVDCollector(BaseCollector):
    slug = "nvd"
    name = "NVD — National Vulnerability Database"
    category = "vulnerability"
    homepage_url = "https://nvd.nist.gov"
    description = "U.S. government vulnerability database: CVSS scores, CPE product mapping, references and CWE weaknesses."
    auth_method = "api_key_header"
    api_key_setting = "NVD_API_KEY"  # optional; raises rate limit only
    commercial_use_status = "permitted"
    terms_notes = "NVD API terms: attribution to NVD requested; no official SLA on the free tier."
    rate_limit_notes = "5 requests/30s without key, 50/30s with key."
    collection_interval_minutes = 60
    source_credibility = 1.0
    checkpoint_value: str | None = None

    async def fetch_batch(self, checkpoint: str | None = None) -> AsyncIterator[CollectedRecord]:
        now = datetime.now(UTC)
        if checkpoint:
            try:
                start = datetime.fromisoformat(checkpoint)
            except ValueError:
                start = None
        else:
            start = None
        if start is None:
            from app.core.config import settings

            start = now - timedelta(days=settings.NVD_MAX_AGE_DAYS)
        # NVD caps the window at 120 days
        if (now - start).days > MAX_WINDOW_DAYS:
            start = now - timedelta(days=MAX_WINDOW_DAYS)

        headers = {}
        interval = NO_KEY_INTERVAL
        if self.api_key:
            headers["apiKey"] = self.api_key
            interval = KEY_INTERVAL

        last_modified = start
        start_index = 0
        for _ in range(MAX_PAGES):
            resp = await self.http.fetch(
                NVD_API_URL,
                headers=headers,
                params={
                    "lastModStartDate": _iso(start),
                    "lastModEndDate": _iso(now),
                    "resultsPerPage": RESULTS_PER_PAGE,
                    "startIndex": start_index,
                },
                rate_limit_interval=interval,
            )
            payload = resp.json()
            vulns = payload.get("vulnerabilities") or []
            for entry in vulns:
                parsed = parse_nvd_cve(entry.get("cve") or {})
                if parsed is None:
                    continue
                mod = parsed["modified_at"] or parsed["published_at"]
                if mod and (last_modified is None or mod > last_modified):
                    last_modified = mod
                yield CollectedRecord(
                    kind="vulnerability",
                    data=parsed,
                    external_id=parsed["cve_id"],
                    published_at=parsed["published_at"],
                )
            total = int(payload.get("totalResults") or 0)
            start_index += RESULTS_PER_PAGE
            if start_index >= total or not vulns:
                break

        self.checkpoint_value = _iso(last_modified or start)
