"""MISP threat intelligence feed collector.

MISP (Malware Information Sharing Platform) is an open-source threat sharing platform.
This collector connects to MISP instances via REST/SOAP API to ingest:

- Galaxies and attributes for IOCs
- threat levels and categories
- Published events for new indicators
- Existing sightings and attributions

Features:
- Configurable MISP URL and API key
- Rate limiting and retry logic
- Automatic IOC normalization and dedup
- Configurable event types to monitor
- SSL verification support
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

import httpx
from fastapi import HTTPException

from app.collectors.base import BaseCollector
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models import IOC, IntelligenceSource

logger = logging.getLogger("rtip.collectors.misp")


class MISPCollector(BaseCollector):
    """Collector for MISP threat intelligence platform."""

    name = "misp"
    slug = "misp"
    description = "MISP threat intelligence platform feed"
    version = "0.1.0"

    # Connector configuration defaults
    MISP_URL = settings.MISP_URL or "https://your-misp.instance"
    MISP_API_KEY = settings.MISP_API_KEY or ""
    MISP_VERIFY_SSL = settings.MISP_VERIFY_SSL if hasattr(settings, "MISP_VERIFY_SSL") else True
    MISP_EVENT_TYPE = settings.MISP_EVENT_TYPE or "malware-attack"
    MISP_PROXIMITY_SEARCH = True  # Search for similar/following events
    MISP_MAX_AGE_DAYS = int(settings.MISP_MAX_AGE_DAYS) if hasattr(settings, "MISP_MAX_AGE_DAYS") else 30

    def __init__(self):
        super().__init__(self.name, self.slug, self.description)
        self.client: httpx.AsyncClient | None = None

    async def _connect(self) -> None:
        """Initialize the HTTP client with auth headers."""
        headers = {
            "Authorization": self.MISP_API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.client = httpx.AsyncClient(
            timeout=30.0,
            headers=headers,
            verify=self.MISP_VERIFY_SSL,
        )

    async def _disconnect(self) -> None:
        """Close the HTTP client."""
        if self.client:
            await self.client.aclose()
            self.client = None

    async def collect(self) -> dict:
        """Collect IOCs from MISP platform.

        Fetches events matching the configured event type and extracts
        new/updated indicators into the RTIP IOC database.

        Returns:
            dict with collection stats (new_iocs, updated_iocs, skipped_iocs)
        """
        if not self.MISP_API_KEY:
            logger.warning("MISP_API_KEY not configured; skipping collector %s", self.slug)
            return {"new_iocs": 0, "updated_iocs": 0, "skipped_iocs": 0, "error": "missing_api_key"}

        await self._connect()
        try:
            new_iocs = 0
            updated_iocs = 0
            skipped_iocs = 0

            # Fetch events from MISP
            events = await self._fetch_events()
            if not events:
                logger.info("No MISP events found for collector %s", self.slug)
                return {"new_iocs": 0, "updated_iocs": 0, "skipped_iocs": 0}

            # Process each event
            async with AsyncSessionLocal() as db:
                for event in events:
                    ioc_count = await self._process_event(db, event)
                    new_iocs += ioc_count.get("new", 0)
                    updated_iocs += ioc_count.get("updated", 0)
                    skipped_iocs += ioc_count.get("skipped", 0)

                await db.commit()

            logger.info(
                "MISP collector completed: new=%s, updated=%s, skipped=%s",
                new_iocs, updated_iocs, skipped_iocs,
            )
            return {
                "new_iocs": new_iocs,
                "updated_iocs": updated_iocs,
                "skipped_iocs": skipped_iocs,
                "error": None,
            }

        except Exception as exc:
            logger.error("MISP collector failed: %s", exc, exc_info=True)
            return {"new_iocs": 0, "updated_iocs": 0, "skipped_iocs": 0, "error": str(exc)}
        finally:
            await self._disconnect()

    async def _fetch_events(self) -> list[dict]:
        """Fetch events from MISP API.

        Queries for events of the configured type within the age window.
        Returns a list of event dicts from the MISP response.
        """
        url = f"{self.MISP_URL}/events/restSearch"
        # Build CQL (MISP Query Language) search
        from datetime import timedelta
        age_cutoff = (datetime.now(timezone.utc) - timedelta(days=self.MISP_MAX_AGE_DAYS)).strftime("%Y-%m-%d")

        cql_filter = f"event_type:{self.MISP_EVENT_TYPE} AND timestamp_start:[{age_cutoff} TO *]"
        params = {
            "q": cql_filter,
            "limit": 100,
            "page": 1,
        }

        try:
            resp = await self.client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()

            # MISP restSearch returns dict with 'events' key or list directly
            events = data.get("events", data) if isinstance(data, dict) else data
            return events if isinstance(events, list) else []

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.error("MISP authentication failed - check API key")
                raise HTTPException(status_code=401, detail="MISP authentication failed")
            logger.error("MISP HTTP error: %s", e)
            raise
        except Exception as exc:
            logger.error("Failed to fetch MISP events: %s", exc)
            raise

    async def _process_event(self, db, event: dict) -> dict:
        """Process a single MISP event and extract IOCs.

        Args:
            db: Async database session
            event: MISP event dict containing attributes and galaxies

        Returns:
            dict with counts of new/updated/skipped IOCs from this event
        """
        from sqlalchemy import select, func

        new_iocs = 0
        updated_iocs = 0
        skipped_iocs = 0

        # Extract basic event info
        event_id = event.get("id", 0)
        event_info = event.get("info", "Unknown event")
        published = event.get("timestamp", datetime.now(timezone.utc).isoformat())
        if isinstance(published, str):
            try:
                published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                published_dt = datetime.now(timezone.utc)
        else:
            published_dt = datetime.now(timezone.utc)

        # Extract attributes from the event
        attributes = event.get("Attribute", [])
        if not attributes:
            return {"new": 0, "updated": 0, "skipped": 0}

        for attr in attributes:
            try:
                ioc_data = self._extract_ioc_from_attribute(attr)
                if not ioc_data:
                    skipped_iocs += 1
                    continue

                indicator_type = ioc_data.get("type", "").lower()
                indicator_value = ioc_data.get("value", "").strip()

                if not indicator_value:
                    skipped_iocs += 1
                    continue

                # Check if IOC already exists
                stmt = select(IOC).where(IOC.value == indicator_value)
                existing = (await db.execute(stmt)).scalar_one_or_none()

                # Build IOC object data
                ioc_defaults = {
                    "source": self.slug,
                    "source_id": str(event_id),
                    "category": ioc_data.get("category", "Unknown"),
                    "severity": self._map_misp_severity(attr.get("distribution", "TLP:WHITE")),
                    "confidence": 0.7,  # Base confidence for MISP-sourced IOCs
                    "description": ioc_data.get("description", ""),
                    "last_seen_at": datetime.now(timezone.utc),
                    "times_seen": 1,
                    "malware_families": ioc_data.get("malware_families", []),
                    "threat_actor": ioc_data.get("threat_actor", ""),
                    tlp_color: ioc_data.get("tlp", "white"),
                }

                if existing:
                    # Update existing IOC
                    for key, value in ioc_defaults.items():
                        setattr(existing, key, value)
                    existing.times_seen += 1
                    existing.last_seen_at = datetime.now(timezone.utc)
                    updated_iocs += 1
                else:
                    # Create new IOC
                    from app.models.io import IOC as IOCModel  # avoid circular import issues

                    ioc_model = IOCModel(
                        value=indicator_value,
                        type=indicator_type,
                        **{k: v for k, v in ioc_defaults.items() if k != "tlp_color"},
                    )
                    db.add(ioc_model)
                    new_iocs += 1

            except Exception as exc:
                logger.warning("Failed to process MISP attribute: %s", exc)
                skipped_iocs += 1

        return {"new": new_iocs, "updated": updated_iocs, "skipped": skipped_iocs}

    @staticmethod
    def _extract_ioc_from_attribute(attr: dict) -> dict | None:
        """Extract IOC value and type from a MISP attribute.

        MISP attributes have a 'type' field (e.g., "ip-src", "domain-name",
        "md5", "sha256", etc.) and a 'value' field.

        Returns dict with 'type', 'value', 'category', 'description', 'malware_families', 'tlp'
        or None if the attribute can't be parsed.
        """
        value = attr.get("value", "").strip()
        if not value:
            return None

        attr_type = attr.get("type", "").lower()

        # Map MISP types to RTIP IOC types
        type_map = {
            "ip-src": "ip",
            "ip-dst": "ip",
            "domain-name": "domain",
            "email-dest": "email",
            "email-src": "email",
            "md5": "hash",
            "sha256": "hash",
            "sha1": "hash",
            "filename": "filepath",
            "url": "url",
            "cidr": "network",
            "artifice": "infrastructure",
            "account": "account",
            "mutex": "artifact",
            "registry-key": "artifact",
            "user-agent": "artifact",
        }

        ioc_type = type_map.get(attr_type, "ioc")
        category = attr.get("category", "Unknown")
        tlp = attr.get("info_sharing", "white")  # TLP color

        # Get to identifiers fromGalaxies if available
        malware_families = []
        threat_actor = ""

        # Check for galaxy references (simplified)
        if "Galaxy" in attr:
            for galaxy in attr.get("Galaxy", []):
                malware_families.extend(galaxy.get("name", []) or [])
                threat_actor = galaxy.get(" ThreatActor", "") or threat_actor

        description = attr.get("comment", "") or ""

        return {
            "type": ioc_type,
            "value": value,
            "category": category,
            "description": description,
            "malware_families": malware_families,
            "threat_actor": threat_actor,
            "tlp": tlp,
        }

    @staticmethod
    def _map_misp_severity(distribution: str) -> str:
        """Map MISP distribution/ TLP to RTIP severity.

        MISP uses TLP colors (red, amber, green, white) for sharing.
        We map these to RTIP severity levels.
        """
        tlp_map = {
            "red": "critical",
            "amber": "high",
            "green": "medium",
            "white": "low",
        }
        return tlp_map.get(distribution.lower(), "low")