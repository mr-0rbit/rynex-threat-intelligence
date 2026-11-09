"""Alert engine: evaluates intelligence against configured rules, dedupes by fingerprint.

Pure evaluation logic lives here (unit-testable); persistence lives in the
collection task layer. Deduplication: same fingerprint + same evidence hash
never creates a new alert; new evidence bumps occurrence_count and updates
last_evidence_at instead.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Alert categories (from platform specification)
CAT_BREACH_DISCLOSURE = "data_breach_disclosure"
CAT_RANSOMWARE_VICTIM = "ransomware_victim"
CAT_CREDENTIAL_EXPOSURE = "credential_exposure"
CAT_CRITICAL_VULN = "critical_vulnerability"
CAT_KEV_ENTRY = "new_kev_entry"
CAT_HIGH_EPSS = "high_epss_vulnerability"
CAT_MALICIOUS_IP = "malicious_ip"
CAT_MALICIOUS_DOMAIN_URL = "malicious_domain_url"
CAT_MALWARE_CAMPAIGN = "malware_campaign"
CAT_THREAT_ACTOR = "threat_actor_activity"
CAT_SIGNIFICANT_INCIDENT = "significant_incident"
CAT_WATCHLIST_MATCH = "watchlist_mention"


@dataclass
class IntelligenceEvent:
    """A normalized intelligence item flowing into the alert engine."""

    category: str
    title: str
    description: str | None
    severity: str
    confidence: float
    source_slug: str
    source_url: str | None
    published_at: datetime | None
    entities: dict  # e.g. {"ips": [...], "domains": [...], "cves": [...], "org": "..."}


@dataclass
class AlertCandidate:
    fingerprint: str
    evidence_hash: str
    category: str
    severity: str
    title: str
    description: str | None
    confidence: float
    source_slug: str
    source_url: str | None
    published_at: datetime | None
    entities: dict
    detected_at: datetime


class AlertEngine:
    def __init__(self, rules: list[dict] | None = None):
        # rules: [{"name":..., "category":..., "min_severity":..., "min_confidence":..., "enabled": True}]
        self.rules = rules or self.default_rules()

    @staticmethod
    def default_rules() -> list[dict]:
        return [
            {"name": "kev-new-entry", "category": CAT_KEV_ENTRY, "min_severity": "high", "min_confidence": 0.0},
            {"name": "critical-cve", "category": CAT_CRITICAL_VULN, "min_severity": "critical", "min_confidence": 0.0},
            {"name": "breach-disclosure", "category": CAT_BREACH_DISCLOSURE, "min_severity": "low", "min_confidence": 0.0},
            {"name": "ransomware-victim", "category": CAT_RANSOMWARE_VICTIM, "min_severity": "low", "min_confidence": 0.0},
            {"name": "malicious-url-ip", "category": CAT_MALICIOUS_DOMAIN_URL, "min_severity": "medium", "min_confidence": 0.3},
        ]

    def evaluate(self, event: IntelligenceEvent) -> AlertCandidate | None:
        """Return an AlertCandidate when the event matches an enabled rule, else None."""
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            if rule.get("category") not in (None, "*", event.category):
                continue
            min_sev = SEVERITY_ORDER.get(rule.get("min_severity", "informational"), 0)
            if SEVERITY_ORDER.get(event.severity, 0) < min_sev:
                continue
            if event.confidence < rule.get("min_confidence", 0.0):
                continue

            fp = self._fingerprint(event)
            return AlertCandidate(
                fingerprint=fp,
                evidence_hash=self._evidence_hash(event),
                category=event.category,
                severity=event.severity,
                title=event.title,
                description=event.description,
                confidence=event.confidence,
                source_slug=event.source_slug,
                source_url=event.source_url,
                published_at=event.published_at,
                entities=event.entities,
                detected_at=datetime.now(UTC),
            )
        return None

    @staticmethod
    def _fingerprint(event: IntelligenceEvent) -> str:
        """Stable identity of the *incident*, not the collection run."""
        e = event.entities
        if event.category == CAT_KEV_ENTRY:
            cve = (e.get("cves") or ["unknown"])[0]
            return f"kev:{cve.lower()}"
        if event.category == CAT_CRITICAL_VULN:
            cve = (e.get("cves") or ["unknown"])[0]
            return f"cve:{cve.lower()}"
        if event.category in (CAT_BREACH_DISCLOSURE, CAT_RANSOMWARE_VICTIM, CAT_CREDENTIAL_EXPOSURE):
            org = (e.get("org") or e.get("orgs") or ["unknown"])[0] if isinstance(e.get("orgs"), list) else e.get("org", "unknown")
            actor = e.get("actor") or "unknown-actor"
            return f"breach:{str(org).lower()}:{str(actor).lower()}"
        if event.category in (CAT_MALICIOUS_IP, CAT_MALICIOUS_DOMAIN_URL):
            vals = sorted((e.get("urls") or []) + (e.get("ips") or []) + (e.get("domains") or []))
            key = vals[0] if vals else event.title.lower()
            return f"mal:{key.lower()}"
        return f"evt:{event.category}:{hashlib.sha256(event.title.lower().encode()).hexdigest()[:16]}"

    @staticmethod
    def _evidence_hash(event: IntelligenceEvent) -> str:
        """Hash of evidence content: changes when meaningful new evidence appears."""
        payload = f"{event.source_slug}|{event.source_url or ''}|{event.title}|{event.description or ''}"
        return hashlib.sha256(payload.encode()).hexdigest()


def should_update_existing_alert(existing_evidence_hash: str | None, new_evidence_hash: str) -> bool:
    """Only meaningful new evidence warrants updating a deduplicated alert."""
    return existing_evidence_hash != new_evidence_hash
