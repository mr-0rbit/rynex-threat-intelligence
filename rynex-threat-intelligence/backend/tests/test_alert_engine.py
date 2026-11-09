"""Alert engine tests: rule matching, fingerprinting, dedup semantics."""

from datetime import UTC, datetime

from app.services.alert_engine import (
    CAT_KEV_ENTRY,
    AlertEngine,
    IntelligenceEvent,
    should_update_existing_alert,
)


def kev_event(cve="CVE-2025-10001", title=None):
    return IntelligenceEvent(
        category=CAT_KEV_ENTRY,
        title=title or f"Actively exploited vulnerability added to CISA KEV: {cve}",
        description="test",
        severity="high",
        confidence=0.95,
        source_slug="cisa-kev",
        source_url="https://www.cisa.gov/",
        published_at=datetime.now(UTC),
        entities={"cves": [cve]},
    )


class TestRuleEvaluation:
    def test_kev_event_matches(self):
        engine = AlertEngine()
        candidate = engine.evaluate(kev_event())
        assert candidate is not None
        assert candidate.category == CAT_KEV_ENTRY

    def test_severity_gate(self):
        engine = AlertEngine(rules=[{"name": "r", "category": "*", "min_severity": "critical", "min_confidence": 0.0}])
        assert engine.evaluate(kev_event()) is None  # high < critical

    def test_confidence_gate(self):
        engine = AlertEngine(rules=[{"name": "r", "category": "*", "min_severity": "low", "min_confidence": 0.99}])
        event = kev_event()
        event.confidence = 0.5
        assert engine.evaluate(event) is None

    def test_disabled_rule_skips(self):
        engine = AlertEngine(rules=[{"name": "r", "category": "*", "min_severity": "low", "min_confidence": 0.0, "enabled": False}])
        assert engine.evaluate(kev_event()) is None


class TestDeduplication:
    def test_same_incident_same_fingerprint(self):
        engine = AlertEngine()
        a = engine.evaluate(kev_event("CVE-2025-10001"))
        b = engine.evaluate(kev_event("CVE-2025-10001"))
        assert a.fingerprint == b.fingerprint

    def test_different_cves_different_fingerprints(self):
        engine = AlertEngine()
        a = engine.evaluate(kev_event("CVE-2025-10001"))
        b = engine.evaluate(kev_event("CVE-2025-10002"))
        assert a.fingerprint != b.fingerprint

    def test_new_evidence_changes_hash(self):
        engine = AlertEngine()
        a = engine.evaluate(kev_event())
        b = engine.evaluate(kev_event(title="Updated: more details on the KEV addition"))
        assert a.fingerprint == b.fingerprint  # same incident
        assert a.evidence_hash != b.evidence_hash  # but new evidence

    def test_should_update_semantics(self):
        assert should_update_existing_alert("hash-a", "hash-b") is True
        assert should_update_existing_alert("hash-a", "hash-a") is False
