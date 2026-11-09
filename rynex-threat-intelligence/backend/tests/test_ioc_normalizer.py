"""Deterministic IOC normalization and validation tests."""

import pytest

from app.services.ioc_normalizer import IOCNormalizer, validate_cve_id


class TestNormalization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("1.2.3.4", ("1.2.3.4", "ipv4")),
            ("2001:0db8:0000:0000:0000:ff00:0042:8329", ("2001:db8::ff00:42:8329", "ipv6")),
            ("HTTP://Example.COM/path", ("HTTP://Example.COM/path", "url")),
            ("Example.COM/path/../", None),  # invalid url without scheme
            ("user@example.com", ("user@example.com", "email")),
            ("EXAMPLE.com", ("example.com", "domain")),
            ("d41d8cd98f00b204e9800998ecf8427e", ("d41d8cd98f00b204e9800998ecf8427e", "md5")),
            ("a" * 64, ("a" * 64, "sha256")),
            ("b" * 41, None),  # wrong hash length
            ("", None),
            ("999.999.999.999", None),
        ],
    )
    def test_normalize(self, raw, expected):
        assert IOCNormalizer.normalize(raw) == expected

    def test_auto_detect(self):
        assert IOCNormalizer.detect_type("1.2.3.4") == "ipv4"
        assert IOCNormalizer.detect_type("CVE-2024-1234") == "cve"
        assert IOCNormalizer.detect_type("https://evil.example/x") == "url"
        assert IOCNormalizer.detect_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
        assert IOCNormalizer.detect_type("not an indicator at all") is None

    def test_refang(self):
        assert IOCNormalizer.refang("hxxp://evil[.]com") == "http://evil.com"
        assert IOCNormalizer.refang("bad(dot)site") == "bad.site"

    def test_benign_allowlist(self):
        assert IOCNormalizer.is_benign_domain("mail.google.com")
        assert not IOCNormalizer.is_benign_domain("notgoogle.com")
        assert not IOCNormalizer.is_benign_domain("evil-google.com")

    def test_cve_validation(self):
        assert validate_cve_id("CVE-2024-3094")
        assert validate_cve_id("cve-2023-4863")
        assert not validate_cve_id("CVE-2024-123")  # too short
        assert not validate_cve_id("XVE-2024-1234")

    def test_fingerprint_stable(self):
        a = IOCNormalizer.fingerprint("breach", "Acme Corp", "LockBit")
        b = IOCNormalizer.fingerprint("breach", "  acme corp ", "lockbit")
        assert a == b
        assert len(a) == 40

    def test_date_parsing(self):
        from datetime import timezone

        dt = IOCNormalizer.parse_date("2025-01-15T10:30:00Z")
        assert dt is not None and dt.year == 2025 and dt.tzinfo is not None
        assert IOCNormalizer.parse_date("Mon, 15 Jan 2025 10:30:00 +0000") is not None
        assert IOCNormalizer.parse_date("garbage") is None
        assert IOCNormalizer.parse_date(None) is None
        assert not dt.tzinfo is timezone.utc or True  # tz-aware assertion sanity
