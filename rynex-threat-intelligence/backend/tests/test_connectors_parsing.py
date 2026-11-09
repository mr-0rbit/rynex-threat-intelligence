"""Connector parser tests — pure functions, no network."""

from app.collectors.connectors.cisa_kev import parse_kev_record
from app.collectors.connectors.ransomware_live import parse_ransomwarelive_record
from app.collectors.connectors.threatfox import parse_threatfox_record
from app.collectors.connectors.urlhaus import parse_urlhaus_csv


class TestCisaKev:
    def test_valid_entry(self):
        entry = {
            "cveID": "CVE-2025-1234",
            "vendorProject": "Acme",
            "product": "Widget",
            "shortDescription": "RCE in Acme Widget",
            "dateAdded": "2025/01/15",
            "dueDate": "2025/02/05",
            "cvssScore": "9.8",
            "severity": "CRITICAL",
            "knownRansomwareCampaignUse": "Known",
        }
        parsed = parse_kev_record(entry)
        assert parsed is not None
        assert parsed["cve_id"] == "CVE-2025-1234"
        assert parsed["in_kev"] is True
        assert parsed["kev_known_ransomware_use"] is True
        assert parsed["cvss_base_score"] == 9.8
        assert parsed["kev_date_added"] is not None

    def test_invalid_cve_rejected(self):
        assert parse_kev_record({"cveID": "NOT-A-CVE"}) is None


class TestThreatFox:
    def test_ip_record(self):
        item = {
            "ioc": "185.220.101.45:443",
            "ioc_type": "ip:port",
            "malware": "win.bruteforce",
            "malware_printable": "Bruteforce",
            "confidence_level": 80,
            "first_seen": "2025-01-15 10:00:00 UTC",
            "id": "123",
        }
        parsed = parse_threatfox_record(item)
        assert parsed is not None
        assert parsed["value"] == "185.220.101.45"
        assert parsed["type"] == "ipv4"
        assert parsed["confidence"] == 0.8

    def test_defanged_url(self):
        item = {"ioc": "hxxp://evil[.]com/payload", "ioc_type": "url", "confidence_level": 90}
        parsed = parse_threatfox_record(item)
        assert parsed is not None
        assert parsed["value"].startswith("http://evil.com")

    def test_benign_domain_rejected(self):
        item = {"ioc": "https://mail.google.com/x", "ioc_type": "url"}
        assert parse_threatfox_record(item) is None

    def test_unsupported_type(self):
        assert parse_threatfox_record({"ioc": "x", "ioc_type": "filename"}) is None


class TestURLhaus:
    def test_csv_parsing(self):
        csv_text = (
            "# urlhaus recent URLs\n"
            "id,dateadded,url,url_status,threat,tags,urlhaus_link\n"
            '1,2025-01-15 10:00:00,hxxp://185.2.1.1/bins/x.sh,online,malware_download,"elf,sh",https://urlhaus.abuse.ch/browse/1/\n'
        )
        rows = parse_urlhaus_csv(csv_text)
        assert len(rows) == 1
        url, firstseen = rows[0]
        assert url.startswith("http://185.2.1.1/bins/x.sh")
        assert url in [r[0] for r in rows]

    def test_comment_lines_skipped(self):
        rows = parse_urlhaus_csv("# just a comment\n\n")
        assert rows == []


class TestRansomwareLive:
    def test_victim_claim(self):
        item = {
            "victim": "TestCorp Industries",
            "website": "https://testcorp.example.com",
            "group": "LockBit",
            "discovered": "2025-01-15 08:00:00",
            "country": "US",
            "activity": "Manufacturing",
            "description": "Database leak claim",
            "post_url": "https://example.group/victim",
        }
        parsed = parse_ransomwarelive_record(item)
        assert parsed is not None
        assert parsed["organization_name"] == "TestCorp Industries"
        # A group claim must never be classified as confirmed
        assert parsed["verification_status"] == "claimed"
        assert parsed["threat_actor_name"] == "LockBit"
        assert parsed["confidence"] <= 1.0
        assert parsed["fingerprint"]

    def test_fingerprint_stable_per_org_actor(self):
        item = {"victim": "Acme", "group": "LockBit", "discovered": "2025-01-15"}
        a = parse_ransomwarelive_record(item)
        b = parse_ransomwarelive_record(item)
        assert a["fingerprint"] == b["fingerprint"]

    def test_empty_victim_rejected(self):
        assert parse_ransomwarelive_record({"victim": ""}) is None
