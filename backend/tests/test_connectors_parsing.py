"""Connector parser tests — pure functions, no network."""

from app.collectors.connectors.blocklist_de import parse_blocklistde_lines
from app.collectors.connectors.cisa_kev import parse_kev_record
from app.collectors.connectors.epss import parse_epss_csv
from app.collectors.connectors.misp import parse_misp_attribute
from app.collectors.connectors.nvd import parse_nvd_cve
from app.collectors.connectors.ransomware_live import parse_ransomwarelive_record
from app.collectors.connectors.threatfox import parse_threatfox_record
from app.collectors.connectors.urlhaus import parse_urlhaus_api_record


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
    def test_api_record_url(self):
        item = {
            "id": "123456",
            "url": "hxxp://185.2.1.1/bins/x.sh",
            "url_status": "online",
            "date_added": "2025-01-15 10:00:00",
            "threat": "malware_download",
            "tags": ["elf", "sh"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/browse/123456/",
        }
        parsed = parse_urlhaus_api_record(item)
        assert parsed is not None
        assert parsed["value"].startswith("http://185.2.1.1/bins/x.sh")
        assert parsed["type"] == "url"
        assert parsed["source_slug"] == "urlhaus"
        assert "elf" in parsed["tags"] and "malware_download" in parsed["tags"]
        assert parsed["last_seen_at"] is not None

    def test_invalid_url_rejected(self):
        assert parse_urlhaus_api_record({"url": "not a url"}) is None

    def test_empty_url_rejected(self):
        assert parse_urlhaus_api_record({"url": ""}) is None


class TestBlocklistDe:
    def test_ip_lines(self):
        text = "# comment\n1.2.3.4\n\n5.6.7.8\n1.2.3.4\nnot-an-ip\n"
        assert parse_blocklistde_lines(text) == ["1.2.3.4", "5.6.7.8"]

    def test_empty(self):
        assert parse_blocklistde_lines("") == []
        assert parse_blocklistde_lines("# only comments\n") == []


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

    def test_v2_record_with_domain_and_gang(self):
        item = {
            "victim": "TestCorp Industries",
            "domain": "testcorp.example.com",
            "claim_gang": "LockBit",
            "claim_url": "https://lockbit.example/victim",
            "date": "2025-09-15",
            "added": "2026-11-09",
            "country": "US",
            "summary": "Database leak claim",
            "has_infostealer_info": True,
            "link": "https://www.ransomware.live/id/abc",
        }
        parsed = parse_ransomwarelive_record(item)
        assert parsed is not None
        assert parsed["organization_domain"] == "testcorp.example.com"
        assert parsed["threat_actor_name"] == "LockBit"
        assert parsed["source_url"] == "https://lockbit.example/victim"
        assert parsed["reported_date"] is not None
        assert parsed["published_at"] is not None
        assert "infostealer logs claimed" in parsed["claimed_data_types"]
        assert parsed["verification_status"] == "claimed"

    def test_v2_unclaimed_gang_boolean_ignored(self):
        item = {
            "victim": "Cox",
            "domain": "coxs-japan.com",
            "claim_gang": False,
            "claim_url": False,
            "date": "2025-09-15",
            "added": "2026-11-09",
            "summary": "Media-reported breach",
        }
        parsed = parse_ransomwarelive_record(item)
        assert parsed is not None
        assert parsed["threat_actor_name"] is None
        assert parsed["organization_domain"] == "coxs-japan.com"
        # falls back to the ransomware.live victim page
        assert parsed["source_url"].startswith("https://www.ransomware.live/")


class TestMisp:
    def test_valid_ip_attribute(self):
        attr = {
            "uuid": "5e8f1a2b-1111-2222-3333-444455556666",
            "type": "ip-src",
            "value": "203.0.113.66",
            "category": "Network activity",
            "comment": "C2 node",
            "timestamp": "1735689600",
            "Tag": [{"name": "tlp:amber"}],
        }
        parsed = parse_misp_attribute(attr, event_tags=["misp-galaxy:ransomware"], source_url="https://misp.test/events/view/42")
        assert parsed is not None
        assert parsed["value"] == "203.0.113.66"
        assert parsed["type"] == "ipv4"
        assert parsed["source_slug"] == "misp"
        assert parsed["source_url"] == "https://misp.test/events/view/42"
        assert parsed["description"] == "C2 node"
        assert parsed["external_id"] == "5e8f1a2b-1111-2222-3333-444455556666"
        assert "misp" in parsed["tags"] and "tlp:amber" in parsed["tags"] and "misp-galaxy:ransomware" in parsed["tags"]
        assert parsed["last_seen_at"] is not None and parsed["last_seen_at"].year == 2025

    def test_ipv6_attribute_resolves(self):
        parsed = parse_misp_attribute({"type": "ip-dst", "value": "2001:0db8:0000:0000:0000:ff00:0042:8329", "timestamp": "1735689600"})
        assert parsed is not None
        assert parsed["type"] == "ipv6"

    def test_domain_and_hash_attributes(self):
        domain = parse_misp_attribute({"type": "domain", "value": "Malware-Evil.Example.COM/", "timestamp": "1735689600"})
        assert domain is not None
        assert domain["type"] == "domain" and domain["value"] == "malware-evil.example.com"

        sha = parse_misp_attribute({"type": "sha256", "value": "a" * 64})
        assert sha is not None and sha["type"] == "sha256"

        email = parse_misp_attribute({"type": "email-src", "value": "phish@bad.example"})
        assert email is not None and email["type"] == "email"

    def test_unmapped_and_invalid_rejected(self):
        assert parse_misp_attribute({"type": "filename", "value": "invoice.exe"}) is None
        assert parse_misp_attribute({"type": "ip-src", "value": ""}) is None
        assert parse_misp_attribute({"type": "ip-src", "value": "999.999.999.999"}) is None
        assert parse_misp_attribute({"type": "url", "value": "not-a-url"}) is None
        assert parse_misp_attribute("not-a-dict") is None

    def test_benign_domain_rejected(self):
        parsed = parse_misp_attribute({"type": "domain", "value": "mail.google.com"})
        assert parsed is None

    def test_combined_value_takes_first_token(self):
        parsed = parse_misp_attribute({"type": "domain", "value": "evil.example|203.0.113.9"})
        assert parsed is not None
        assert parsed["value"] == "evil.example"


class TestNVDParsing:
    def _cve_item(self):
        return {
            "id": "CVE-2025-7777",
            "published": "2025-01-15T10:00:00.000",
            "lastModified": "2025-02-01T12:30:00.000",
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseSeverity": "CRITICAL",
                        }
                    }
                ]
            },
            "descriptions": [
                {"lang": "es", "value": "spanish text"},
                {"lang": "en", "value": "A critical flaw in Acme Widget"},
            ],
            "references": [{"url": "https://nvd.example/advisory"}],
            "weaknesses": [
                {"description": [{"lang": "en", "value": "CWE-78"}]},
                {"description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"},
                                {"criteria": "cpe:2.3:a:acme:widget:1.1:*:*:*:*:*:*:*"},
                                {"criteria": "cpe:2.3:o:acmeos:kernel:5.0:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ],
        }

    def test_full_record(self):
        parsed = parse_nvd_cve(self._cve_item())
        assert parsed is not None
        assert parsed["cve_id"] == "CVE-2025-7777"
        assert parsed["cvss_base_score"] == 9.8
        assert parsed["severity"] == "critical"
        assert parsed["description"] == "A critical flaw in Acme Widget"
        assert parsed["cwes"] == ["CWE-78"]
        assert {"vendor": "acme", "product": "widget"} in parsed["affected_products"]
        assert {"vendor": "acmeos", "product": "kernel"} in parsed["affected_products"]
        assert len(parsed["affected_products"]) == 2  # deduped
        assert parsed["published_at"] is not None
        assert parsed["modified_at"] is not None
        assert parsed["in_kev"] is False
        assert parsed["source_slug"] == "nvd"

    def test_invalid_rejected(self):
        assert parse_nvd_cve({"id": "NOPE"}) is None
        assert parse_nvd_cve({}) is None


class TestEPSSParsing:
    def test_parse_bulk_csv_header_order_agnostic(self):
        csv_text = (
            "cve,epss,percentile,date\n"
            "CVE-2025-1111,0.91234,0.98765,2025-01-15\n"
            "NOT-A-CVE,0.5,0.5,2025-01-15\n"
            "CVE-2025-2222,,0.5,2025-01-15\n"
        )
        rows = parse_epss_csv(csv_text)
        assert len(rows) == 1
        assert rows[0]["cve_id"] == "CVE-2025-1111"
        assert rows[0]["epss_score"] == 0.91234
        assert rows[0]["enrichment_only"] is True
        assert rows[0]["source_slug"] == "epss"

    def test_parse_reordered_columns(self):
        csv_text = (
            "date,epss,cve,percentile\n"
            "2025-01-15,0.42,CVE-2025-3333,0.55\n"
        )
        rows = parse_epss_csv(csv_text)
        assert len(rows) == 1
        assert rows[0]["cve_id"] == "CVE-2025-3333"
        assert rows[0]["epss_score"] == 0.42
        assert rows[0]["epss_percentile"] == 0.55

    def test_empty_and_garbage(self):
        assert parse_epss_csv("") == []
        assert parse_epss_csv("garbage\nno header") == []
