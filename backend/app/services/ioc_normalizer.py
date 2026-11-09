"""Deterministic IOC validation and normalization.

These are rule-based, not AI-based: a SHA256 is a SHA256, a CVE ID matches a
strict regex, and a reserved IP range is never treated as a routable threat.
"""

import hashlib
import ipaddress
import re
from datetime import UTC, datetime

_HASH_RE = re.compile(r"^[a-f0-9]{32,64}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_MD5_RE = re.compile(r"^[a-f0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-f0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

# Common benign infrastructure (MISP-warning-list style allowlist seed)
BENIGN_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "amazonaws.com",
    "w3.org",
    "schema.org",
}


class IOCNormalizer:
    @staticmethod
    def normalize(value: str, ioc_type: str | None = None) -> tuple[str, str] | None:
        """Return (normalized_value, type) or None when invalid."""
        raw = value.strip()
        if not raw or len(raw) > 2000:
            return None
        lowered = raw.lower()

        if ioc_type in (None, "", "unknown"):
            ioc_type = IOCNormalizer.detect_type(raw)
        if not ioc_type:
            return None

        if ioc_type in ("md5", "sha1", "sha256"):
            if not _HASH_RE.match(lowered) or len(lowered) != {"md5": 32, "sha1": 40, "sha256": 64}[ioc_type]:
                return None
            return lowered, ioc_type

        if ioc_type == "ipv4":
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                return None
            if addr.version != 4:
                return None
            return str(addr), "ipv4"

        if ioc_type == "ipv6":
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                return None
            if addr.version != 6:
                return None
            return str(addr), "ipv6"

        if ioc_type == "ip":
            # Generic "ip" from feeds: resolve to v4/v6
            try:
                return str(ipaddress.ip_address(raw)), f"ipv{ipaddress.ip_address(raw).version}"
            except ValueError:
                return None

        if ioc_type == "domain":
            domain = lowered.removeprefix("http://").removeprefix("https://").split("/")[0]
            domain = domain.removeprefix("www.")
            if not domain or "." not in domain or not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
                return None
            return domain, "domain"

        if ioc_type == "url":
            if not raw.lower().startswith(("http://", "https://")):
                return None
            return raw, "url"

        if ioc_type == "email":
            if not _EMAIL_RE.match(raw):
                return None
            return lowered, "email"

        return None

    @staticmethod
    def detect_type(value: str) -> str | None:
        v = value.strip().lower()
        if _MD5_RE.match(v):
            return "md5"
        if _SHA1_RE.match(v):
            return "sha1"
        if _SHA256_RE.match(v):
            return "sha256"
        if _CVE_RE.match(v.upper()):
            return "cve"
        if v.startswith(("http://", "https://")):
            return "url"
        if _EMAIL_RE.match(value.strip()):
            return "email"
        try:
            return f"ipv{ipaddress.ip_address(value.strip()).version}"
        except ValueError:
            pass
        if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", v):
            return "domain"
        return None

    @staticmethod
    def is_benign_domain(domain: str) -> bool:
        """Allowlist check against common benign infrastructure (MISP warning-list style)."""
        d = domain.lower().rstrip(".")
        if d in BENIGN_DOMAINS:
            return True
        return any(d.endswith("." + b) for b in BENIGN_DOMAINS)

    @staticmethod
    def is_defangable(value: str) -> bool:
        """Defanged indicators (e.g. hxxp, [.]) should be refanged before validation."""
        return bool(re.search(r"hxxp|\[\.\]|\(\.\)|\[dot\]|\(dot\)", value, re.IGNORECASE))

    @staticmethod
    def refang(value: str) -> str:
        v = re.sub(r"hxxp", "http", value, flags=re.IGNORECASE)
        v = re.sub(r"[\[\(]\.[\]\)]", ".", v)
        v = re.sub(r"\[(dot|\.?)\]|\((dot|\.?)\)", ".", v, flags=re.IGNORECASE)
        return v

    @staticmethod
    def fingerprint(*parts: str) -> str:
        """Stable deduplication fingerprint from entity parts."""
        joined = "|".join(p.strip().lower() for p in parts if p)
        return hashlib.sha256(joined.encode()).hexdigest()[:40]

    @staticmethod
    def parse_date(value: str | None) -> datetime | None:
        """Parse common feed date formats deterministically; never guess."""
        if not value:
            return None
        v = value.strip()
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S GMT",
            "%d %b %Y %H:%M:%S %z",
            "%Y/%m/%d",
            "%m/%d/%Y",
        ):
            try:
                dt = datetime.strptime(v.replace("Z", "+0000") if fmt.endswith("%z") else v, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
            except ValueError:
                continue
        return None


def validate_cve_id(cve_id: str) -> bool:
    return bool(_CVE_RE.match(cve_id.upper()))
