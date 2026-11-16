"""MITRE ATT&CK Enterprise Matrix service.

Standardizes threat actor profiles, vulnerabilities, and indicators against
the MITRE ATT&CK framework (v14+ Enterprise Matrix).
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class MitreTactic:
    id: str  # e.g. TA0001
    name: str  # Initial Access
    description: str


@dataclass
class MitreTechnique:
    id: str  # e.g. T1190
    name: str  # Exploit Public-Facing Application
    tactic_id: str
    description: str
    detection: str
    mitigation: str


# 14 Standard Enterprise Tactics
TACTICS: list[dict[str, str]] = [
    {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering victim information."},
    {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources (infrastructure, accounts)."},
    {"id": "TA0001", "name": "Initial Access", "description": "Getting into your network."},
    {"id": "TA0002", "name": "Execution", "description": "Running malicious code."},
    {"id": "TA0003", "name": "Persistence", "description": "Maintaining access."},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Gaining higher-level permissions."},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Avoiding detection."},
    {"id": "TA0006", "name": "Credential Access", "description": "Stealing account credentials."},
    {"id": "TA0007", "name": "Discovery", "description": "Exploring your environment."},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Moving through your environment."},
    {"id": "TA0009", "name": "Collection", "description": "Gathering data of interest."},
    {"id": "TA0011", "name": "Command and Control", "description": "Communicating with compromised systems."},
    {"id": "TA0010", "name": "Exfiltration", "description": "Stealing data."},
    {"id": "TA0040", "name": "Impact", "description": "Disrupting, destroying, or encrypting systems and data."},
]

# Core Enterprise Techniques with detection and mitigation
TECHNIQUES: list[dict[str, Any]] = [
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic_id": "TA0001",
        "description": "Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or system.",
        "detection": "Monitor application logs for abnormal requests and web application firewall (WAF) alerts.",
        "mitigation": "Regular vulnerability scanning, automated patch management (CISA KEV), and network segmentation.",
        "intel_link": "cisa_kev",
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic_id": "TA0001",
        "description": "Adversaries may send phishing messages with malicious attachments or links.",
        "detection": "Inspect inbound email for suspicious attachments, spoofed senders, and malicious URLs.",
        "mitigation": "Anti-spoofing technologies (DMARC, DKIM, SPF) and URL reputation filtering.",
        "intel_link": "urlhaus",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic_id": "TA0001",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "detection": "Monitor authentication logs for impossible travel, unusual times, or rapid failed logins.",
        "mitigation": "Enforce Multi-Factor Authentication (MFA) and strong password policies.",
        "intel_link": "breaches",
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, bash, Python) to execute commands.",
        "detection": "Enable process command-line logging and script block logging.",
        "mitigation": "Disable unneeded interpreters and enforce script execution policies.",
        "intel_link": "iocs",
    },
    {
        "id": "T1203",
        "name": "Exploitation for Client Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may exploit vulnerabilities in client applications to execute code.",
        "detection": "Monitor process creation spawned by browsers, document viewers, and email clients.",
        "mitigation": "Enforce software update cycles and application sandboxing.",
        "intel_link": "vulnerabilities",
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Adversaries may exploit vulnerabilities to gain higher system permissions.",
        "detection": "Monitor system kernel calls and privilege changes.",
        "mitigation": "Patch management of operating systems and kernel services.",
        "intel_link": "cisa_kev",
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic_id": "TA0006",
        "description": "Adversaries may use brute force techniques to attempt credential guessing.",
        "detection": "Detect repeated authentication failures from specific IP addresses.",
        "mitigation": "Account lockout thresholds and automated IP rate-limiting blocklists.",
        "intel_link": "blocklist_de",
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to avoid detection.",
        "detection": "Analyze network traffic for beaconing, unusual user-agent strings, and self-signed certificates.",
        "mitigation": "Network intrusion detection systems (NIDS) and C2 indicator blocklists.",
        "intel_link": "feodo",
    },
    {
        "id": "T1567",
        "name": "Exfiltration Over Web Service",
        "tactic_id": "TA0010",
        "description": "Adversaries may exfiltrate data to a cloud storage or web service (Mega, Dropbox, Telegram).",
        "detection": "Monitor high-volume outbound data transfers to public cloud storage and paste sites.",
        "mitigation": "Cloud Access Security Broker (CASB) policies and egress filtering.",
        "intel_link": "ransomware_claims",
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries may encrypt data on target systems to interrupt availability and extort victims.",
        "detection": "Monitor high I/O disk writes, mass file renaming, and volume shadow copy deletions.",
        "mitigation": "Immutable off-site backups, least-privilege file permissions, and anti-ransomware EDR protection.",
        "intel_link": "ransomware_claims",
    },
    {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic_id": "TA0040",
        "description": "Adversaries may delete or disable operating system recovery features (e.g. vssadmin delete shadows).",
        "detection": "Detect execution of vssadmin, bcdedit, or wbadmin commands by unauthorized users.",
        "mitigation": "Protect local backup repositories and restrict administrative recovery commands.",
        "intel_link": "ransomware_claims",
    },
]

# Threat Actor ATT&CK Mapping
ACTOR_MAPPINGS: dict[str, list[str]] = {
    "lockbit": ["T1190", "T1078", "T1059", "T1486", "T1490", "T1567"],
    "alphv": ["T1190", "T1566", "T1059", "T1486", "T1567"],
    "blackcat": ["T1190", "T1566", "T1059", "T1486", "T1567"],
    "akira": ["T1190", "T1078", "T1486", "T1567"],
    "cl0p": ["T1190", "T1068", "T1567"],
    "play": ["T1190", "T1078", "T1486", "T1490"],
    "bianlian": ["T1190", "T1078", "T1567"],
    "rhysida": ["T1566", "T1059", "T1486"],
    "8base": ["T1566", "T1078", "T1486"],
}


def get_actor_techniques(actor_name: str | None) -> list[dict[str, Any]]:
    if not actor_name:
        return []
    key = actor_name.lower().replace(" ", "").replace("-", "")
    for mapped_key, tech_ids in ACTOR_MAPPINGS.items():
        if mapped_key in key or key in mapped_key:
            return [t for t in TECHNIQUES if t["id"] in tech_ids]
    # Default ransomware profile if name indicates a gang
    return [t for t in TECHNIQUES if t["id"] in ("T1486", "T1567", "T1190")]


def get_mitre_matrix() -> list[dict[str, Any]]:
    """Build the full ATT&CK Matrix layout with grouped techniques."""
    tech_by_tactic: dict[str, list[dict[str, Any]]] = {}
    for tech in TECHNIQUES:
        tech_by_tactic.setdefault(tech["tactic_id"], []).append(tech)

    matrix = []
    for tactic in TACTICS:
        matrix.append({
            "tactic": tactic,
            "techniques": tech_by_tactic.get(tactic["id"], []),
        })
    return matrix
