# RTIP Source Inventory & Terms Register

Every integrated source is recorded here with its access model and commercial-use status.
**No source is polled beyond its documented limits. Statuses are re-verified before any
commercial redistribution of source data.**

## Live-verified (2026-11-09)

| Source | Category | Auth | Commercial use | Notes |
|---|---|---|---|---|
| CISA KEV | Vulnerability / exploitation | none | Permitted (public domain) | 1,769 entries ingested live |
| Ransomware.live | Breach claims | optional key | **Verify before commercial use** | 100 victim claims ingested; stored as `claimed` only |
| Ransomware.live groups API | Dark web group profiles (metadata) | optional key | **Verify before commercial use** | 419 leak-site operator profiles ingested live; **metadata only — no onion connectivity exists in RTIP** |
| News RSS ×6 (The Hacker News, BleepingComputer, SecurityWeek, Dark Reading, KrebsOnSecurity, CISA advisories) | News | none | Attribution required; headline+summary+link only | 165 articles ingested live |

## Implemented

| Source | Category | Auth | Commercial use | Notes |
|---|---|---|---|---|
| abuse.ch URLhaus | IOC (URLs) | optional Auth-Key (free) | Permitted w/ attribution | recent feed; 5-min min interval |
| abuse.ch ThreatFox | IOC (multi-type) | **required** Auth-Key (free, auth.abuse.ch) | Fair-use; commercial may need paid API | API v1 @ threatfox-api.abuse.ch; IOCs expire 6 months at source |
| abuse.ch Feodo Tracker | IOC (C2 IPs) | none | Permitted w/ attribution | JSON blocklist |

## Pipeline (Phase 4–5)

| Source | Category | Auth | Commercial use | Notes |
|---|---|---|---|---|
| NVD 2.0 API | Vulnerability | optional key | Public domain | 5 req/30s without key — needs pacing |
| FIRST EPSS | Vulnerability enrichment | none | Permitted (open data) | gzipped CSV; needs streaming ingest |
| OSV.dev | Vulnerability | none | Permitted (Apache-2.0 data) | |
| GitHub Security Advisories | Vulnerability | free token | Verify GH terms | GraphQL; key required |
| MITRE ATT&CK STIX | Threat actors / techniques | none | Permitted | |
| OTX pulses | IOC / actors | free key | Community terms | per-user keys |
| AbuseIPDB | IP reputation | free key | Free tier limits; check terms | 1k checks/day free |
| GreyNoise | Internet scanning context | free key | Community terms | |
| PhishTank | Phishing URLs | free key | Attribution + non-commercial check | |
| urlscan.io | URL intelligence | free key | Verify terms | |
| MISP feeds / warning lists | IOC / allowlists | community | PerCommunity terms | warning lists also feed the allowlist engine |
| GDELT / Google News RSS | Breach news correlation | none | Verify terms | breach module Phase 5 |
| HIBP | Breach / exposure | paid API | **Commercial license required** | optional module only |
