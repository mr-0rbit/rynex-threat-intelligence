# RTIP Architecture

## 1. Overview

RTIP is a pipeline: **collect → normalize → validate → persist → correlate → alert → display**.
Accuracy beats volume; every record is traceable to its source; every score is explainable.

```
┌────────────────────────────────────────────────────────────────────┐
│ COLLECTORS (one async connector per source; isolated failure)      │
│   parse_*(pure functions) → CollectedRecord(kind, data, ...)       │
└──────────────┬─────────────────────────────────────────────────────┘
               ▼
┌────────────────────────────────────────────────────────────────────┐
│ INGESTION SERVICE                                                  │
│   dedupe (natural keys) · enrich · confidence scoring · alerting   │
└──────────────┬─────────────────────────────────────────────────────┘
               ▼
┌──────────────┐   ┌──────────────────┐   ┌───────────────────────────┐
│ PostgreSQL   │◄──│ FastAPI (v1 API) │◄──│ React dashboard (Phase 7) │
│ (normalized) │   │ JWT + RBAC       │   └───────────────────────────┘
└──────────────┘   └──────────────────┘
               ▲
┌──────────────┴─────────────────────────────────────────────────────┐
│ CELERY worker + beat on Redis (per-source schedules)               │
└────────────────────────────────────────────────────────────────────┘
```

## 2. Key decisions

| Decision | Rationale |
|---|---|
| Async connectors with per-host rate limiting (`app/collectors/http.py`) | Respect provider limits; a 429 triggers Retry-After backoff |
| Connectors yield `CollectedRecord`s; persistence is centralized | Parsing is testable without network; storage rules live in one place |
| Baseline runs suppress alerts (`run_collector`) | First run ingests history (e.g., 1,769 KEV entries) without flooding analysts |
| Fingerprint-based alert dedup + evidence hash | Same incident never re-alerts; *new evidence* bumps occurrence_count instead |
| Deterministic confidence engine (`services/confidence.py`) | Auditable reasons attached to every score; no opaque AI percentages |
| Breach verification ladder | `confirmed > reported > claimed > unverified`; `disputed` overrides; actor claims alone are always `claimed` |
| MISP-warning-list style allowlist | Prevents benign infrastructure (google.com etc.) from becoming false-positive alerts |
| UUID PKs + provenance columns on every intel table | Distributed-safe IDs; original URL/source/publication time always retained |
| API keys by env-var *name* in connectors (`api_key_setting`) | Values never in code or DB; per-source enable/disable in admin UI (Phase 9) |

## 3. Data model (Phase 2 scope)

- **users / audit_logs** — JWT auth, roles (admin/analyst/viewer), full audit trail.
- **intelligence_sources / collection_jobs** — registry + health: last success/failure, consecutive failures, records received/rejected/stored, checkpoints, avg duration.
- **iocs** — normalized value+type unique; platform confidence with reasons; source reputation kept separate; first/last seen; malware family; tags.
- **vulnerabilities** — CVE-anchored; CVSS, EPSS (Phase 4 enrichment), CISA KEV status; dedupe by CVE; enrichment never downgrades KEV status.
- **breach_incidents** — fingerprint dedup; org/domain/industry/region; threat-actor claim; claimed data types; verification ladder + confidence reasons; evidence references.
- **news_articles** — URL-hash dedup; publisher, published vs collected timestamps; categories/entities.
- **threat_actors / investigations** — Phase 6+ correlation targets.
- **alerts / alert_rules / watchlists / watchlist_items** — alert management core.

## 4. Security model

- **AuthN**: JWT access + refresh tokens (PyJWT), bcrypt (12 rounds).
- **AuthZ**: admin > analyst > viewer; collection triggers and user management restricted to admin/analyst.
- **Headers**: nosniff, DENY framing, no-referrer, Permissions-Policy; HSTS in production.
- **Untrusted input**: all feeds treated as hostile — size caps (20 MB), timeouts, strict Pydantic/regex validation, HTML stripped from summaries before storage.
- **SSRF posture**: collector destinations are code-defined, not user-defined. If user-configurable feeds are added (Phase 9), enforce allowlisted schemes, resolved-IP checks against private/metadata ranges, and redirect validation (`ALLOW_PRIVATE_NETWORK_SOURCES=false` default).
- **Secrets**: environment variables only; `intelligence_sources.api_key_setting` stores env-var names, never values.
- **Errors**: generic 500s to clients; details in structured JSON logs.

## 5. API surface (v1, implemented)

```
POST /api/v1/auth/login            POST /api/v1/auth/refresh
GET  /api/v1/auth/me               POST /api/v1/auth/users        (admin)
GET  /api/v1/dashboard/overview
GET  /api/v1/alerts                POST /api/v1/alerts/{id}/status (analyst+)
GET  /api/v1/sources               GET  /api/v1/sources/{slug}/jobs
POST /api/v1/sources/{slug}/collect (analyst+; manual trigger)
GET  /api/v1/iocs                  GET  /api/v1/vulnerabilities
GET  /api/v1/breaches              GET  /api/v1/news
GET  /api/health
```

All list endpoints support filtering, search (`q`), pagination (`limit`/`offset`), and require authentication.

## 6. Scaling notes

- Stateless API behind Nginx; Celery workers scale horizontally.
- Long feeds (NVD, EPSS) must move to streaming/segmented fetches before volume grows (tracked in ROADMAP).
- Correlation engine (Phase 6) runs on ingestion with entity normalization (org/domain/hash), backed by `investigations`.
