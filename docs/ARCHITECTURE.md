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

- **AuthN**: JWT access + refresh tokens (PyJWT), bcrypt (12 rounds). Refresh token is delivered as an `httpOnly` cookie scoped to `/api/v1/auth` (SameSite=Lax; `Secure` in production) and requires an `X-CSRF-Client` header; SPA keeps only the short-lived access token in memory.
- **Password policy**: minimum 12 characters with upper, lower and digit (`validate_password_policy`).
- **Token revocation**: every JWT carries a `ver` claim matching the user's `token_version`; password change/reset bumps the version, instantly invalidating all outstanding tokens.
- **MFA**: TOTP (RFC 6238, pyotp). Login with MFA enabled returns a 5-minute `mfa_preauth` token that only `/auth/mfa/verify` accepts. Enrollment: `/auth/mfa/setup` → scan → `/auth/mfa/confirm` (still disabled until confirmed) → `/auth/mfa/disable` (requires a valid code).
- **Service API keys**: `X-API-Key: rtip_...` (hash-only storage in `api_tokens`, prefix display, inherits owner role, revocable, `last_used_at` tracked). Machine clients (SOAR/SIEM) use these instead of interactive JWTs.
- **Rate limiting**: in-process sliding window on login/MFA-verify/reset endpoints (`core/ratelimit.py`, settings-gated). Single-node stopgap; multi-node deployments front it with a shared limiter.
- **Password reset**: hashed single-use tokens (30-min TTL), uniform 202 responses (no user enumeration), token-version bump on use. Dev-only inline token return when no SMTP is configured.
- **AuthZ**: admin > analyst > viewer; collection triggers and user management restricted to admin/analyst. API-key auth maps onto the same RBAC via the owning user.
- **Audit trail**: security-relevant events (logins, MFA, password changes, asset/watchlist/case/key changes) recorded via `services/audit.py`; readable at `/admin/audit-logs`.
- **Headers**: nosniff, DENY framing, no-referrer, Permissions-Policy; HSTS in production.
- **Untrusted input**: all feeds treated as hostile — size caps (20 MB), timeouts, strict Pydantic/regex validation, HTML stripped from summaries before storage.
- **SSRF posture**: collector destinations are code-defined, not user-defined. If user-configurable feeds are added (Phase 9), enforce allowlisted schemes, resolved-IP checks against private/metadata ranges, and redirect validation (`ALLOW_PRIVATE_NETWORK_SOURCES=false` default).
- **Secrets**: environment variables only; `intelligence_sources.api_key_setting` stores env-var names, never values.
- **Errors**: generic 500s to clients; details in structured JSON logs.

## 5. API surface (v1, implemented)

```
POST /api/v1/auth/login            POST /api/v1/auth/refresh
GET  /api/v1/auth/me               POST /api/v1/auth/users        (admin)
POST /api/v1/auth/mfa/setup|confirm|disable   POST /api/v1/auth/mfa/verify
POST /api/v1/auth/change-password  POST /api/v1/auth/forgot-password|reset-password
GET  /api/v1/dashboard/overview
GET  /api/v1/alerts                POST /api/v1/alerts/{id}/status (analyst+)
GET  /api/v1/alerts/{id}/report.pdf (PDF case export; requires reportlab)
GET  /api/v1/sources               GET  /api/v1/sources/{slug}/jobs
POST /api/v1/sources/{slug}/collect (analyst+; manual trigger)
GET  /api/v1/iocs                  GET  /api/v1/vulnerabilities
GET  /api/v1/breaches              GET  /api/v1/breaches/{id}
GET  /api/v1/news                  GET  /api/v1/darkweb/overview
GET  /api/v1/search                GET  /api/v1/dashboard/charts
GET  /api/v1/reports/{type}        (json|csv|md)
GET  /api/v1/executive-report      (markdown executive summary)
GET  /api/v1/export/stix           (STIX 2.1 bundle)
GET  /api/v1/assets | POST/PATCH/DELETE /api/v1/assets[/{id}]  (writes: analyst+)
GET  /api/v1/watchlists | POST/DELETE /api/v1/watchlists[...]
GET  /api/v1/investigations | POST/PATCH/DELETE /api/v1/investigations[/{id}]
POST /api/v1/investigations/{id}/notes
GET  /api/v1/admin/api-keys | POST/DELETE /api/v1/admin/api-keys[/{id}]  (admin)
GET  /api/v1/admin/audit-logs      GET  /api/v1/admin/users        (admin)
GET  /api/v1/metrics               (Prometheus text exposition; auth required)
WS   /api/v1/ws/alerts             (?token=<access JWT>; live alert stream)
GET  /api/health
```

All list endpoints support filtering, search (`q`), pagination (`limit`/`offset`), and require authentication (JWT **or** service API key).

Optional sources with API keys (ThreatFox, URLhaus, MISP) appear in `/api/v1/sources` and are triggered manually; they report `misconfigured`/failing when their key is absent rather than crashing the pipeline.

## 6. Intelligence depth: assets, watchlists, corroboration

- **Asset inventory** (`assets` table): domains, IPs/CIDRs, products, vendors, keywords with criticality. Ingestion matches every stored record against enabled assets; an asset match **escalates severity** (floor: high; critical assets → critical) and names the asset inside the alert payload (`matched_assets`).
- **Watchlists** (`watchlists` / `watchlist_items`): organizations, domains, actors, CVEs, keywords. Matches raise dedicated `watchlist_mention` alerts (fingerprint `watch:<value>`) that dedupe across intel kinds — a breach claim and an IOC naming the same org collapse into one alert with occurrence counts.
- **Corroboration**: distinct source slugs reporting the same (value, type) IOC accumulate in `iocs.corroborating_sources` and deterministically re-score platform confidence (`services/confidence.py`).
- **Alert rules in DB**: rows in `alert_rules` override built-in defaults — operators tune thresholds without code changes.
- **Enrichment-only feeds**: EPSS bulk data updates `epss_score` on tracked CVEs and never inserts bare rows; high-EPSS (≥ 0.5) tracked CVEs raise `high_epss_vulnerability` alerts (fingerprint `epss:<cve>`).
- **NVD connector**: incremental via `lastModStartDate/lastModEndDate` with real checkpoint persistence (last successful job's checkpoint is reused); optional API key raises rate limits.

## 7. Real-time and observability

- **WebSocket alerts** (`/api/v1/ws/alerts`): token-authenticated live stream fed by an in-process pub/sub bus (`services/events.py`). Single-worker deployments get true push; **multi-worker deployments need a Redis pub/sub bridge** so every replica receives all events (ingestion and API run in different processes).
- **Prometheus metrics** (`/api/v1/metrics`): record counts, alerts by severity, source health, job statuses. Scraped with a service API key.
- **CI** (`.github/workflows/ci.yml`): ruff lint + pytest backend; type-check + build frontend.

- Stateless API behind Nginx; Celery workers scale horizontally.
## 8. Scaling notes

- Stateless API behind Nginx; Celery workers scale horizontally.
- WebSocket fan-out needs a Redis pub/sub bridge when running multiple API workers (single-worker default gets push directly).
- Rate limiting is in-process; put a shared limiter in front (nginx/Envoy) or add a Redis-backed store for multi-node.
- Correlation engine (Phase 6) runs on ingestion with entity normalization (org/domain/hash), backed by `investigations`.
- **Known boundaries** (deliberate, documented): OIDC/SAML SSO requires a real IdP to build and verify against; Helm/k8s HA packaging requires a cluster; full multi-tenancy is an architecture-wide change tracked separately.
