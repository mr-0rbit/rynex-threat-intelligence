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

- **organizations / users / audit_logs** — tenant membership and role-based access; users, alerts, assets, cases, watchlists, and audit views are organization-scoped.
- **oidc_identities / oidc_login_states** — issuer/subject identity links and short-lived, browser-bound, one-use OIDC state with PKCE verifier.
- **taxii_objects / taxii_operations** — organization-scoped STIX 2.1 writes and durable TAXII operation status.
- **audit_chain_head** — persisted sequence/head for the HMAC-SHA256 audit chain.
- **intelligence_sources / collection_jobs** — registry + health: last success/failure, consecutive failures, records received/rejected/stored, checkpoints, avg duration.
- **iocs** — normalized value+type unique; platform confidence with reasons; source reputation kept separate; first/last seen; malware family; tags.
- **vulnerabilities** — CVE-anchored; CVSS, EPSS (Phase 4 enrichment), CISA KEV status; dedupe by CVE; enrichment never downgrades KEV status.
- **breach_incidents** — fingerprint dedup; org/domain/industry/region; threat-actor claim; claimed data types; verification ladder + confidence reasons; evidence references.
- **news_articles** — URL-hash dedup; publisher, published vs collected timestamps; categories/entities.
- **threat_actors / investigations** — Phase 6+ correlation targets.
- **alerts / alert_rules / watchlists / watchlist_items** — alert management core.

## 4. Security model

- **AuthN**: JWT access + refresh tokens (PyJWT), bcrypt (12 rounds). Refresh token is delivered as an `httpOnly` cookie scoped to `/api/v1/auth` (SameSite=Lax; `Secure` in production) and requires an `X-CSRF-Client` header; SPA keeps only the short-lived access token in memory.
- **Enterprise SSO**: OIDC authorization-code flow with browser-bound single-use state, PKCE S256, signed ID-token verification against issuer JWKS, audience/issuer/expiry/nonce checks, matching UserInfo subject, and verified-email requirement. JIT accounts default to `viewer`; production callback and issuer URLs must use HTTPS.
- **Password policy**: minimum 12 characters with upper, lower and digit (`validate_password_policy`).
- **Token revocation**: every JWT carries a `ver` claim matching the user's `token_version`; password change/reset bumps the version, instantly invalidating all outstanding tokens.
- **MFA**: TOTP (RFC 6238, pyotp). Login with MFA enabled returns a 5-minute `mfa_preauth` token that only `/auth/mfa/verify` accepts. Enrollment: `/auth/mfa/setup` → scan → `/auth/mfa/confirm` (still disabled until confirmed) → `/auth/mfa/disable` (requires a valid code).
- **Service API keys**: `X-API-Key: rtip_...` (hash-only storage in `api_tokens`, prefix display, inherits owner role, revocable, `last_used_at` tracked). Machine clients (SOAR/SIEM) use these instead of interactive JWTs.
- **Rate limiting**: Redis sorted-set sliding window on login/MFA-verify/reset endpoints, with an in-process fallback. Forwarded client IPs are accepted only from explicitly configured `TRUSTED_PROXY_CIDRS`.
- **Password reset**: hashed single-use tokens (30-min TTL), uniform 202 responses (no user enumeration), token-version bump on use. Dev-only inline token return when no SMTP is configured.
- **AuthZ and tenancy**: granular permissions are checked server-side; organization admins cannot cross tenant boundaries. Shared threat-intelligence records remain global, while operational alerting, assets, watchlists, cases, TAXII writes, and audit views are tenant-scoped. Platform-wide organization management is restricted to platform admins.
- **Audit trail**: all immutable record fields are HMAC-chained in sequence, and a separately persisted chain head is checked for edits, deletion, insertion, reordering, or truncation. Audit-write failures abort the caller's transaction; pre-migration legacy rows are reported as unverified.
- **Headers**: nosniff, DENY framing, no-referrer, Permissions-Policy; HSTS in production.
- **Untrusted input**: all feeds treated as hostile — size caps (20 MB), timeouts, strict Pydantic/regex validation, HTML stripped from summaries before storage.
- **SSRF posture**: collector destinations are code-defined, not user-defined. If user-configurable feeds are added (Phase 9), enforce allowlisted schemes, resolved-IP checks against private/metadata ranges, and redirect validation (`ALLOW_PRIVATE_NETWORK_SOURCES=false` default).
- **Secrets**: environment variables only; `intelligence_sources.api_key_setting` stores env-var names, never values. Production rejects placeholder JWT/audit/bootstrap secrets and SQLite. Kubernetes secrets are provisioned externally; see [`deploy-secrets.md`](deploy-secrets.md).
- **Errors**: generic 500s to clients; details in structured JSON logs.

## 5. API surface (v1, implemented)

```
POST /api/v1/auth/login            POST /api/v1/auth/refresh
GET  /api/v1/auth/oidc/login       POST /api/v1/auth/oidc/callback
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
GET  /api/v1/admin/audit-logs/verify (HMAC chain validation)
GET  /api/v1/admin/audit-logs/export (CEF & RFC 5424 syslog export)
GET/POST /api/v1/admin/organizations (platform admin)
GET  /api/v1/mitre/matrix          GET  /api/v1/mitre/techniques
GET  /api/v1/edl/ips | domains | urls | hashes (Firewall EDLs with ETag caching)
POST /api/v1/iocs/{id}/false-positive (Analyst false-positive revocation)
POST /api/v1/iocs/decay (Automated confidence decay cycle)
GET  /taxii2/                      (OASIS TAXII 2.1 Server Discovery)
GET  /taxii2/api1/                 (TAXII 2.1 API Root)
GET  /taxii2/api1/collections/     (TAXII 2.1 Collections)
GET  /taxii2/api1/collections/{id}/objects/ (STIX 2.1 Objects Bundle)
GET  /livez | /readyz | /healthz   (Enterprise Kubernetes health probes)
WS   /api/v1/ws/alerts             (?token=<access JWT>; live alert stream via Redis Pub/Sub)
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
- **MITRE ATT&CK Matrix**: 14 enterprise tactics mapped to platform telemetry, active indicators, and threat actor profiles.
- **Automated IOC Confidence Decay**: Time-decay engine continuously ages indicators (IPs half-life: 14 days, domains: 30 days, hashes: permanent), preventing firewall rule exhaustion.

## 7. Real-time and observability

- **WebSocket alerts** (`/api/v1/ws/alerts`): token-authenticated live stream fed by an enterprise **Redis Pub/Sub event bridge** (`services/events.py`). Celery workers and multi-replica API workers broadcast alerts cluster-wide with seamless local in-memory fallback.
- **Prometheus metrics** (`/api/v1/metrics`): record counts, alerts by severity, source health, job statuses. Scraped with a service API key.
- **Kubernetes Probes**: `/livez` for process responsiveness and `/readyz` for deep asynchronous dependency verification (PostgreSQL connectivity and Redis ping).
- **CI** (`.github/workflows/ci.yml`): ruff lint + pytest backend (128 tests passing); type-check + build frontend with page-level lazy chunks.

## 8. Enterprise Scaling & Cloud Architecture

- **Stateless API & Distributed Workers**: FastAPI API replicas scale horizontally behind Nginx or Kubernetes Ingress; Celery workers scale independently across worker pools.
- **Redis Pub/Sub Cluster Fan-Out**: Real-time push across all active WebSocket connections across multiple pods.
- **Distributed Rate Limiting**: Redis sorted-set sliding window rate limiter protects endpoints against credential stuffing and brute force.
- **Kubernetes manifests**: TLS ingress, probes, HPA and PodDisruptionBudgets are under `deploy/k8s/`. No credentials are checked in; provision the referenced `rtip-secrets` Secret from the approved secret manager before deployment and run Alembic migrations before scaling API replicas.
- **Cryptographic Audit Integrity**: HMAC-SHA256 hash chaining on all audit events with online verification and ArcSight CEF / RFC 5424 Syslog export for enterprise SIEMs.
