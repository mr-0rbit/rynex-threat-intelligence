# RTIP Development Roadmap

## Phase 1 — Architecture & design ✅
- [x] Architecture decision record (docs/ARCHITECTURE.md)
- [x] Directory structure, DB schema design, API surface
- [x] Source inventory & terms register (docs/SOURCES.md)

## Phase 2 — Backend, database, authentication ✅
- [x] FastAPI app, config via env, structured JSON logging
- [x] SQLAlchemy 2.0 async models (14 tables), UUID PKs, provenance columns
- [x] JWT auth (login/refresh/me), RBAC (admin/analyst/viewer), admin bootstrap
- [x] Audit logging on auth + user management
- [x] Security headers, error hygiene
- [x] 54 tests passing (unit + API integration)

## Phase 3 — Collector framework ✅
- [x] BaseCollector contract: job bookkeeping, retries, backoff, checkpoints
- [x] Async HTTP layer: per-host rate limiting, 429 Retry-After handling, size caps
- [x] Source registry with API-key resolution from env
- [x] Per-source health tracking (last success/failure, consecutive failures, counters)
- [x] Manual collection trigger via API

## Phase 4 — Threat intel & vulnerability collectors ✅ (first batch)
- [x] CISA KEV — **live-verified (1,769 records)**
- [x] URLhaus, Feodo Tracker — implemented
- [x] ThreatFox — implemented (requires free Auth-Key; graceful failure without)
- [ ] NVD 2.0 (needs pacing/streaming), FIRST EPSS (streaming gzip)
- [ ] OTX, AbuseIPDB, GreyNoise, PhishTank, urlscan, MISP feeds

## Phase 5 — Breach monitoring & news ✅ (first batch)
- [x] Ransomware.live — **live-verified (100 claims, `claimed` status enforced)**
- [x] News RSS ×6 — **live-verified (165 articles)**
- [ ] GDELT + Google News breach correlation
- [ ] Entity extraction (org/actor/CVE mentions) on news
- [ ] HIBP domain monitoring (commercial license — optional module)

## Phase 6 — Correlation, confidence, alert engine (partially done)
- [x] Deterministic confidence engine with reasons
- [x] Alert engine: rules, severity/confidence gates, fingerprint dedup, evidence-hash updates, baseline suppression
- [x] MISP-warning-list style allowlist for benign infrastructure
- [ ] Cross-source correlation → investigations
- [ ] Timeline generation, related-entity discovery

## Phase 7 — Frontend & dashboard ✅
- [x] React + TS + Vite + Tailwind (dark theme, #00D4FF), react-router, lucide icons
- [x] Login + protected app shell with sidebar, global search bar, footer policy notice
- [x] Dashboard: 6 live stat cards + 8 Recharts aggregates (all from real DB queries)
- [x] Alerts module: filters, status workflow, evidence expansion, pagination
- [x] Breach module: verification badges, actor claims, expandable confidence reasons
- [x] Vulnerability module: KEV filter, severity, CVSS/EPSS columns
- [x] IOC module: type filter, search, confidence bars
- [x] News module: search, publisher filter, original links
- [x] Sources module: health table, collection history, manual collect trigger
- [x] Global search results page across alerts/vulns/breaches/IOCs/news
- [ ] Vitest component tests, Playwright e2e

## Phase 8 — Notifications & dark web ✅ (core)
- [x] Telegram Bot API + SMTP email + generic webhook (config-gated, error-isolated)
- [x] Dispatch wired into alert creation; delivered channels recorded on alert
- [ ] Per-rule channel routing UI

## Phase 8b — Dark web monitoring ✅ (compliant design)
- [x] DarkWebGroupsCollector: 419 leak-site operator profiles via Ransomware.live (live-verified)
- [x] `/darkweb/overview` API: group registry, claims by actor/day, recent claims, policy notice
- [x] Dark Web dashboard page with scope notice and claims-vs-confirmed discipline
- [x] **Policy enforced in code**: no Tor/onion connectivity, no marketplaces, no stolen data storage
- [ ] Optional: vetted commercial dark-web API integrations (e.g. recorded-future type), keyword watchlists

## Phase 8c — Secure SDLC formalization ✅
- [x] SECURITY.md: threat model, mandatory dev gates, dark web handling policy
- [x] Security regression test suite: SQLi probes, JWT tampering, HTML stripping, report whitelisting, secret invariants
- [x] Dependency audits: pip-audit + npm audit clean (vite 5→8, react-router 6→7 upgraded; pip noted)
- [ ] CI pipeline wiring the audit + test gates

## Phase 9 — Reports, admin, search (partially done)
- [x] Reports: breaches/vulnerabilities/IOCs/alerts in JSON/CSV/Markdown with provenance note
- [x] Global search endpoint + UI
- [ ] PDF rendering, admin settings UI, source configuration wizard

## Phase 10 — Hardening & deployment
- [x] Frontend Dockerfile + nginx (API proxy, security headers, SPA fallback)
- [ ] Dependency vulnerability scanning (pip-audit, npm audit)
- [ ] Performance testing; Alembic initial migration committed; CI pipeline

## Known debt / risks
- EPSS gzip CSV (~30 MB) requires streaming ingest before enabling.
- NVD without API key: 5 req/30s — implement segmented pacing.
- docker compose plugin not installed in current dev machine; compose file provided and to be verified in Phase 10.
- Frontend bundle >500 kB warning — add code splitting.
- Docker deployment unverified on this machine (no compose plugin); dev mode verified end-to-end.
