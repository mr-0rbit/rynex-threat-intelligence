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

## Phase 7 — Frontend & dashboard
- [ ] React + TS + Vite + Tailwind + shadcn/ui scaffold (dark theme, #00D4FF)
- [ ] Dashboard overview + charts (Recharts) on real DB aggregates
- [ ] Live activity feed, alerts management, breach/vuln/IOC modules
- [ ] Vitest + Playwright tests

## Phase 8 — Notifications & AI assistance
- [ ] Telegram Bot API + SMTP + webhooks (+ optional Slack)
- [ ] Per-severity/category notification routing
- [ ] Optional LLM layer (summarize/extract, evidence-traceable, never confirms breaches)

## Phase 9 — Reports, admin UI, search
- [ ] PDF/CSV/JSON/Markdown reports with source references
- [ ] Admin settings: keys, schedules, thresholds, users, watchlists, audit logs
- [ ] Global search + source configuration wizard

## Phase 10 — Hardening & deployment
- [ ] Dependency vulnerability scanning (pip-audit, npm audit)
- [ ] Performance testing, Nginx reverse proxy config
- [ ] Alembic initial migration committed; CI pipeline

## Known debt / risks
- EPSS gzip CSV (~30 MB) requires streaming ingest before enabling.
- NVD without API key: 5 req/30s — implement segmented pacing.
- docker compose plugin not installed in current dev machine; compose file provided and to be verified in Phase 10.
- Frontend Dockerfile referenced by compose `full` profile — created in Phase 7.
