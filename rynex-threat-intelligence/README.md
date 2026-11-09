# RYNEX THREAT INTELLIGENCE PLATFORM (RTIP)

**DETECT. ANALYZE. RESPOND.**

A centralized, continuously updated Cyber Threat Intelligence platform for Rynex Technologies. RTIP aggregates intelligence from legitimate, publicly accessible free/community-tier sources, correlates it, scores confidence transparently, and generates deduplicated, actionable alerts.

> **Status: Phases 1–8 core complete, live-verified.** Real intelligence flows from CISA KEV (1,700+ vulnerabilities), Ransomware.live (breach claims), and 6 security news RSS feeds. Full React dashboard operational. See [docs/ROADMAP.md](docs/ROADMAP.md).

## What runs today

| Capability | Status |
|---|---|
| FastAPI backend with JWT auth + RBAC (admin/analyst/viewer) | ✅ Tested |
| Normalized PostgreSQL schema (SQLAlchemy 2.0, Alembic-ready) | ✅ Tested |
| Collector framework (async, retries, backoff, rate limits, checkpoints, per-source health) | ✅ Tested |
| CISA KEV collector — **verified against live feed** | ✅ Live |
| Ransomware.live breach collector — **verified against live feed** (claims only) | ✅ Live |
| Security news RSS (HN, BleepingComputer, SecurityWeek, Dark Reading, Krebs, CISA) — **verified live** (165 articles) | ✅ Live |
| URLhaus, Feodo Tracker collectors | ✅ Implemented |
| ThreatFox collector (requires free Auth-Key) | ✅ Implemented |
| Confidence engine (deterministic, explainable) | ✅ Tested |
| Alert engine (rule-based, fingerprint dedup, baseline suppression) | ✅ Tested |
| Celery beat scheduling | ✅ Configured |
| Dashboard charts + global search + reports (JSON/CSV/Markdown) | ✅ Tested |
| Notifications: Telegram, SMTP email, webhooks | ✅ Implemented (config-gated) |
| **React dashboard** (dark theme, #00D4FF, Recharts, full alert/breach/vuln/IOC/news/source modules) | ✅ Built |
| Docker Compose (Postgres, Redis, API, worker, beat, frontend/nginx) | ✅ Provided |
| PDF reports, correlation→investigations UI, MISP feeds | ⏳ Remaining polish |

## Quick start (development)

```bash
cp .env.example .env            # then edit secrets

# Backend
cd backend
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/uvicorn app.main:app --reload
# API docs: http://localhost:8000/api/docs

# Frontend (separate terminal)
cd frontend
npm install && npm run dev
# Dashboard: http://localhost:5173
```

Default admin (dev only): `admin@rynex.local` / `ChangeMeNow!2024` — **change immediately**.

## Quick start (Docker Compose)

```bash
cp .env.example .env    # set POSTGRES_PASSWORD and JWT_SECRET_KEY
docker compose up --build
```

## Collect real intelligence now

```bash
cd backend
.venv/bin/python scripts/live_smoke.py cisa-kev
.venv/bin/python scripts/live_smoke.py security-news-rss
.venv/bin/python scripts/live_smoke.py ransomware-live
```

## Tests

```bash
cd backend && .venv/bin/python -m pytest tests/ -v
```

## Intelligence policy

- **No fake data.** Every record originates from a named source with provenance (source slug, URL, timestamps).
- **Ransomware claims are never auto-confirmed.** Verification statuses: `confirmed | reported | claimed | unverified | disputed` — a leak-site listing is always `claimed`.
- **Baseline suppression**: the first successful collection from a source ingests history without generating alerts, so analysts aren't flooded by backlogs.
- **Confidence is explainable**: every score ships with human-readable reasons; allowlisted benign infrastructure is down-weighted; AI never invents evidence (Phase 8+).
- **Terms respected**: per-source commercial-use status and terms are recorded in `docs/SOURCES.md` and in the `intelligence_sources` table. Keyed sources are optional and degrade gracefully.

## Security

JWT auth with role-based access control, bcrypt password hashing, security headers, strict input validation (Pydantic), per-source rate limiting, response size caps, and SSRF-safe outbound collection (config-only destinations, no user-supplied feed URLs without validation). See `docs/ARCHITECTURE.md` § Security.
