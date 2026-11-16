<div align="center">

# RYNEX THREAT INTELLIGENCE PLATFORM (RTIP)

### `DETECT.` &nbsp; `ANALYZE.` &nbsp; `RESPOND.`

**A centralized, continuously updated Cyber Threat Intelligence platform for Rynex Technologies.**

![Status](https://img.shields.io/badge/status-implemented%20%26%20tested-2ea44f?style=for-the-badge)
![Tests](https://img.shields.io/badge/tests-128%20passing-00D4FF?style=for-the-badge)
![Fake Data](https://img.shields.io/badge/fake%20data-none-critical?style=for-the-badge)
![CI](https://github.com/mr-0rbit/rynex-threat-intelligence/actions/workflows/ci.yml/badge.svg?branch=master)

![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-D71F00?style=flat-square)
![Alembic](https://img.shields.io/badge/Alembic-migrations-4A4A4A?style=flat-square&logo=alembic&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-37814A?style=flat-square&logo=celery&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=redis&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=flat-square&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat-square&logo=vite&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-auth-000000?style=flat-square&logo=jsonwebtokens&logoColor=white)
![Docker](https://img.shields.io/badge/Docker%20Compose-2496ED?style=flat-square&logo=docker&logoColor=white)

[Quick Start](#quick-start) · [Full Setup Guide](#full-setup-guide) · [Features](#what-runs-today) · [Leak Monitoring](#company-leak-monitoring-first-to-know) · [Architecture](#architecture) · [Intelligence Policy](#intelligence-policy) · [Security](#security)

</div>

---

## Overview

RTIP aggregates intelligence from **legitimate, publicly accessible free/community-tier sources**, correlates it, **scores confidence transparently**, and generates **deduplicated, actionable alerts** - so analysts spend time on threats, not on noise.

> **Status: implemented and tested.** The platform ingests and correlates live public threat intelligence. Record counts vary by deployment and collection time, so this README does not treat a local database snapshot as a current platform-wide total. The backend suite has **128 passing tests**; the React dashboard is operational.

### Why RTIP?

<table width="100%">
  <tr><th width="25%">Feature</th><th width="75%">What it means</th></tr>
  <tr><td><b>Real data only</b></td><td>Every record has a named source, URL and timestamps. No fabricated intel.</td></tr>
  <tr><td><b>Explainable scoring</b></td><td>Each confidence score ships with human-readable reasons.</td></tr>
  <tr><td><b>Low noise</b></td><td>Fingerprint deduplication and first-run baseline suppression.</td></tr>
  <tr><td><b>Terms-respecting</b></td><td>Per-source commercial-use status and terms are tracked.</td></tr>
  <tr><td><b>Resilient collection</b></td><td>Async collectors with retries, backoff, rate limits, checkpoints and health.</td></tr>
</table>

---

## What Runs Today

### Core Platform

<table width="100%">
  <tr><th width="72%">Capability</th><th width="28%">Status</th></tr>
  <tr><td>FastAPI backend with JWT authentication, organization-scoped authorization and platform-admin controls</td><td align="center">Tested</td></tr>
  <tr><td>Normalized PostgreSQL schema (SQLAlchemy 2.0; Alembic head <code>72d4cb69a113</code>)</td><td align="center">Tested</td></tr>
  <tr><td>Collector framework (async, retries, backoff, rate limits, checkpoints, per-source health)</td><td align="center">Tested</td></tr>
  <tr><td>Deterministic confidence engine (no AI inside the score)</td><td align="center">Tested</td></tr>
  <tr><td>Alert engine (rule-based, fingerprint dedup, baseline suppression, DB-override rules)</td><td align="center">Tested</td></tr>
  <tr><td>Organization tenancy, OIDC SSO, STIX 2.1 / TAXII 2.1, firewall EDLs and MITRE ATT&amp;CK views</td><td align="center">Tested</td></tr>
  <tr><td>Asset inventory + watchlists with severity escalation</td><td align="center">Live verified</td></tr>
  <tr><td>WebSocket live alert bus</td><td align="center">Live verified</td></tr>
  <tr><td>Celery worker + beat scheduling, Redis-backed events and Prometheus metrics</td><td align="center">Implemented</td></tr>
</table>

### Intelligence Sources

<table width="100%">
  <tr><th width="45%">Source</th><th width="35%">Type</th><th width="20%">Status</th></tr>
  <tr><td><b>CISA KEV</b></td><td>Known exploited vulnerabilities</td><td align="center">Live</td></tr>
  <tr><td><b>Ransomware.live</b> v2 API</td><td>Breach claims (claims only; not independently verified)</td><td align="center">Live</td></tr>
  <tr><td><b>blocklist.de</b></td><td>Abuse / brute-force IPs</td><td align="center">Live</td></tr>
  <tr><td><b>Feodo Tracker</b></td><td>C2 server IPs (banking trojans)</td><td align="center">Live</td></tr>
  <tr><td><b>Ransomware.live groups API</b></td><td>Operator profile metadata only; RTIP does not connect to onion sites</td><td align="center">Live</td></tr>
  <tr><td><b>Security News RSS</b> - The Hacker News, BleepingComputer, SecurityWeek, Dark Reading, KrebsOnSecurity, CISA</td><td>News</td><td align="center">Live</td></tr>
  <tr><td><b>NVD</b>, <b>EPSS</b></td><td>CVE + exploitation probability</td><td align="center">Implemented</td></tr>
  <tr><td><b>URLhaus</b> <i>(needs free abuse.ch key)</i></td><td>Malicious URLs</td><td align="center">Implemented</td></tr>
  <tr><td><b>ThreatFox</b> <i>(needs free abuse.ch key)</i></td><td>IOCs</td><td align="center">Implemented</td></tr>
  <tr><td><b>MISP feeds</b></td><td>Private/community feeds</td><td align="center">Implemented (config-gated)</td></tr>
</table>

> Keyed sources degrade gracefully: without a key they report <code>misconfigured</code>/<code>degraded</code> in the sources UI instead of crashing the pipeline. Free abuse.ch keys: <a href="https://auth.abuse.ch/">https://auth.abuse.ch/</a>
>
> The counts shown by the application are deployment-specific. A ransomware leak-site post is stored as a **claim**, not proof that a breach occurred; group profiles are metadata and do not imply access to dark-web sites.

### Security and Access

<table width="100%">
  <tr><th width="72%">Capability</th><th width="28%">Status</th></tr>
  <tr><td>TOTP multi-factor authentication</td><td align="center">Live verified</td></tr>
  <tr><td>Login rate limiting (per-IP sliding window, 429 responses)</td><td align="center">Live verified</td></tr>
  <tr><td>Immutable audit log of admin/analyst actions</td><td align="center">Live verified</td></tr>
  <tr><td>Revocable API tokens</td><td align="center">Live verified</td></tr>
  <tr><td>Refresh-token rotation with reuse detection</td><td align="center">Live verified</td></tr>
</table>

### Analyst Experience

<table width="100%">
  <tr><th width="72%">Capability</th><th width="28%">Status</th></tr>
  <tr><td>React dashboard - dark theme, <code>#00D4FF</code> accent, Recharts; alert / breach / vuln / IOC / news / source modules</td><td align="center">Built</td></tr>
  <tr><td>Dashboard charts + global search</td><td align="center">Tested</td></tr>
  <tr><td>MITRE ATT&amp;CK matrix, integrations, assets, investigations and account/security settings</td><td align="center">Built</td></tr>
  <tr><td>Reports: JSON / CSV / Markdown / PDF</td><td align="center">Built</td></tr>
  <tr><td>Correlation to Investigations UI</td><td align="center">Built</td></tr>
  <tr><td>Metrics + admin endpoints</td><td align="center">Built</td></tr>
  <tr><td>Notifications: Telegram, SMTP email, webhooks</td><td align="center">Implemented (config-gated)</td></tr>
  <tr><td>Docker Compose (Postgres, Redis, API, worker, beat, frontend/nginx)</td><td align="center">Provided</td></tr>
</table>

---

## Company Leak Monitoring ("First to Know")

RTIP watches leak sites continuously so the organization hears about its own breach from the platform first:

```
Ransomware group posts victim
        |
Ransomware.live indexes it   (polled every 20 min)
        |
RTIP ingests victim + domain + gang claim
        |
Matched against YOUR registered assets and watchlists?
        |
Severity-escalated alert - WebSocket banner + alert row naming the matched asset
```

- **Assets** - register owned domains, IP ranges (CIDR), product names with criticality. Intel touching them raises severity to a `high`/`critical` floor and names the asset in the alert.
- **Watchlists** - `organization` (exact match), `domain`, `actor`, `cve`, `keyword` items raise dedicated `watchlist_mention` alerts.
- A matching leak-site post is still an **unverified claim**. Configure assets and watchlists to raise alert severity and surface the match; investigate and validate the underlying claim separately.

---

## Architecture

```mermaid
flowchart LR
    subgraph Sources["Public Intel Sources"]
        A[CISA KEV]
        B[Ransomware.live]
        C[blocklist.de / Feodo / URLhaus / ThreatFox]
        D[Dark web actor groups]
        E[Security News RSS]
        F[NVD / EPSS]
    end

    subgraph Core["RTIP Backend"]
        G[Async Collectors<br/>retry · backoff · rate limit]
        H[(PostgreSQL)]
        I[Confidence Engine<br/>deterministic]
        J[Asset / Watchlist Matching<br/>severity escalation]
        K[Alert Engine<br/>dedup · baseline suppression]
        L[Correlation / Investigations]
    end

    M[Celery Beat + Worker]
    N[FastAPI + JWT/RBAC/MFA]
    O[React Dashboard]
    P[WebSocket Live Feed]
    Q[Telegram · Email · Webhooks]
    R[Reports<br/>JSON · CSV · MD · PDF]

    Sources --> G --> H
    M -. schedules .-> G
    H --> I --> J --> K --> P
    K --> Q
    H --> L
    H --> N --> O
    N --> R
```

Full details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Live Collection Schedule

<table width="100%">
  <tr><th width="60%">Source</th><th width="40%">Interval</th></tr>
  <tr><td>IOC feeds (URLhaus, Feodo)</td><td>every 15 min</td></tr>
  <tr><td>ThreatFox</td><td>hourly at :05</td></tr>
  <tr><td>CISA KEV</td><td>hourly at :10</td></tr>
  <tr><td>Ransomware.live</td><td>hourly at :20</td></tr>
  <tr><td>blocklist.de</td><td>hourly at :25</td></tr>
  <tr><td>Security news RSS</td><td>every 10 min</td></tr>
  <tr><td>Dark web actor groups</td><td>every 12 h</td></tr>
  <tr><td>NVD</td><td>hourly at :35 UTC</td></tr>
  <tr><td>EPSS enrichment</td><td>daily at 04:10 UTC</td></tr>
</table>

---

## Full Setup Guide

### Prerequisites

<table width="100%">
  <tr><th width="30%">Component</th><th width="25%">Minimum version</th><th width="45%">Notes</th></tr>
  <tr><td>Linux or macOS</td><td>Debian/Ubuntu/Kali tested</td><td>Any Unix-like system works</td></tr>
  <tr><td>Python</td><td>3.12</td><td>Backend runtime + Alembic + Celery</td></tr>
  <tr><td>Node.js + npm</td><td>20.19+ or 22.12+</td><td>Frontend build (Vite 8; Node 22.12+ recommended)</td></tr>
  <tr><td>Redis</td><td>7</td><td>Task broker + WebSocket event bus backend</td></tr>
  <tr><td>Git</td><td>2.30</td><td>To clone the repository</td></tr>
  <tr><td>Docker + Compose</td><td>24 / v2</td><td>Optional - one-command production-style install</td></tr>
</table>

### Step 1 - Get the code

```bash
git clone git@github.com:mr-0rbit/rynex-threat-intelligence.git
cd rynex-threat-intelligence
```

### Step 2 - Configure the environment

```bash
cp .env.example .env            # NEVER commit .env (already gitignored)
```

Then edit `.env`. Every variable is documented in the file itself; the ones you actually care about:

<table width="100%">
  <tr><th width="30%">Variable</th><th width="50%">Purpose</th><th width="20%">Dev default</th></tr>
  <tr><td><code>DATABASE_URL</code></td><td>Database. SQLite for dev; set <code>postgresql+asyncpg://user:pass@host:5432/rtip</code> for production</td><td><code>sqlite+aiosqlite:///./rtip.db</code></td></tr>
  <tr><td><code>REDIS_URL</code>, <code>CELERY_BROKER_URL</code>, <code>CELERY_RESULT_BACKEND</code></td><td>Redis DBs used for cache, task broker and task results</td><td><code>redis://localhost:6379/{0,1,2}</code></td></tr>
  <tr><td><code>JWT_SECRET_KEY</code></td><td>Token signing secret. <b>Generate a real one:</b> <code>python3 -c "import secrets; print(secrets.token_urlsafe(48))"</code></td><td><code>CHANGE_ME_in_production</code></td></tr>
  <tr><td><code>ADMIN_EMAIL</code>, <code>ADMIN_PASSWORD</code></td><td>First admin account, bootstrapped once on first backend start</td><td><code>admin@rynex.local</code> / <code>ChangeMeNow!2024</code></td></tr>
  <tr><td><code>ACCESS_TOKEN_EXPIRE_MINUTES</code>, <code>REFRESH_TOKEN_EXPIRE_DAYS</code></td><td>Session lifetimes</td><td>60 min / 7 days</td></tr>
  <tr><td><code>RATE_LIMIT_*</code></td><td>Per-IP login rate limiting (attempts per window)</td><td>10 / 300 s</td></tr>
  <tr><td><code>CORS_ORIGINS</code></td><td>Allowed frontend origins (JSON list)</td><td>localhost:5173, :3000</td></tr>
  <tr><td><code>THREATFOX_AUTH_KEY</code>, <code>URLHAUS_AUTH_KEY</code></td><td>Free abuse.ch key - unlocks ThreatFox + URLhaus (<a href="https://auth.abuse.ch/">auth.abuse.ch</a>)</td><td>empty</td></tr>
  <tr><td><code>RANSOMWARELIVE_API_KEY</code></td><td>Optional; free tier works without a key</td><td>empty</td></tr>
  <tr><td><code>NVD_API_KEY</code>, <code>MISP_URL</code>, <code>MISP_API_KEY</code></td><td>Optional NVD rate-limit boost and private MISP feeds</td><td>empty</td></tr>
  <tr><td><code>TELEGRAM_BOT_TOKEN</code>, <code>SMTP_*</code>, <code>WEBHOOK_URL</code></td><td>Notification channels - each activates when set</td><td>empty</td></tr>
  <tr><td><code>POSTGRES_USER</code>, <code>POSTGRES_PASSWORD</code>, <code>POSTGRES_DB</code></td><td>Docker Compose only (Postgres container)</td><td>rtip / <i>(required)</i> / rtip</td></tr>
</table>

### Step 3 - Install the backend

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

### Step 4 - Create the database schema

```bash
set -a
. ../.env
set +a
.venv/bin/alembic upgrade head          # current migration head: 72d4cb69a113
```

- Run this from `backend/` so the root `.env` settings are exported to the migration command.
- **Dev:** SQLite is the default; the database path is relative to the backend working directory (`backend/rtip.db`).
- **Production:** set `DATABASE_URL` to PostgreSQL **before** this step. Back up existing databases before upgrading.

### Step 5 - Start Redis

```bash
redis-server --daemonize yes --save "" --appendonly no \
  --pidfile /tmp/rtip-redis.pid --logfile /tmp/rtip-redis.log
# or: docker run -d --name rtip-redis -p 6379:6379 redis:7-alpine
redis-cli ping                          # must reply PONG
```

### Step 6 - Run the backend

```bash
set -a && . ../.env && set +a
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- Health check: `curl http://localhost:8000/healthz` (also available at `/health`)
- Interactive API docs: `http://localhost:8000/api/docs`
- On the first development start, the admin account from `ADMIN_EMAIL`/`ADMIN_PASSWORD` is created if no users exist. Change the sample password before exposing the service.

### Step 7 - Run the Celery worker and scheduler

Two separate terminals, both from `backend/`. In **each** terminal, export the root environment file, then run one of these commands:

```bash
set -a && . ../.env && set +a
# Terminal 1:
.venv/bin/celery -A app.workers.celery_app.celery_app worker --loglevel=warning --concurrency=2
# Terminal 2:
.venv/bin/celery -A app.workers.celery_app.celery_app beat --loglevel=warning --schedule=/tmp/rtip-celerybeat-schedule
```

The worker executes collectors; beat fires the schedule from the table above. Without these two processes no scheduled collection happens - the API alone only stores what you trigger manually.

### Step 8 - Run the frontend

```bash
cd frontend
npm install
npm run dev
# Dashboard: http://localhost:5173
```

Log in with the admin credentials from `.env`.

### Step 9 - Verify the installation

<table width="100%">
  <tr><th width="40%">Check</th><th width="60%">Expected</th></tr>
  <tr><td><code>curl http://localhost:8000/health</code></td><td><code>{"status":"ok","service":"rtip-backend",...}</code></td></tr>
  <tr><td>Dashboard login at <code>:5173</code></td><td>Alert feed, breach, vuln, IOC, news, sources modules render</td></tr>
  <tr><td>Sources page</td><td>Configured sources listed with per-source health</td></tr>
  <tr><td>IOC page after first collections</td><td>Populated with typed, scored, sourced indicators</td></tr>
  <tr><td><code>redis-cli ping</code></td><td><code>PONG</code></td></tr>
</table>

### Step 10 - Collect the first real intelligence

```bash
cd backend
.venv/bin/python scripts/live_smoke.py cisa-kev
.venv/bin/python scripts/live_smoke.py security-news-rss
.venv/bin/python scripts/live_smoke.py ransomware-live
.venv/bin/python scripts/live_smoke.py blocklist-de
```

> **Baseline suppression:** the first successful run from each source stores history *without* generating alerts, so you never start with a backlog of noise. From the second run on, new records raise alerts and hit the WebSocket feed.

### Step 11 - Register your company (activate "First to Know")

1. Open **Assets** in the dashboard and add everything you own: domains (`criticality: critical`), IP ranges / CIDRs, product names.
2. Open **Watchlists** and add your exact organization name as an `organization` item, plus any supplier domains, threat actors or CVEs you track.
3. Matching intelligence raises alert severity and names the matched asset. Treat a ransomware leak-site entry as a claim until independently validated.

### Step 12 - Optional keys and channels

<table width="100%">
  <tr><th width="35%">Key</th><th width="30%">Where to get it</th><th width="35%">Effect</th></tr>
  <tr><td><code>THREATFOX_AUTH_KEY</code> + <code>URLHAUS_AUTH_KEY</code></td><td><a href="https://auth.abuse.ch/">auth.abuse.ch</a> (free)</td><td>Unlocks the ThreatFox and URLhaus connectors</td></tr>
  <tr><td><code>RANSOMWARELIVE_API_KEY</code></td><td>ransomware.live partners page</td><td>Optional; free tier works without it</td></tr>
  <tr><td><code>NVD_API_KEY</code></td><td><a href="https://nvd.nist.gov/developers/request-an-api-key">nvd.nist.gov</a> (free)</td><td>Raises NVD request rate limits</td></tr>
  <tr><td><code>MISP_URL</code> + <code>MISP_API_KEY</code></td><td>Your MISP instance admin</td><td>Private feed ingestion (manual trigger)</td></tr>
  <tr><td><code>TELEGRAM_BOT_TOKEN</code> / <code>SMTP_*</code> / <code>WEBHOOK_URL</code></td><td>BotFather / your mail server / your endpoint</td><td>Alerts delivered to those channels</td></tr>
</table>

After adding keys, restart the backend **and** the worker so the collector registry picks them up.

### Quick Start

```bash
cp .env.example .env
cd backend
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
set -a && . ../.env && set +a
.venv/bin/alembic upgrade head
# terminal 0: redis-server --daemonize yes --save "" --appendonly no --pidfile /tmp/rtip-redis.pid --logfile /tmp/rtip-redis.log
# terminal 1 (from backend/): .venv/bin/uvicorn app.main:app --reload
# terminal 2 (from backend/): .venv/bin/celery -A app.workers.celery_app.celery_app worker --loglevel=warning
# terminal 3 (from backend/): .venv/bin/celery -A app.workers.celery_app.celery_app beat --loglevel=warning --schedule=/tmp/rtip-celerybeat-schedule
# terminal 4 (from frontend/): npm install && npm run dev
```

### Option B - Docker Compose (all-in-one)

```bash
cp .env.example .env    # set POSTGRES_PASSWORD and unique strong JWT_SECRET_KEY/AUDIT_HMAC_KEY/ADMIN_PASSWORD
docker compose up -d postgres redis
docker compose run --rm --build backend alembic upgrade head
docker compose run --rm backend python -c "import asyncio; from app.main import bootstrap_admin; asyncio.run(bootstrap_admin())"
docker compose up --build -d
```

Brings up PostgreSQL 17, Redis 7, API (:8000), Celery worker, Celery beat, and the frontend served by nginx (:3000). Migrate the database and create the initial platform administrator **before** starting the API and worker services. Protect the `.env` file and change the bootstrap password after first login. The dashboard is at `http://localhost:3000`; API docs are at `http://localhost:8000/api/docs`.

### Production hardening checklist

- Generate unique strong `JWT_SECRET_KEY`, `AUDIT_HMAC_KEY` and bootstrap `ADMIN_PASSWORD` values; set `ENVIRONMENT=production`, `DEBUG=false`.
- Use PostgreSQL with a strong `POSTGRES_PASSWORD`; never ship SQLite to production.
- In development, the first admin is created from `ADMIN_EMAIL` / `ADMIN_PASSWORD`; change its sample password immediately and enable TOTP MFA. In production, provision an initial platform administrator through your approved bootstrap process before enabling interactive logins.
- Terminate TLS at a reverse proxy and set `CORS_ORIGINS` to your real dashboard origin.
- Keep `.env` out of version control (gitignored) and back it up securely - it is the only place secrets live.
- Run worker + beat under a supervisor (Compose `restart: unless-stopped` policies are provided).

---

## Tests

```bash
cd backend && .venv/bin/python -m pytest tests/ -v
# 128 passed
```

---

## Intelligence Policy

RTIP is built on a few non-negotiable principles:

- **No fake data.** Every record originates from a named source with provenance (source slug, URL, timestamps).
- **Ransomware claims are never auto-confirmed.** Verification statuses are:

  `confirmed` · `reported` · `claimed` · `unverified` · `disputed`

  A leak-site listing is **always** `claimed`.
- **Dark-web scope is explicit.** Group records are public API metadata; RTIP does not connect to onion services.
- **Baseline suppression.** The first successful collection from a source ingests history *without* generating alerts, so analysts aren't flooded by backlogs.
- **Confidence is explainable.** Every score ships with human-readable reasons; allowlisted benign infrastructure is down-weighted; AI never invents evidence inside the score.
- **Terms respected.** Per-source commercial-use status and terms are recorded in [`docs/SOURCES.md`](docs/SOURCES.md) and in the `intelligence_sources` table. Keyed sources are optional and degrade gracefully.

---

## Security

<table width="100%">
  <tr><th width="30%">Control</th><th width="70%">Detail</th></tr>
  <tr><td>Authentication</td><td>JWT, organization-scoped authorization, refresh rotation, MFA (TOTP), optional OIDC SSO</td></tr>
  <tr><td>Passwords</td><td>bcrypt hashing</td></tr>
  <tr><td>Brute force</td><td>Redis-backed per-IP sliding-window rate limiting (429 on threshold; in-process fallback)</td></tr>
  <tr><td>Audit</td><td>HMAC-SHA256 chained audit events with verification and CEF / RFC 5424 export</td></tr>
  <tr><td>Machine access</td><td>Revocable service API keys; stored as hashes and shown only once</td></tr>
  <tr><td>Transport hardening</td><td>Security headers</td></tr>
  <tr><td>Input handling</td><td>Strict validation (Pydantic)</td></tr>
  <tr><td>Collection safety</td><td>Per-source rate limiting, response size caps</td></tr>
  <tr><td>SSRF protection</td><td>Config-only destinations; no user-supplied feed URLs without validation</td></tr>
</table>

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) § Security.

---

## Documentation

<table width="100%">
  <tr><th width="40%">Doc</th><th width="60%">Purpose</th></tr>
  <tr><td><a href="docs/ARCHITECTURE.md"><code>docs/ARCHITECTURE.md</code></a></td><td>System design and security model</td></tr>
  <tr><td><a href="docs/SOURCES.md"><code>docs/SOURCES.md</code></a></td><td>Source catalog, terms and commercial-use status</td></tr>
  <tr><td><a href="docs/deploy-secrets.md"><code>docs/deploy-secrets.md</code></a></td><td>Production secret provisioning and deployment guidance</td></tr>
  <tr><td><a href="docs/testing.md"><code>docs/testing.md</code></a></td><td>Backend, frontend, migration and Playwright test workflows</td></tr>
  <tr><td><a href="deploy/DR_RUNBOOK.md"><code>deploy/DR_RUNBOOK.md</code></a></td><td>Backup schedule, restore procedure and DR drills</td></tr>
  <tr><td><a href="deploy/monitoring/README.md"><code>deploy/monitoring/README.md</code></a></td><td>Rendering and deploying Prometheus/Alertmanager with Kustomize</td></tr>
  <tr><td><code>http://localhost:8000/api/docs</code></td><td>Interactive OpenAPI docs (when running)</td></tr>
</table>

---

<div align="center">

**Built by Rynex Technologies** · `DETECT. ANALYZE. RESPOND.`

</div>
