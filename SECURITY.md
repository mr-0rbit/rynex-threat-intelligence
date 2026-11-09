# RTIP Secure Software Development Life Cycle (S-SDLC)

This document defines the mandatory security practices for all RTIP code. Every
contribution must satisfy these gates before merge.

## 1. Threat model summary

| Asset | Threat | Control |
|---|---|---|
| JWT secrets / API keys | Exfiltration, hardcoding | Env-only configuration; env-var *names* (never values) in code; `.env` gitignored |
| Analyst sessions | Token theft, privilege escalation | Short-lived JWTs, refresh rotation, RBAC (admin/analyst/viewer) enforced server-side |
| Intelligence feeds | Supply-chain: malicious content from untrusted sources | All external data treated as hostile: size caps (20 MB), timeouts, strict validation, HTML stripped, React escaping as final defense |
| Collection engine | SSRF | Collector destinations are code-defined; user-configurable feeds forbidden without allowlisted schemes + private-range blocking (`ALLOW_PRIVATE_NETWORK_SOURCES=false`) |
| Database | SQL injection | SQLAlchemy parameterized queries exclusively; no string-built SQL (regression-tested) |
| Users | Credential attacks | bcrypt (12 rounds), generic auth errors, no user enumeration |
| Audit trail | Repudiation | `audit_logs` on auth + all admin actions; append-only usage |
| Source data misuse | Legal/ethical violation | Per-source terms register (`docs/SOURCES.md`); commercial-use status recorded; dark web limited to legitimate intermediaries |

## 2. Development gates (enforced per change)

1. **Design**: security-relevant changes require a threat-model note in the PR description.
2. **Secure coding**: strict typing; no `eval`/`exec`/`pickle` on external data; no secrets in logs; structured logging with allowlisted extra fields only.
3. **Testing**: every feature ships with tests. Security regression tests live in
   `tests/test_darkweb_security.py` and must never be weakened:
   - SQL injection probes on search/filter parameters
   - JWT tampering rejection
   - HTML/script stripping from external content
   - Report type whitelisting
   - Secret handling invariants
4. **Dependency hygiene**: `pip-audit` and `npm audit` run at each release; known-high findings are fixed or formally risk-accepted with rationale in this file.
5. **Data protection**: no stolen personal data, credential dumps, or raw breach
   corpora are ever stored; breach records store metadata + evidence URLs only.
6. **Least privilege**: containers run as non-root (`rtip` user); DB user scoped to
   a single schema; admin endpoints require explicit role checks.

## 3. Handling of dark web intelligence

- No direct Tor/onion connectivity exists in the codebase — by design, not by config.
- Dark web signals enter only via vetted intermediary APIs (Ransomware.live) as
  metadata: group names, victim claims, dates, source links.
- Threat-actor claims are stored as `claimed` and can only be upgraded to
  `confirmed` through primary disclosure or strong corroboration (deterministic
  rule, tested).

## 4. Incident response for the platform itself

- Failed collections and notification errors are logged with structured fields and
  visible on the Sources page (health status, consecutive failures).
- Unhandled server errors return generic 500s; details stay in server logs.
- Security contact: security@rynex.tech (internal).
