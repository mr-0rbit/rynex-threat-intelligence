# Production secret provisioning

Kubernetes manifests intentionally do **not** contain a `Secret` object or
sample credentials. The API, Celery worker, and Celery beat deployments refer
to a pre-provisioned Secret named `rtip-secrets`. Use the organization's
approved external-secrets controller or cloud secret manager, and apply it in
the `rtip` namespace before the workloads.

Required keys:

- `DATABASE_URL` — PostgreSQL URL using `postgresql+asyncpg://` or
  `postgresql+psycopg://`.
- `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` — Redis URLs. Use
  separate logical DBs/credentials and TLS where the cluster supports it.
- `JWT_SECRET_KEY` — unique random secret, at least 32 characters.
- `AUDIT_HMAC_KEY` — independent unique random key, at least 32 characters.
- `ADMIN_EMAIL`, `ADMIN_PASSWORD` — bootstrap credentials. The password is
  used only when the first user is created; rotate it through the normal
  credential-management process immediately after bootstrap.

Optional keys include `OIDC_CLIENT_SECRET`, mail/notification credentials,
and collector API keys. Do not put values in Git, ConfigMaps, container
arguments, or deployment manifests. Rotate a secret through the secret manager
and restart the workloads; plan audit-HMAC key rotation as a controlled chain
verification/continuity operation rather than an ordinary password rotation.

Before starting production API replicas, run the migration from the backend
image with the same database secret:

```sh
python -m alembic upgrade head
```

Set `TRUSTED_PROXY_CIDRS` in the ConfigMap to the exact ingress-controller
proxy CIDRs used by the cluster. Do not use `0.0.0.0/0` or `::/0`; forwarded
client IP headers are ignored unless the direct peer is within a trusted CIDR.
If it is left empty, rate limits key on the direct peer address.

Production startup validation rejects placeholder JWT/audit/admin secrets,
debug mode, SQLite, wildcard CORS, invalid proxy CIDRs, and incomplete or
non-HTTPS OIDC configuration.
