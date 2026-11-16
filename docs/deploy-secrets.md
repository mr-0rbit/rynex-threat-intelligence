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

The hourly database backup CronJob additionally reads a separate
`rtip-backup-credentials` Secret with `S3_BUCKET`, `AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`, and optional `S3_ENDPOINT`, `S3_PREFIX`, `S3_SSE`,
`AWS_DEFAULT_REGION`. Prefer workload identity over static AWS keys when the
platform supports it. The monitoring stack reads two more pre-provisioned
Secrets: `rtip-prometheus-credentials` (`metrics-api-key`, a service API key
created through `/api/v1/admin/api-keys`) and `rtip-alertmanager-credentials`
(`smtp-password`).

Before starting production API replicas, run the migration from the backend
image with the same database secret:

```sh
python -m alembic upgrade head
```

Apply the application workloads through Kustomize so image tags are pinned in
one reviewed file instead of `:latest` floating across four manifests:

```sh
kustomize edit set image rtip-backend=registry.example.com/rtip/backend:1.2.3 \
  --kustomization deploy/k8s/kustomization.yaml
kustomize edit set image rtip-frontend=registry.example.com/rtip/frontend:1.2.3 \
  --kustomization deploy/k8s/kustomization.yaml
kubectl apply -k deploy/k8s
```

The hourly backup CronJob and the monitoring stack are applied separately
because they require their own published image and credential Secrets; see
[`deploy/DR_RUNBOOK.md`](../deploy/DR_RUNBOOK.md) and
[`deploy/monitoring/README.md`](../deploy/monitoring/README.md).
`backend/tests/test_deploy_artifacts.py` fails if a workload image is mutable
and not overridden by `deploy/k8s/kustomization.yaml`.

Set `TRUSTED_PROXY_CIDRS` in the ConfigMap to the exact ingress-controller
proxy CIDRs used by the cluster. Do not use `0.0.0.0/0` or `::/0`; forwarded
client IP headers are ignored unless the direct peer is within a trusted CIDR.
If it is left empty, rate limits key on the direct peer address.

Production startup validation rejects placeholder JWT/audit/admin secrets,
debug mode, SQLite, wildcard CORS, invalid proxy CIDRs, and incomplete or
non-HTTPS OIDC configuration.
