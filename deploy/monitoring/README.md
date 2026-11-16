# RTIP monitoring deployment

The monitoring stack is rendered with Kustomize so the Prometheus and
Alertmanager configuration files remain readable, reviewable YAML instead of
being embedded in a Kubernetes manifest.

## Prerequisites

Create the two credential Secrets in the `rtip` namespace before applying:

```sh
# Service API key created through POST /api/v1/admin/api-keys (or the admin UI).
# The key only needs the role required to read /api/v1/metrics.
kubectl -n rtip create secret generic rtip-prometheus-credentials \
  --from-literal=metrics-api-key='rtip_...'

kubectl -n rtip create secret generic rtip-alertmanager-credentials \
  --from-literal=smtp-password='...'
```

Prefer your organisation's external-secrets controller or cloud secret manager
over imperative `kubectl create secret` commands. Never commit the values.

## Apply

```sh
kubectl apply -k deploy/monitoring
```

The generated ConfigMaps carry a content hash. Changing
`prometheus.yaml`, `alerts.yaml`, or `alertmanager.yaml` and re-applying
produces a new ConfigMap and a rolling restart of the consuming Deployment.

## Files

| File | Purpose |
|------|---------|
| `workloads.yaml` | Prometheus and Alertmanager Deployments, Services, PVCs |
| `prometheus.yaml` | Scrape configuration; authenticates with a bearer token file |
| `alerts.yaml` | Alert rules; every `rtip_*` metric is emitted by `backend/app/api/v1/metrics.py` |
| `alertmanager.yaml` | Routing/inhibition and SMTP credentials via file |
| `servicemonitor.yaml` | Optional Prometheus Operator variant; do not apply alongside the static scrape |
| `kustomization.yaml` | Renders the files into ConfigMaps and applies `workloads.yaml` |

## Verify

```sh
curl -fsS -H "Authorization: Bearer $RTIP_API_KEY" \
  http://rtip-backend.rtip.svc:8000/api/v1/metrics | head
```

Prometheus should report `up{job="rtip-backend"} == 1`. The regression test
`backend/tests/test_deploy_artifacts.py` fails if an alert references a metric
the backend does not expose, or if credentials are moved out of a mounted file.
