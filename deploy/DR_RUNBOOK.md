# RTIP Disaster Recovery Runbook

## Recovery Objectives
- **RTO (Recovery Time Objective)**: 30 minutes
- **RPO (Recovery Point Objective)**: 1 hour, enforced by the hourly
  `rtip-postgres-backup` CronJob (`0 * * * *`). For a tighter RPO, enable
  PostgreSQL WAL archiving/point-in-time recovery and record the new objective
  here; the CronJob alone cannot provide sub-hour recovery points.

---

## 1. Complete Cluster Loss (Kubernetes + Database)

### Prerequisites
- Access to backup storage (S3/GCS/Azure Blob)
- kubectl access to new cluster
- DNS control to point `rtip.rynex.tech`

### Procedure

1. **Provision new cluster**
   ```bash
   # Using your IaC (Terraform/Cluster API)
   terraform apply -target=kubernetes_cluster
   ```

2. **Restore PostgreSQL from backup**
   ```bash
   # Find the latest backup (default prefix is rtip/)
   aws s3 ls "s3://$S3_BUCKET/rtip/" | tail -1

   # Download and verify integrity before restoring
   aws s3 cp "s3://$S3_BUCKET/rtip/rtip-20240115-040000.sql.gz" .
   aws s3 cp "s3://$S3_BUCKET/rtip/rtip-20240115-040000.sql.gz.sha256" .
   sha256sum -c rtip-20240115-040000.sql.gz.sha256

   # Restore in a single transaction; stop application writers first.
   gunzip -c rtip-20240115-040000.sql.gz | PGPASSWORD=$POSTGRES_PASSWORD psql \
       -h new-pg-host -U rtip -d rtip --single-transaction
   ```

3. **Deploy RTIP manifests**
   ```bash
   kubectl apply -f deploy/k8s/namespace.yaml
   kubectl apply -f deploy/k8s/configmap-and-secrets.yaml  # Ensure secrets are populated
   kubectl apply -f deploy/k8s/backend-deployment.yaml
   kubectl apply -f deploy/k8s/workers-and-ingress.yaml
   ```

4. **Verify health**
   ```bash
   curl -f https://rtip.rynex.tech/healthz
   curl -f https://rtip.rynex.tech/readyz
   ```

5. **Update DNS** (if cluster IP changed)
   ```bash
   # Point rtip.rynex.tech to new ingress IP
   ```

---

## 2. Database-Only Loss (PostgreSQL Pod Failure)

### Automatic (if using Cloud SQL / RDS / Patroni)
- Failover is automatic; just wait for new primary
- Verify `readyz` endpoint recovers

### Manual (self-managed PostgreSQL)
```bash
# 1. Check replica status
kubectl exec -it rtip-postgres-0 -n rtip -- patronictl list

# 2. If replica exists, promote
kubectl exec -it rtip-postgres-1 -n rtip -- patronictl failover

# 3. If no replica, restore from backup (see section 1, step 2)
```

---

## 3. Redis Loss

Redis is ephemeral; data is rebuilt from PostgreSQL:
```bash
# Redis data: Celery task queues, rate limit counters, WebSocket pub/sub
# All recoverable:
# - Rate limits: rebuilt on next request
# - Celery: tasks re-queued from DB schedules on beat restart
# - WebSocket: clients reconnect on next poll
```

Procedure:
```bash
kubectl delete pod -n rtip -l app.kubernetes.io/name=redis
# Wait for new pod, verify redis-cli ping
```

---

## 4. Single Backend Pod Crash

```bash
# Kubernetes auto-restarts (restartPolicy: Always)
# Check logs:
kubectl logs -n rtip -l app.kubernetes.io/name=rtip-backend --tail=100

# If CrashLoopBackOff:
kubectl describe pod -n rtip -l app.kubernetes.io/name=rtip-backend
# Check: secrets mounted? DB reachable? Redis reachable?
```

---

## 5. Celery Worker/Beat Issues

```bash
# Workers
kubectl get pods -n rtip -l app.kubernetes.io/name=rtip-worker
kubectl logs -n rtip -l app.kubernetes.io/name=rtip-worker --tail=100

# Beat (only 1 replica!)
kubectl get pods -n rtip -l app.kubernetes.io/name=rtip-beat
kubectl logs -n rtip -l app.kubernetes.io/name=rtip-beat --tail=100
```

Common issues:
- **Beat not scheduling**: Check `celerybeat-schedule` volume, beat logs for "Scheduler: beat"
- **Worker not picking tasks**: Check broker URL, Redis connectivity, task registration

---

## 6. Corrupted Database (Point-in-Time Recovery)

If using WAL archiving (recommended for production):
```bash
# 1. Stop writes (scale backend to 0)
kubectl scale deployment rtip-backend -n rtip --replicas=0

# 2. Restore base backup
pg_basebackup -D /var/lib/postgresql/data -R --host=backup-host

# 3. Replay WAL up to desired timestamp
# Create recovery.signal with recovery_target_time
echo "recovery_target_time = '2024-01-15 10:30:00'" >> /var/lib/postgresql/data/postgresql.auto.conf

# 4. Start PostgreSQL, verify, then scale backend up
kubectl scale deployment rtip-backend -n rtip --replicas=3
```

---

## 7. Secret Compromise (JWT_SECRET_KEY, API Keys)

```bash
# 1. Generate new secrets
JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
AUDIT_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")

# 2. Update Kubernetes secrets
kubectl create secret generic rtip-secrets -n rtip \
    --from-literal=JWT_SECRET_KEY="$JWT_SECRET_KEY" \
    --from-literal=AUDIT_HMAC_KEY="$AUDIT_HMAC_KEY" \
    --dry-run=client -o yaml | kubectl apply -f -

# 3. Rollout restart all pods to pick up new secrets
kubectl rollout restart deployment/rtip-backend -n rtip
kubectl rollout restart deployment/rtip-worker -n rtip
kubectl rollout restart deployment/rtip-beat -n rtip

# 4. All existing sessions invalidated - users re-login
# 5. Rotate any external API keys (abuse.ch, NVD, MISP, Telegram, SMTP)
```

---

## 8. Verification Checklist (Post-Recovery)

| Check | Command | Expected |
|-------|---------|----------|
| API health | `curl -f https://rtip.rynex.tech/healthz` | 200 OK |
| DB connectivity | `curl -f https://rtip.rynex.tech/readyz` | `{"status":"ok","checks":{"database":{"status":"healthy"},...}}` |
| Auth works | Login via dashboard | Session created |
| Collection runs | Check Sources page | Last run < 1h ago |
| Alerts flow | Trigger test alert | WebSocket delivers |
| Notifications | Check Telegram/email | Test message received |

---

## 9. Contacts

- **Platform On-Call**: oncall@rynex.tech (pagerduty)
- **Security Team**: security@rynex.tech
- **Database Admin**: dba@rynex.tech
- **Infra Team**: infra@rynex.tech

---

## 10. Backup Verification Schedule

| Frequency | Action |
|-----------|--------|
| Hourly | Automated logical backup via the `rtip-postgres-backup` CronJob |
| Daily | Confirm the latest S3 object and `.sha256` checksum exist |
| Weekly | Restore the latest backup to staging and run smoke tests |
| Monthly | Full DR drill: restore to an isolated cluster, run smoke tests, record actual RTO/RPO |

The CronJob image must contain both `pg_dump` and the AWS CLI v2. Build it from
`deploy/backup/Dockerfile` and publish it before applying the CronJob:

```bash
docker build -t registry.example.com/rtip/backup:1.0.0 deploy/backup
docker push registry.example.com/rtip/backup:1.0.0
```

### Manual / on-demand backups

`deploy/backup.sh` is the operator-driven counterpart to the CronJob. It writes
local, checksummed archives and never uploads, so it is safe to run against
production for a pre-change snapshot:

```bash
POSTGRES_PASSWORD=... ./deploy/backup.sh backup pre-upgrade
POSTGRES_PASSWORD=... ./deploy/backup.sh verify pre-upgrade
POSTGRES_PASSWORD=... ./deploy/backup.sh restore pre-upgrade   # verifies .sha256 first
```

Set `BACKUP_DIR` to a path with enough free space (default `/var/backups/rtip`)
and `RETENTION_DAYS` for `./deploy/backup.sh cleanup`.

> **Important**: Never test restores against production. Use a staging namespace/cluster.