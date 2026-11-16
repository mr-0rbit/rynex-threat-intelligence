#!/usr/bin/env bash
# RTIP Database Backup & Restore Script
# Usage:
#   ./backup.sh backup [tag]        - create a backup (optional tag, default: timestamp)
#   ./backup.sh restore <tag>       - restore from a backup tag
#   ./backup.sh list                - list available backups
#   ./backup.sh verify <tag>        - verify backup integrity

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/rtip}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-rtip}"
POSTGRES_USER="${POSTGRES_USER:-rtip}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"

mkdir -p "$BACKUP_DIR"

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }

cmd_backup() {
    local tag="${1:-$(date -u +'%Y%m%d-%H%M%S')}"
    local file="${BACKUP_DIR}/rtip-${tag}.sql.gz"
    : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
    log "Creating backup: $file"
    PGPASSWORD="$POSTGRES_PASSWORD" pg_dump \
        -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
        --no-owner --no-privileges --clean --if-exists |
        gzip -9 > "$file"
    gzip -t "$file"
    sha256sum "$file" > "${file}.sha256"
    log "Backup complete: $(du -h "$file" | cut -f1)"
}

cmd_restore() {
    local tag="${1:-}"
    if [[ -z "$tag" ]]; then
        echo "Usage: $0 restore <tag>"
        exit 1
    fi
    local file="${BACKUP_DIR}/rtip-${tag}.sql.gz"
    if [[ ! -f "$file" ]]; then
        log "Backup not found: $file"
        exit 1
    fi
    : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
    if [[ -f "${file}.sha256" ]]; then
        (cd "$BACKUP_DIR" && sha256sum -c "$(basename "${file}.sha256")") || {
            log "Checksum verification failed; refusing to restore"
            exit 1
        }
    fi
    log "Restoring from: $file"
    gunzip -c "$file" | PGPASSWORD="$POSTGRES_PASSWORD" psql \
        -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
        --single-transaction --quiet
    log "Restore complete"
}

cmd_list() {
    log "Available backups:"
    ls -lh "$BACKUP_DIR"/rtip-*.sql.gz 2>/dev/null | awk '{print $9, $5, $6, $7, $8}' || log "No backups found"
}

cmd_verify() {
    local tag="${1:-}"
    if [[ -z "$tag" ]]; then
        echo "Usage: $0 verify <tag>"
        exit 1
    fi
    local file="${BACKUP_DIR}/rtip-${tag}.sql.gz"
    if [[ ! -f "$file" ]]; then
        log "Backup not found: $file"
        exit 1
    fi
    log "Verifying backup integrity..."
    gunzip -t "$file" && log "GZIP integrity: OK"
    local line_count=$(gunzip -c "$file" | wc -l)
    log "SQL lines: $line_count"
}

cmd_cleanup() {
    log "Cleaning backups older than $RETENTION_DAYS days..."
    find "$BACKUP_DIR" -name "rtip-*.sql.gz" -mtime +"$RETENTION_DAYS" -delete
    log "Cleanup complete"
}

case "${1:-}" in
    backup)   cmd_backup "${2:-}" ;;
    restore)  cmd_restore "${2:-}" ;;
    list)     cmd_list ;;
    verify)   cmd_verify "${2:-}" ;;
    cleanup)  cmd_cleanup ;;
    *)        echo "Usage: $0 {backup|restore|list|verify|cleanup} [tag]"; exit 1 ;;
esac