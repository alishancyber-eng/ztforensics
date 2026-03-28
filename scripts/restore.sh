#!/usr/bin/env bash
# ==============================================================
# restore.sh – Restore ZTForensics data from a backup archive
#
# Usage:
#   bash scripts/restore.sh <backup_archive.tar.gz>
#
# Example:
#   bash scripts/restore.sh backups/ztforensics_backup_20260328T120000Z.tar.gz
# ==============================================================
set -euo pipefail

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARCHIVE="${1:-}"
if [ -z "$ARCHIVE" ]; then
    error "Usage: $0 <backup_archive.tar.gz>"
    exit 1
fi

if [ ! -f "$ARCHIVE" ]; then
    error "Backup archive not found: $ARCHIVE"
    exit 1
fi

# Load .env if present
if [ -f "${REPO_ROOT}/.env" ]; then
    set -o allexport
    # shellcheck source=/dev/null
    source "${REPO_ROOT}/.env"
    set +o allexport
fi

# ----------------------------------------------------------------
# Extract archive to temp dir
# ----------------------------------------------------------------
RESTORE_TMP="$(mktemp -d)"
trap 'rm -rf "${RESTORE_TMP}"' EXIT

info "Extracting ${ARCHIVE} ..."
tar -xzf "${ARCHIVE}" -C "${RESTORE_TMP}"
RESTORE_DIR="${RESTORE_TMP}/$(ls "${RESTORE_TMP}" | head -1)"
info "Restore directory: ${RESTORE_DIR}"

# ----------------------------------------------------------------
# PostgreSQL restore
# ----------------------------------------------------------------
info "Restoring PostgreSQL database ..."
PG_CONTAINER="${PG_CONTAINER:-ztf-postgres}"
DB_USER="${PGUSER:-ztf}"
DB_NAME="${PGDATABASE:-ztfdb}"

PG_DUMP="${RESTORE_DIR}/ztfdb_backup.dump"
if [ -f "$PG_DUMP" ]; then
    docker cp "${PG_DUMP}" "${PG_CONTAINER}:/tmp/ztfdb_restore.dump"
    # Drop and recreate target database before restore
    docker exec "${PG_CONTAINER}" psql -U "${DB_USER}" -c "
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();" postgres || true
    docker exec "${PG_CONTAINER}" dropdb  -U "${DB_USER}" --if-exists "${DB_NAME}"
    docker exec "${PG_CONTAINER}" createdb -U "${DB_USER}" "${DB_NAME}"
    docker exec "${PG_CONTAINER}" pg_restore \
        -U "${DB_USER}" \
        -d "${DB_NAME}" \
        --no-owner \
        -F custom \
        /tmp/ztfdb_restore.dump
    docker exec "${PG_CONTAINER}" rm -f /tmp/ztfdb_restore.dump
    info "PostgreSQL restore complete."
else
    warn "No PostgreSQL dump found in archive – skipping."
fi

# ----------------------------------------------------------------
# MinIO restore
# ----------------------------------------------------------------
info "Restoring MinIO data ..."
MINIO_CONTAINER="${MINIO_CONTAINER:-ztf-minio}"
BUCKET="${MINIO_BUCKET:-forensics-evidence}"
MINIO_BACKUP_DIR="${RESTORE_DIR}/minio"

if [ -d "${MINIO_BACKUP_DIR}" ]; then
    if command -v mc >/dev/null 2>&1; then
        MINIO_ALIAS="ztfrestore"
        MINIO_URL="http://localhost:${MINIO_PORT:-9000}"
        mc alias set "${MINIO_ALIAS}" "${MINIO_URL}" \
            "${MINIO_ACCESS_KEY:-minioadmin}" \
            "${MINIO_SECRET_KEY:-minioadmin123}" --quiet
        mc mb --quiet "${MINIO_ALIAS}/${BUCKET}" 2>/dev/null || true
        mc mirror --quiet "${MINIO_BACKUP_DIR}/${BUCKET}" "${MINIO_ALIAS}/${BUCKET}"
        mc alias rm "${MINIO_ALIAS}" --quiet || true
        info "MinIO restore complete."
    else
        warn "'mc' not found – attempting raw docker cp ..."
        docker cp "${MINIO_BACKUP_DIR}/." "${MINIO_CONTAINER}:/data/" 2>/dev/null || \
            warn "MinIO data copy failed – manual restore may be required."
    fi
else
    warn "No MinIO backup found in archive – skipping."
fi

# ----------------------------------------------------------------
# Configuration restore (optional – user confirms)
# ----------------------------------------------------------------
CONFIG_BACKUP_DIR="${RESTORE_DIR}/config"
if [ -d "$CONFIG_BACKUP_DIR" ]; then
    read -r -p "[INFO]  Restore configuration files from backup? This will overwrite .env [y/N]: " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        for f in .env .env.development .env.production docker-compose.yml; do
            src="${CONFIG_BACKUP_DIR}/${f}"
            if [ -f "$src" ]; then
                cp "$src" "${REPO_ROOT}/${f}"
                info "  Restored ${f}"
            fi
        done
        info "Configuration files restored."
    else
        info "Skipping configuration file restore."
    fi
fi

echo ""
echo "============================================================"
echo " Restore complete."
echo "============================================================"
