#!/usr/bin/env bash
# ==============================================================
# backup.sh – Back up ZTForensics data
#
# Usage:
#   bash scripts/backup.sh [backup_dir]
#
# Default backup directory: ./backups/<timestamp>
# ==============================================================
set -euo pipefail

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load .env if present
if [ -f "${REPO_ROOT}/.env" ]; then
    set -o allexport
    # shellcheck source=/dev/null
    source "${REPO_ROOT}/.env"
    set +o allexport
fi

TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
BACKUP_ROOT="${1:-${REPO_ROOT}/backups}/${TIMESTAMP}"
mkdir -p "${BACKUP_ROOT}"

info "Backup directory: ${BACKUP_ROOT}"

# ----------------------------------------------------------------
# PostgreSQL backup
# ----------------------------------------------------------------
info "Backing up PostgreSQL database ..."
PG_CONTAINER="${PG_CONTAINER:-ztf-postgres}"
DB_USER="${PGUSER:-ztf}"
DB_NAME="${PGDATABASE:-ztfdb}"

docker exec "${PG_CONTAINER}" pg_dump \
    -U "${DB_USER}" \
    -d "${DB_NAME}" \
    -F custom \
    -f /tmp/ztfdb_backup.dump

docker cp "${PG_CONTAINER}:/tmp/ztfdb_backup.dump" \
    "${BACKUP_ROOT}/ztfdb_backup.dump"
docker exec "${PG_CONTAINER}" rm -f /tmp/ztfdb_backup.dump
info "PostgreSQL backup saved to ${BACKUP_ROOT}/ztfdb_backup.dump"

# ----------------------------------------------------------------
# MinIO backup (using mc mirror)
# ----------------------------------------------------------------
info "Backing up MinIO data ..."
MINIO_CONTAINER="${MINIO_CONTAINER:-ztf-minio}"
MINIO_ALIAS="ztfbackup"
MINIO_URL="http://localhost:${MINIO_PORT:-9000}"
MINIO_ACCESS="${MINIO_ACCESS_KEY:-minioadmin}"
MINIO_SECRET="${MINIO_SECRET_KEY:-minioadmin123}"
BUCKET="${MINIO_BUCKET:-forensics-evidence}"
MINIO_BACKUP_DIR="${BACKUP_ROOT}/minio"

mkdir -p "${MINIO_BACKUP_DIR}"

if command -v mc >/dev/null 2>&1; then
    mc alias set "${MINIO_ALIAS}" "${MINIO_URL}" "${MINIO_ACCESS}" "${MINIO_SECRET}" --quiet
    mc mirror --quiet "${MINIO_ALIAS}/${BUCKET}" "${MINIO_BACKUP_DIR}/${BUCKET}" || \
        info "  Bucket '${BUCKET}' may be empty or unreachable – skipped."
    mc alias rm "${MINIO_ALIAS}" --quiet || true
    info "MinIO backup saved to ${MINIO_BACKUP_DIR}/${BUCKET}"
else
    info "  'mc' not found – backing up via docker cp ..."
    docker cp "${MINIO_CONTAINER}:/data" "${MINIO_BACKUP_DIR}/" 2>/dev/null || \
        info "  MinIO container data copy failed – skipped."
fi

# ----------------------------------------------------------------
# Configuration backup
# ----------------------------------------------------------------
info "Backing up configuration files ..."
CONFIG_BACKUP_DIR="${BACKUP_ROOT}/config"
mkdir -p "${CONFIG_BACKUP_DIR}"

for f in .env .env.development .env.production docker-compose.yml; do
    src="${REPO_ROOT}/${f}"
    if [ -f "$src" ]; then
        cp "$src" "${CONFIG_BACKUP_DIR}/"
        info "  Copied ${f}"
    fi
done
cp -r "${REPO_ROOT}/opa/policies" "${CONFIG_BACKUP_DIR}/opa-policies" 2>/dev/null || true

# ----------------------------------------------------------------
# Create archive
# ----------------------------------------------------------------
ARCHIVE="${REPO_ROOT}/backups/ztforensics_backup_${TIMESTAMP}.tar.gz"
tar -czf "${ARCHIVE}" -C "${REPO_ROOT}/backups" "${TIMESTAMP}"
info "Archive created: ${ARCHIVE}"

# Remove uncompressed backup directory
rm -rf "${BACKUP_ROOT}"

echo ""
echo "============================================================"
echo " Backup complete: ${ARCHIVE}"
echo "============================================================"
