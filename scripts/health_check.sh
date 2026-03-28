#!/usr/bin/env bash
# ==============================================================
# health_check.sh – Verify all ZTForensics services are healthy
#
# Usage:
#   bash scripts/health_check.sh
#
# Returns exit code 0 if all services are healthy, 1 otherwise.
# ==============================================================
set -uo pipefail

# ----------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load .env if present
if [ -f "${REPO_ROOT}/.env" ]; then
    set -o allexport
    # shellcheck source=/dev/null
    source "${REPO_ROOT}/.env"
    set +o allexport
fi

KEYCLOAK_URL="${KEYCLOAK_SERVER_URL:-http://localhost:8080}"
API_URL="${API_GATEWAY_URL:-http://localhost:8000}"
OPA_URL="${OPA_URL:-http://localhost:8181}"
DASHBOARD_URL="http://localhost:${DASHBOARD_PORT:-5000}"
DATABASE_URL="${DATABASE_URL:-postgresql://ztf:ztfpass@localhost:5432/ztfdb}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-localhost:9000}"

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
PASS=0
FAIL=0

check() {
    local name="$1"
    local result="$2"   # "ok" or anything else = fail
    local detail="${3:-}"

    if [ "$result" = "ok" ]; then
        printf "  %-30s [OK]\n" "$name"
        PASS=$((PASS + 1))
    else
        printf "  %-30s [FAIL] %s\n" "$name" "$detail"
        FAIL=$((FAIL + 1))
    fi
}

http_check() {
    local url="$1"
    if curl -sf --max-time 5 "$url" >/dev/null 2>&1; then
        echo "ok"
    else
        echo "unreachable"
    fi
}

port_check() {
    local host="$1"
    local port="$2"
    if (echo > /dev/tcp/"$host"/"$port") 2>/dev/null; then
        echo "ok"
    else
        echo "closed"
    fi
}

db_check() {
    python3 -c "
import sys, sqlalchemy
try:
    e = sqlalchemy.create_engine('${DATABASE_URL}', connect_args={'connect_timeout': 5})
    with e.connect() as c: c.execute(sqlalchemy.text('SELECT 1'))
    print('ok')
except Exception as ex:
    print(str(ex), file=sys.stderr)
    sys.exit(1)
" 2>/dev/null && echo "ok" || echo "fail"
}

# ----------------------------------------------------------------
# Run checks
# ----------------------------------------------------------------
echo ""
echo "============================================================"
echo " ZTForensics Health Check – $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
echo "▶  Services"

# PostgreSQL
PG_HOST="${DATABASE_URL##*@}"
PG_HOST="${PG_HOST%%:*}"
check "PostgreSQL port (5432)"   "$(port_check "${PG_HOST:-localhost}" 5432)"
check "PostgreSQL connectivity"  "$(db_check)"

# Keycloak
check "Keycloak port (8080)"     "$(port_check localhost 8080)"
check "Keycloak health endpoint" "$(http_check "${KEYCLOAK_URL}/health/ready")"

# MinIO
MINIO_HOST="${MINIO_ENDPOINT%%:*}"
MINIO_PORT="${MINIO_ENDPOINT##*:}"
check "MinIO port (${MINIO_PORT})" "$(port_check "${MINIO_HOST:-localhost}" "${MINIO_PORT:-9000}")"
check "MinIO health endpoint"      "$(http_check "http://${MINIO_ENDPOINT}/minio/health/live")"

# OPA
check "OPA port (8181)"          "$(port_check localhost 8181)"
check "OPA health endpoint"      "$(http_check "${OPA_URL}/health")"

# API Gateway
check "API Gateway port (8000)"  "$(port_check localhost 8000)"
check "API Gateway /health"      "$(http_check "${API_URL}/health")"

# Dashboard
check "Dashboard port (5000)"    "$(port_check localhost 5000)"
check "Dashboard /"              "$(http_check "${DASHBOARD_URL}/")"

# OPA policies loaded
OPA_POLICY_STATUS=$(curl -sf --max-time 5 "${OPA_URL}/v1/data/ztf/authz" 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('ok' if 'result' in d else 'no_policy')
except: print('fail')
" 2>/dev/null || echo "fail")
check "OPA ztf.authz policy"     "${OPA_POLICY_STATUS}"

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
echo ""
echo "============================================================"
echo " Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "One or more services failed the health check."
    echo "Run 'docker-compose ps' and 'docker-compose logs <service>' to investigate."
    exit 1
else
    echo "All services are healthy. ✓"
    exit 0
fi
