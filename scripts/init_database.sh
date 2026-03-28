#!/usr/bin/env bash
# ==============================================================
# init_database.sh – Initialize ZTForensics PostgreSQL database
#
# Usage:
#   bash scripts/init_database.sh
#
# Environment variables:
#   DATABASE_URL – PostgreSQL connection string
# ==============================================================
set -euo pipefail

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load .env if present
if [ -f "${REPO_ROOT}/.env" ]; then
    # shellcheck source=/dev/null
    set -o allexport
    source "${REPO_ROOT}/.env"
    set +o allexport
    info "Loaded environment from ${REPO_ROOT}/.env"
fi

DATABASE_URL="${DATABASE_URL:-postgresql://ztf:ztfpass@localhost:5432/ztfdb}"

# ----------------------------------------------------------------
# Wait for PostgreSQL to be ready
# ----------------------------------------------------------------
info "Waiting for PostgreSQL at ${DATABASE_URL} ..."
retries=0
until python3 -c "
import sys, sqlalchemy
try:
    e = sqlalchemy.create_engine('${DATABASE_URL}')
    with e.connect() as c: c.execute(sqlalchemy.text('SELECT 1'))
    print('ok')
except Exception as ex:
    print(str(ex), file=sys.stderr)
    sys.exit(1)
" 2>/dev/null; do
    retries=$((retries + 1))
    if [ "$retries" -ge 30 ]; then
        error "PostgreSQL not available after 30 attempts."
        exit 1
    fi
    info "  Attempt ${retries}/30 – sleeping 3 s ..."
    sleep 3
done
info "PostgreSQL is ready."

# ----------------------------------------------------------------
# Run SQLAlchemy schema creation via the api_gateway module
# ----------------------------------------------------------------
info "Creating database schema from SQLAlchemy models ..."
(
    cd "${REPO_ROOT}"
    PYTHONPATH="${REPO_ROOT}/api_gateway" python3 - <<'PYEOF'
import os, sys
sys.path.insert(0, os.path.join(os.getcwd(), "api_gateway"))
from database import init_db, engine, Base
import sqlalchemy

# Create all tables defined by SQLAlchemy models
Base.metadata.create_all(bind=engine)
print("[INFO]  Tables created.")

# Create indexes (SQLAlchemy creates them via model definitions,
# but we add any extra composite or partial indexes here).
with engine.connect() as conn:
    conn.execute(sqlalchemy.text("""
        CREATE INDEX IF NOT EXISTS idx_access_log_user_id
            ON access_logs (user_id);
    """))
    conn.execute(sqlalchemy.text("""
        CREATE INDEX IF NOT EXISTS idx_access_log_timestamp
            ON access_logs (timestamp DESC);
    """))
    conn.execute(sqlalchemy.text("""
        CREATE INDEX IF NOT EXISTS idx_access_log_decision
            ON access_logs (decision);
    """))
    conn.commit()
print("[INFO]  Indexes created.")
PYEOF
)

info "Database initialization complete."
