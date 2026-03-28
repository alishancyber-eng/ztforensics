#!/usr/bin/env bash
# ==============================================================
# setup_keycloak.sh – Automated Keycloak realm & client setup
#
# Usage:
#   bash scripts/setup_keycloak.sh
#
# Environment variables (override via .env or shell):
#   KEYCLOAK_SERVER_URL   – defaults to http://localhost:8080
#   KEYCLOAK_ADMIN_USER   – defaults to admin
#   KEYCLOAK_ADMIN_PASSWORD – defaults to admin123
#   KEYCLOAK_REALM        – defaults to forensics
#   KEYCLOAK_CLIENT_ID    – defaults to api-gateway
# ==============================================================
set -euo pipefail

# ----------------------------------------------------------------
# Configuration (read from environment or use defaults)
# ----------------------------------------------------------------
KEYCLOAK_URL="${KEYCLOAK_SERVER_URL:-http://localhost:8080}"
ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin123}"
REALM="${KEYCLOAK_REALM:-forensics}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-api-gateway}"

# Test user created by this script
TEST_USER="testuser"
TEST_USER_PASSWORD="testpass123"
TEST_USER_EMAIL="testuser@ztforensics.local"

ROLES=("investigator" "analyst" "auditor" "admin" "viewer")

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*" >&2; }

wait_for_keycloak() {
    info "Waiting for Keycloak to become ready at ${KEYCLOAK_URL} ..."
    local retries=0
    local max_retries=30
    until curl -sf "${KEYCLOAK_URL}/health/ready" >/dev/null 2>&1; do
        retries=$((retries + 1))
        if [ "$retries" -ge "$max_retries" ]; then
            error "Keycloak did not become ready after ${max_retries} attempts."
            exit 1
        fi
        info "  Attempt ${retries}/${max_retries} – sleeping 5 s ..."
        sleep 5
    done
    info "Keycloak is ready."
}

get_admin_token() {
    local token
    token=$(curl -sf \
        -d "client_id=admin-cli" \
        -d "username=${ADMIN_USER}" \
        -d "password=${ADMIN_PASSWORD}" \
        -d "grant_type=password" \
        "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
    echo "$token"
}

kc_post() {
    # kc_post <path> <json_body> [<token>]
    local path="$1"
    local body="$2"
    local token="${3:-$ADMIN_TOKEN}"
    curl -sf \
        -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "${KEYCLOAK_URL}${path}" || true
}

kc_get() {
    local path="$1"
    local token="${2:-$ADMIN_TOKEN}"
    curl -sf \
        -H "Authorization: Bearer ${token}" \
        "${KEYCLOAK_URL}${path}"
}

# ----------------------------------------------------------------
# Step 1: Wait for Keycloak
# ----------------------------------------------------------------
wait_for_keycloak

# ----------------------------------------------------------------
# Step 2: Obtain admin token
# ----------------------------------------------------------------
info "Obtaining admin access token ..."
ADMIN_TOKEN=$(get_admin_token)
info "Admin token obtained."

# ----------------------------------------------------------------
# Step 3: Create realm
# ----------------------------------------------------------------
info "Creating realm '${REALM}' ..."
kc_post "/admin/realms" "{
  \"realm\": \"${REALM}\",
  \"enabled\": true,
  \"displayName\": \"ZTForensics\",
  \"sslRequired\": \"external\",
  \"registrationAllowed\": false,
  \"loginWithEmailAllowed\": true,
  \"duplicateEmailsAllowed\": false,
  \"resetPasswordAllowed\": false,
  \"editUsernameAllowed\": false,
  \"bruteForceProtected\": true
}" || warn "Realm '${REALM}' may already exist – continuing."

# ----------------------------------------------------------------
# Step 4: Create roles
# ----------------------------------------------------------------
info "Creating realm roles: ${ROLES[*]} ..."
for role in "${ROLES[@]}"; do
    kc_post "/admin/realms/${REALM}/roles" \
        "{\"name\": \"${role}\", \"description\": \"ZTForensics role: ${role}\"}" \
        || warn "Role '${role}' may already exist – continuing."
    info "  Role '${role}' created/verified."
done

# ----------------------------------------------------------------
# Step 5: Create client
# ----------------------------------------------------------------
info "Creating client '${CLIENT_ID}' ..."
kc_post "/admin/realms/${REALM}/clients" "{
  \"clientId\": \"${CLIENT_ID}\",
  \"enabled\": true,
  \"protocol\": \"openid-connect\",
  \"publicClient\": false,
  \"serviceAccountsEnabled\": true,
  \"authorizationServicesEnabled\": false,
  \"directAccessGrantsEnabled\": true,
  \"standardFlowEnabled\": true,
  \"implicitFlowEnabled\": false,
  \"redirectUris\": [\"*\"],
  \"webOrigins\": [\"+\"]
}" || warn "Client '${CLIENT_ID}' may already exist – continuing."

# ----------------------------------------------------------------
# Step 6: Retrieve client secret
# ----------------------------------------------------------------
info "Retrieving client secret for '${CLIENT_ID}' ..."
CLIENT_INTERNAL_ID=$(kc_get "/admin/realms/${REALM}/clients?clientId=${CLIENT_ID}" \
    | python3 -c "import sys,json; clients=json.load(sys.stdin); print(clients[0]['id']) if clients else print('')")

if [ -z "$CLIENT_INTERNAL_ID" ]; then
    warn "Could not retrieve client internal ID – skipping secret retrieval."
else
    CLIENT_SECRET=$(kc_get "/admin/realms/${REALM}/clients/${CLIENT_INTERNAL_ID}/client-secret" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('value',''))")
    info "Client secret: ${CLIENT_SECRET}"
    info "Add this to your .env file:"
    info "  KEYCLOAK_CLIENT_SECRET=${CLIENT_SECRET}"
fi

# ----------------------------------------------------------------
# Step 7: Create test user
# ----------------------------------------------------------------
info "Creating test user '${TEST_USER}' ..."
kc_post "/admin/realms/${REALM}/users" "{
  \"username\": \"${TEST_USER}\",
  \"email\": \"${TEST_USER_EMAIL}\",
  \"enabled\": true,
  \"emailVerified\": true,
  \"credentials\": [{
    \"type\": \"password\",
    \"value\": \"${TEST_USER_PASSWORD}\",
    \"temporary\": false
  }]
}" || warn "User '${TEST_USER}' may already exist – continuing."

# ----------------------------------------------------------------
# Step 8: Assign 'investigator' role to test user
# ----------------------------------------------------------------
info "Assigning 'investigator' role to '${TEST_USER}' ..."
USER_ID=$(kc_get "/admin/realms/${REALM}/users?username=${TEST_USER}" \
    | python3 -c "import sys,json; users=json.load(sys.stdin); print(users[0]['id']) if users else print('')")

ROLE_ID=$(kc_get "/admin/realms/${REALM}/roles/investigator" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")

if [ -n "$USER_ID" ] && [ -n "$ROLE_ID" ]; then
    kc_post "/admin/realms/${REALM}/users/${USER_ID}/role-mappings/realm" \
        "[{\"id\": \"${ROLE_ID}\", \"name\": \"investigator\"}]" \
        || warn "Could not assign role – continuing."
    info "Role 'investigator' assigned to '${TEST_USER}'."
else
    warn "Could not look up user ID or role ID – skipping role assignment."
fi

# ----------------------------------------------------------------
# Done
# ----------------------------------------------------------------
echo ""
echo "============================================================"
echo " Keycloak setup complete!"
echo "============================================================"
echo " Realm:          ${REALM}"
echo " Client ID:      ${CLIENT_ID}"
echo " Test user:      ${TEST_USER} / ${TEST_USER_PASSWORD}"
echo " Roles created:  ${ROLES[*]}"
echo " Keycloak UI:    ${KEYCLOAK_URL}/admin"
echo "============================================================"
