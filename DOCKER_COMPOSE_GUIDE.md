# Docker Compose Guide

This guide describes every service defined in `docker-compose.yml`.

---

## Services

### `ztf-postgres` – Application Database

| Item | Value |
|---|---|
| Image | `postgres:16.4` |
| Port | `5432:5432` |
| Credentials | `ztf` / `ztfpass` |
| Database | `ztfdb` |
| Volume | `ztforensics_postgres_data` |

The primary PostgreSQL instance used by the API Gateway to persist access
logs, blockchain hashes, and other forensic records.

**Environment variables:**

| Variable | Description |
|---|---|
| `POSTGRES_USER` | Database username |
| `POSTGRES_PASSWORD` | Database password |
| `POSTGRES_DB` | Database name |

---

### `ztf-keycloak-db` – Keycloak Database

| Item | Value |
|---|---|
| Image | `postgres:16.4` |
| Port | `5433:5432` |
| Credentials | `keycloak` / `keycloakpass` |
| Database | `keycloakdb` |
| Volume | `ztforensics_keycloak_db_data` |

A dedicated PostgreSQL instance for Keycloak's internal storage. Kept
separate from the application database for isolation.

---

### `ztf-keycloak` – Identity Provider

| Item | Value |
|---|---|
| Image | `quay.io/keycloak/keycloak:26.1.4` |
| Port | `8080:8080` |
| Admin UI | http://localhost:8080/admin |
| Depends on | `ztf-keycloak-db` (healthy) |

Keycloak provides OpenID Connect / OAuth 2.0 authentication. The API
Gateway validates JWTs signed by Keycloak on every protected request.

**Key environment variables:**

| Variable | Description |
|---|---|
| `KC_DB` | Database type (`postgres`) |
| `KC_DB_URL` | JDBC connection string |
| `KC_HOSTNAME` | Public hostname |
| `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` | Initial admin credentials |

---

### `ztf-minio` – Object Storage

| Item | Value |
|---|---|
| Image | `minio/minio:RELEASE.2025-02-28T09-55-16Z` |
| Ports | `9000:9000` (API), `9001:9001` (Console) |
| Console | http://localhost:9001 |
| Volume | `ztforensics_minio_data` |

S3-compatible object storage for large forensic evidence files.

**Environment variables:**

| Variable | Description |
|---|---|
| `MINIO_ROOT_USER` | Access key (maps to `MINIO_ACCESS_KEY`) |
| `MINIO_ROOT_PASSWORD` | Secret key (maps to `MINIO_SECRET_KEY`) |

---

### `ztf-opa` – Policy Engine

| Item | Value |
|---|---|
| Image | `openpolicyagent/opa:0.68.0` |
| Port | `8181:8181` |
| Policy mount | `./opa/policies:/policies` (read-only) |

Open Policy Agent evaluates access-control policies written in Rego.
The API Gateway forwards every access request to OPA for a `allow/deny` decision.

Health endpoint: `GET http://localhost:8181/health`

---

### `ztf-api` – API Gateway

| Item | Value |
|---|---|
| Build | `api_gateway/Dockerfile` |
| Port | `8000:8000` |
| Depends on | `ztf-postgres` (healthy), `ztf-opa` (healthy), `ztf-keycloak` (healthy) |

FastAPI application that:
- Validates JWTs issued by Keycloak
- Calculates a risk score for each access request
- Queries OPA for an `allow/deny` decision
- Persists each decision as a blockchain-chained log entry

**Key environment variables (set via `.env`):**

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `OPA_URL` | OPA base URL |
| `MINIO_ENDPOINT` | MinIO host:port |
| `KEYCLOAK_SERVER_URL` | Keycloak base URL |
| `KEYCLOAK_REALM` | Keycloak realm |
| `KEYCLOAK_CLIENT_ID` | Client ID |
| `KEYCLOAK_CLIENT_SECRET` | Client secret |
| `SECRET_KEY` | Application secret key |
| `LOG_LEVEL` | Logging level |

---

### `ztf-dashboard` – Web Dashboard

| Item | Value |
|---|---|
| Build | `dashboard/Dockerfile` |
| Port | `5000:5000` |
| Depends on | `ztf-api` (healthy) |

Flask web application that displays real-time forensic evidence, access
logs, blockchain verification status, and Keycloak login/logout flows.

**Key environment variables:**

| Variable | Description |
|---|---|
| `API_GATEWAY_URL` | Internal URL to reach `ztf-api` |
| `KEYCLOAK_SERVER_URL` | Keycloak base URL (public) |
| `KEYCLOAK_LOGIN_URL` | OIDC authorization endpoint |

---

## Volume Mounts

| Volume | Service | Purpose |
|---|---|---|
| `ztforensics_postgres_data` | `ztf-postgres` | Persistent app database storage |
| `ztforensics_keycloak_db_data` | `ztf-keycloak-db` | Persistent Keycloak database storage |
| `ztforensics_minio_data` | `ztf-minio` | Persistent object storage |
| `./opa/policies` (bind mount) | `ztf-opa` | OPA Rego policy files |

---

## Health Checks

Every service declares a Docker health check. Use `docker compose ps` to
view status. All services should show `(healthy)` before the API Gateway
starts accepting traffic.

| Service | Health check command |
|---|---|
| `ztf-postgres` | `pg_isready -U ztf -d ztfdb` |
| `ztf-keycloak-db` | `pg_isready -U keycloak -d keycloakdb` |
| `ztf-keycloak` | `GET /health/ready` |
| `ztf-minio` | `mc ready local` |
| `ztf-opa` | `GET /health` |
| `ztf-api` | `GET /health` |
| `ztf-dashboard` | `GET /` |

---

## Service Dependencies

```
ztf-keycloak-db
    └── ztf-keycloak (depends on ztf-keycloak-db healthy)
ztf-postgres
ztf-minio
ztf-opa
    ↳ ztf-api (depends on ztf-postgres healthy + ztf-opa healthy + ztf-keycloak healthy)
        └── ztf-dashboard (depends on ztf-api healthy)
```

---

## Networking

All services join the `ztforensics_ztf-net` bridge network. Services
communicate using their container names as hostnames:

| Hostname | Service |
|---|---|
| `ztf-postgres` | Application database |
| `ztf-keycloak-db` | Keycloak database |
| `ztf-keycloak` | Identity provider |
| `ztf-minio` | Object storage |
| `ztf-opa` | Policy engine |
| `ztf-api` | API Gateway |
| `ztf-dashboard` | Web dashboard |

---

## Scaling Considerations

- `ztf-api` is stateless and can be scaled horizontally:
  ```bash
  docker compose up -d --scale ztf-api=3
  ```
  Place a load balancer (Nginx, Traefik) in front of the replicas.
- `ztf-dashboard` can similarly be scaled.
- PostgreSQL and MinIO require a single primary in basic deployments.
  For HA, consider managed services (AWS RDS, GCP Cloud SQL, AWS S3).

---

## Log Management

All services use the `json-file` log driver with rotation:

```bash
docker compose logs -f ztf-api      # stream API Gateway logs
docker compose logs --tail 100 ztf-keycloak
```

Log files are stored at `/var/lib/docker/containers/<id>/<id>-json.log`
on the Docker host and rotate when they reach the configured `max-size`.
