# ZTForensics Troubleshooting Guide

## Common Issues

| Issue | Likely Cause | Solution |
|-------|-------------|---------|
| `ztf-api` exits immediately | PostgreSQL not ready | Check `docker logs ztf-api`; ensure `ztf-postgres` is healthy first |
| `"storage": "down"` in health | MinIO unreachable at API startup | Restart API: `docker compose restart ztf-api` |
| `POST /access` returns 500 | Database connection lost | Check `docker logs ztf-postgres`; verify `DATABASE_URL` |
| OPA returns `allow: true` unexpectedly | OPA unreachable; fallback to allow | Check `docker logs ztf-opa`; verify OPA port 8181 |
| Dashboard shows no data | API Gateway URL misconfigured | Check `API_GATEWAY_URL` env var in `ztf-dashboard` |
| `psycopg2.OperationalError` | Wrong DB credentials or host | Verify `DATABASE_URL` matches `docker-compose.yml` credentials |
| Port already in use | Another service on same port | `lsof -i :8000`; stop conflicting service |
| `422 Unprocessable Entity` | Missing required fields | Ensure `user_id`, `resource`, `action` are in request body |
| Chain `"valid": false` | In-memory chain reset on restart | Expected on restart; chain rebuilds from next request |
| MinIO bucket not found | First run, bucket not created | `StorageManager` auto-creates the bucket; restart `ztf-api` |
| `docker compose` not found | Using old `docker-compose` v1 | Use `docker compose` (space, not hyphen) — requires Compose v2 |

---

## Debug Mode

### Enable verbose API Gateway logging

Set `LOG_LEVEL=DEBUG` (add to `docker-compose.yml` environment section or `.env`):

```yaml
ztf-api:
  environment:
    LOG_LEVEL: DEBUG
```

Then restart:

```bash
docker compose up -d ztf-api
docker logs -f ztf-api
```

### Run the API Gateway locally (outside Docker) for debugging

```bash
cd api_gateway
pip install -r requirements.txt
LOG_LEVEL=DEBUG uvicorn main:app --reload --port 8000
```

This requires `ztf-postgres`, `ztf-opa`, and `ztf-minio` to be reachable at `localhost` (use the `.env` defaults).

---

## Docker Logs Commands

```bash
# Stream all service logs together
docker compose logs -f

# API Gateway
docker logs -f ztf-api
docker logs --tail=50 ztf-api

# OPA policy engine
docker logs -f ztf-opa

# PostgreSQL
docker logs -f ztf-postgres

# MinIO
docker logs -f ztf-minio

# Dashboard
docker logs -f ztf-dashboard

# Filter for errors only
docker logs ztf-api 2>&1 | grep -i "error\|exception\|traceback"

# Check last restart reason
docker inspect ztf-api --format '{{.State.ExitCode}} {{.State.Error}}'
```

---

## Database Connection Debugging

### Check PostgreSQL is running and healthy

```bash
docker exec ztf-postgres pg_isready -U ztf -d ztfdb
# Expected: /var/run/postgresql:5432 - accepting connections
```

### Connect to PostgreSQL directly

```bash
docker exec -it ztf-postgres psql -U ztf -d ztfdb
```

### Inspect the access_logs table

```sql
-- From inside psql:
\dt                         -- list tables
SELECT COUNT(*) FROM access_logs;
SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 5;
SELECT decision, COUNT(*) FROM access_logs GROUP BY decision;
SELECT user_id, COUNT(*) FROM access_logs WHERE decision='deny' GROUP BY user_id ORDER BY 2 DESC;
```

### Verify DATABASE_URL

```bash
docker exec ztf-api env | grep DATABASE_URL
# Should output: DATABASE_URL=postgresql://ztf:ztfpass@ztf-postgres:5432/ztfdb
```

### Test database connection from API container

```bash
docker exec -it ztf-api python -c "
from database import get_db, init_db
import sqlalchemy
engine = sqlalchemy.create_engine('postgresql://ztf:ztfpass@ztf-postgres:5432/ztfdb')
with engine.connect() as conn:
    result = conn.execute(sqlalchemy.text('SELECT 1'))
    print('DB OK:', result.scalar())
"
```

### Reset the database (development only)

```bash
docker compose down -v                   # removes all volumes
docker compose up -d ztf-postgres        # recreate DB
docker compose up -d                     # start all services
```

---

## MinIO Connection Debugging

### Check MinIO is running

```bash
curl -s http://localhost:9000/minio/health/live
# Expected: HTTP 200 (empty body)
```

### Open MinIO web console

Navigate to **http://localhost:9001** in your browser.  
Default credentials: `minioadmin` / `minioadmin123`

### Verify MinIO env vars in API container

```bash
docker exec ztf-api env | grep -E "MINIO_|STORAGE"
```

### Check storage status via health endpoint

```bash
curl -s http://localhost:8000/health | jq .services.storage
```

### Test MinIO connection manually

```bash
docker exec -it ztf-api python -c "
from minio import Minio
client = Minio('ztf-minio:9000', access_key='minioadmin', secret_key='minioadmin123', secure=False)
buckets = client.list_buckets()
print('Buckets:', [b.name for b in buckets])
"
```

### Force re-initialise MinIO storage

```bash
docker compose restart ztf-api
# StorageManager is initialised on API startup and creates the bucket if missing
```

---

## OPA Policy Debugging

### Check OPA is running and responsive

```bash
curl -s http://localhost:8181/health | jq .
# Expected: {"status": "ok"}
```

### Check loaded policies

```bash
curl -s http://localhost:8181/v1/policies | jq '.[].id'
# Should include the ztf.authz policy
```

### Evaluate a policy decision directly

```bash
curl -s -X POST http://localhost:8181/v1/data/ztf/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "test",
      "resource": "test",
      "action": "READ",
      "ip_address": "203.0.113.1",
      "user_agent": "Mozilla/5.0",
      "hour": 12,
      "country": "US",
      "role": "user",
      "failure_count": 0
    }
  }' | jq .result
```

### Check for Rego syntax errors

```bash
docker logs ztf-opa 2>&1 | grep -i "error\|failed\|policy"
```

### Reload policies manually (OPA uses --watch, but to force)

```bash
docker compose restart ztf-opa
```

### Dry-run a policy change with OPA CLI

```bash
# Install OPA CLI locally
curl -L -o opa https://openpolicyagent.org/downloads/v0.68.0/opa_linux_amd64_static
chmod +x opa

# Evaluate policy
./opa eval -i input.json -d opa/policies/opa_policies.rego "data.ztf.authz.allow"
```

Where `input.json` contains your test input (without the `"input":` wrapper):
```json
{
  "user_id": "test",
  "resource": "reports",
  "action": "READ",
  "ip_address": "203.0.113.1",
  "user_agent": "Mozilla/5.0",
  "hour": 10,
  "country": "US",
  "role": "user",
  "failure_count": 0
}
```

---

## Startup Sequence Issues

### API Gateway fails to connect to PostgreSQL

```bash
docker logs ztf-api 2>&1 | head -20
```

If you see `connection refused` or `could not connect`:

```bash
# Check Postgres health
docker inspect ztf-postgres --format '{{.State.Health.Status}}'
# Wait for "healthy", then restart API:
docker compose restart ztf-api
```

### OPA not loaded when API starts

```bash
docker logs ztf-opa 2>&1 | tail -10
# Check for policy load errors
# API falls back to allow when OPA is unreachable — check warn logs in ztf-api
```

---

## Performance Tuning Tips

### 1. Increase database connection pool size

The SQLAlchemy engine can be tuned in `api_gateway/database.py`:

```python
engine = create_engine(
    DATABASE_URL,
    pool_size=20,        # default: 5
    max_overflow=40,     # default: 10
    pool_pre_ping=True,  # validate connections before use
)
```

### 2. Reduce OPA query timeout

In `api_gateway/main.py`, the OPA timeout is currently 5 seconds:

```python
async with httpx.AsyncClient(timeout=5.0) as client:
```

Reduce to `timeout=2.0` in environments where OPA response times are consistently fast.

### 3. Use async PostgreSQL driver

Replace `psycopg2-binary` with `asyncpg` + `databases` for fully async database access to improve throughput under high load.

### 4. Cache repeated OPA decisions

For read-heavy workloads with low variance, cache OPA decisions in Redis (TTL: 60 seconds) keyed by `(user_id, resource, action, ip_address, hour)`.

### 5. Profile slow endpoints

```bash
# Install py-spy (from host)
pip install py-spy

# Profile the running API container
docker exec ztf-api pip install py-spy
docker exec -it ztf-api py-spy top --pid 1
```

### 6. Monitor PostgreSQL query performance

```sql
-- From inside psql, find slow queries:
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

Enable `pg_stat_statements` by adding to PostgreSQL config:
```
shared_preload_libraries = 'pg_stat_statements'
```
