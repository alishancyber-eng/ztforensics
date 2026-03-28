# ZTForensics Deployment Guide

## Prerequisites

| Requirement          | Minimum Version | Notes                                    |
|----------------------|-----------------|------------------------------------------|
| Docker Engine        | 24.0+           | `docker --version`                       |
| Docker Compose       | v2.20+          | `docker compose version` (note: no dash) |
| Available RAM        | 2 GB            | 4 GB recommended for production          |
| Available disk       | 5 GB            | For images, database, and MinIO data     |
| Ports available      | 5000, 8000, 8181, 5432, 9000, 9001 | All must be free on the host  |

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-org/ztforensics.git
cd ztforensics
```

### 2. Configure environment variables

```bash
cp .env .env.local
# Edit .env.local to override any defaults (see Environment Variables below)
```

### 3. Start all services

```bash
docker compose up --build -d
```

The `--build` flag rebuilds the API Gateway and Dashboard images. Omit it on subsequent starts if code has not changed.

### 4. Verify services are running

```bash
docker compose ps
```

Expected output:

```
NAME             IMAGE                          STATUS
ztf-postgres     postgres:16.4                  Up (healthy)
ztf-minio        minio/minio:...                Up
ztf-opa          openpolicyagent/opa:0.68.0     Up
ztf-api          ztforensics-ztf-api            Up
ztf-dashboard    ztforensics-ztf-dashboard      Up
```

### 5. Confirm health

```bash
curl -s http://localhost:8000/health | jq .
```

```json
{
  "status": "healthy",
  "services": {
    "database": "up",
    "blockchain": "up",
    "storage": "up"
  }
}
```

### 6. Open the Dashboard

Navigate to **http://localhost:5000** in your browser.

---

## Environment Variables

All variables can be set in the `.env` file at the project root. Docker Compose reads this file automatically.

### API Gateway (`ztf-api`)

| Variable          | Default                                         | Description                                        |
|-------------------|-------------------------------------------------|----------------------------------------------------|
| `DATABASE_URL`    | `postgresql://ztf:ztfpass@ztf-postgres:5432/ztfdb` | PostgreSQL connection string                    |
| `OPA_URL`         | `http://ztf-opa:8181`                           | OPA REST API base URL                              |
| `MINIO_ENDPOINT`  | `ztf-minio:9000`                                | MinIO endpoint (host:port, no scheme)              |
| `MINIO_ACCESS_KEY`| `minioadmin`                                    | MinIO access key (username)                        |
| `MINIO_SECRET_KEY`| `minioadmin123`                                 | MinIO secret key (password) — change in production |

### PostgreSQL (`ztf-postgres`)

| Variable            | Default    | Description                    |
|---------------------|------------|--------------------------------|
| `POSTGRES_USER`     | `ztf`      | Database user                  |
| `POSTGRES_PASSWORD` | `ztfpass`  | Database password — change in production |
| `POSTGRES_DB`       | `ztfdb`    | Database name                  |

### MinIO (`ztf-minio`)

| Variable              | Default         | Description                         |
|-----------------------|-----------------|-------------------------------------|
| `MINIO_ROOT_USER`     | `minioadmin`    | MinIO root user — change in production |
| `MINIO_ROOT_PASSWORD` | `minioadmin123` | MinIO root password — change in production |

### Dashboard (`ztf-dashboard`)

| Variable            | Default                   | Description                         |
|---------------------|---------------------------|-------------------------------------|
| `API_GATEWAY_URL`   | `http://ztf-api:8000`     | API Gateway URL (internal Docker DNS) |

---

## Health Check Commands

```bash
# API Gateway health
curl -s http://localhost:8000/health | jq .

# Blockchain integrity
curl -s http://localhost:8000/forensics/verify-chain | jq '{valid: .valid, blocks: .total_blocks}'

# PostgreSQL (from host)
docker exec ztf-postgres pg_isready -U ztf -d ztfdb

# OPA status
curl -s http://localhost:8181/health | jq .

# MinIO health
curl -s http://localhost:9000/minio/health/live

# Dashboard
curl -s http://localhost:5000/api/health | jq .
```

---

## Service Startup Order

Docker Compose enforces the following dependency chain:

```
ztf-postgres (healthy) ─┐
ztf-opa (started)       ├─► ztf-api (started) ─► ztf-dashboard (started)
```

The API Gateway will not start until PostgreSQL reports healthy via `pg_isready`. This prevents database connection errors on startup.

---

## Stopping Services

```bash
# Stop all services (keep data volumes)
docker compose down

# Stop and remove all volumes (destroys database data)
docker compose down -v

# Stop a single service
docker compose stop ztf-api
```

---

## Rebuilding After Code Changes

```bash
# Rebuild a specific service
docker compose up --build -d ztf-api

# Rebuild all services
docker compose up --build -d
```

---

## Production Setup Considerations

### 1. Change all default credentials

```bash
# In your production .env file:
POSTGRES_PASSWORD=<strong-random-password>
MINIO_ROOT_USER=<non-default-user>
MINIO_ROOT_PASSWORD=<strong-random-password>
MINIO_ACCESS_KEY=<non-default-key>
MINIO_SECRET_KEY=<strong-random-password>
```

### 2. Remove external port bindings for internal services

In `docker-compose.yml`, remove or comment out these port bindings for production:

```yaml
# ztf-postgres — do not expose to host in production
# ports:
#   - "5432:5432"

# ztf-opa — do not expose to host in production
# ports:
#   - "8181:8181"
```

### 3. Set up a reverse proxy with TLS

Use **nginx** or **Caddy** in front of the Dashboard (5000) and API Gateway (8000):

**Example nginx config snippet**:

```nginx
server {
    listen 443 ssl;
    server_name api.your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 4. Persist MinIO data with a named volume

```yaml
# docker-compose.yml
ztf-minio:
  volumes:
    - minio_data:/data

volumes:
  minio_data:
```

### 5. Persist PostgreSQL data with a named volume

```yaml
ztf-postgres:
  volumes:
    - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### 6. Configure resource limits

```yaml
ztf-api:
  deploy:
    resources:
      limits:
        cpus: '1.0'
        memory: 512M
```

### 7. Enable OPA decision logging

Add `--log-level=debug` or configure an OPA decision log plugin to capture all policy evaluations.

---

## SSL/TLS Setup Notes

ZTForensics services do not handle TLS directly. TLS should be terminated at the reverse proxy layer.

**Recommended stack**:
- **Caddy** (automatic HTTPS via Let's Encrypt): simplest option
- **nginx + Certbot**: common in existing infrastructure
- **AWS ALB / GCP Load Balancer**: for cloud deployments

Ensure the following headers are forwarded so the API Gateway can log the correct client IP:
- `X-Real-IP`
- `X-Forwarded-For`
- `X-Forwarded-Proto`

---

## Scaling Guidelines

### Horizontal scaling of the API Gateway

The API Gateway can be scaled horizontally. However, note:

- **Blockchain state is in-memory** per process. Multiple instances maintain independent chains. A shared Redis or database-backed chain is required for true horizontal scaling.
- **Failure counters** (`_failure_counts`) are per-process. Use Redis to share state across instances.

```bash
# Scale to 3 API Gateway replicas (requires swarm or external load balancer)
docker compose up --scale ztf-api=3 -d
```

### Database connection pooling

For high-throughput deployments, add **PgBouncer** between the API Gateway and PostgreSQL to pool connections:

```yaml
ztf-pgbouncer:
  image: edoburu/pgbouncer
  environment:
    DATABASE_URL: "postgresql://ztf:ztfpass@ztf-postgres:5432/ztfdb"
    POOL_MODE: transaction
    MAX_CLIENT_CONN: 200
```

### MinIO cluster mode

For production, replace single-node MinIO with a distributed cluster:

```bash
# Example: 4-node MinIO cluster
minio server http://minio{1...4}/data
```

---

## Viewing Logs

```bash
# All services
docker compose logs -f

# API Gateway only
docker logs -f ztf-api

# OPA policy decisions
docker logs -f ztf-opa

# PostgreSQL
docker logs -f ztf-postgres

# Dashboard
docker logs -f ztf-dashboard

# Last 100 lines
docker logs --tail=100 ztf-api
```
