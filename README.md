# ZTForensics

![Python](https://img.shields.io/badge/python-3.12-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)
![Docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker)
![OPA](https://img.shields.io/badge/OPA-0.68.0-7D4698?logo=openpolicyagent)
![License](https://img.shields.io/badge/license-MIT-green)

**Zero Trust Forensic Gateway** — policy-driven access control with a tamper-evident audit trail.

ZTForensics enforces Zero Trust security principles on every request: every access attempt is evaluated against 10 contextual risk factors, decided by Open Policy Agent, logged to PostgreSQL, and chained into a SHA-256 blockchain for forensic integrity. No request is ever implicitly trusted.

---

## Features

- 🔒 **Zero Trust enforcement** — every request evaluated independently, no implicit trust
- 🧠 **10-factor risk scoring** — IP reputation, user agent, time-of-day, geolocation, action type, resource sensitivity, brute-force detection, device compliance, role baseline, VPN detection
- ⚖️ **OPA policy engine** — declarative Rego policies, hot-reloaded without restarts
- ⛓️ **Blockchain audit trail** — SHA-256 hash chain detects any post-hoc log tampering
- 🗄️ **PostgreSQL persistence** — all access decisions stored with full context
- 📦 **MinIO object storage** — S3-compatible evidence and export storage
- 📊 **Real-time dashboard** — Flask web UI with live forensic statistics
- 🔍 **Forensic export** — complete evidence bundle as verifiable JSON
- 🩺 **Health monitoring** — per-service health checks with dependency status
- 🐳 **One-command deployment** — full stack via Docker Compose

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Browser / Client                  │
└──────────────────────┬──────────────────────────────┘
                       │  :5000
                       ▼
            ┌──────────────────────┐
            │  Dashboard (Flask)   │
            └──────────┬───────────┘
                       │  :8000
                       ▼
            ┌──────────────────────┐
            │  API Gateway         │
            │  (FastAPI)           │
            └──┬──────┬────────┬───┘
         :8181 │ :5432 │  :9000 │
               ▼       ▼        ▼
          ┌────────┐ ┌────┐ ┌───────┐
          │  OPA   │ │ PG │ │ MinIO │
          └────────┘ └────┘ └───────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system design, data flow diagrams, and component descriptions.

---

## Quick Start

### Prerequisites

- Docker Engine 24.0+ and Docker Compose v2.20+

### 1. Clone the repository

```bash
git clone https://github.com/your-org/ztforensics.git
cd ztforensics
```

### 2. Configure environment

```bash
cp .env .env.local
# Edit .env.local to change credentials for production use
```

### 3. Start the full stack

```bash
docker compose up --build -d
```

That's it. All five services start in the correct order.

| Service           | URL                         | Description              |
|-------------------|-----------------------------|--------------------------|
| Dashboard         | http://localhost:5000        | Web UI                   |
| API Gateway       | http://localhost:8000        | REST API                 |
| API Docs          | http://localhost:8000/docs   | Swagger UI               |
| OPA               | http://localhost:8181        | Policy engine            |
| MinIO Console     | http://localhost:9001        | Object storage UI        |

### 4. Send a test access request

```bash
curl -s -X POST http://localhost:8000/access \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "alice",
    "resource": "reports/q4",
    "action": "READ",
    "ip_address": "203.0.113.42",
    "user_agent": "Mozilla/5.0"
  }' | jq .
```

```json
{
  "decision": "allow",
  "risk_score": 0.05,
  "reason": "Access granted",
  "chain_hash": "a3f2c1d4e5b6..."
}
```

### 5. Verify blockchain integrity

```bash
curl -s http://localhost:8000/forensics/verify-chain | jq .
```

---

## Testing

```bash
# Install test dependencies
pip install -r api_gateway/requirements.txt

# Run the full test suite with coverage
pytest tests/ --cov=api_gateway --cov-report=term-missing -v

# Run a specific test file
pytest tests/test_api.py -v
```

Tests are located in `tests/` and cover unit, integration, edge case, error handling, and storage scenarios. The project targets **95%+ line coverage**.

---

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, component diagram, data flow, blockchain |
| [API_REFERENCE.md](API_REFERENCE.md) | All endpoints, request/response schemas, error codes |
| [SECURITY.md](SECURITY.md) | Zero Trust model, 10 risk factors, threat model |
| [OPA_POLICIES.md](OPA_POLICIES.md) | Rego policy documentation, testing guide, how to add rules |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Docker Compose setup, env vars, production considerations |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues, debug commands, performance tuning |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, code style, PR process |

---

## Tech Stack

| Layer            | Technology                   | Version     |
|------------------|------------------------------|-------------|
| API Gateway      | FastAPI + Uvicorn             | 0.115 / 0.34 |
| Dashboard        | Flask                        | 3.x          |
| Policy Engine    | Open Policy Agent (OPA)      | 0.68.0       |
| Database         | PostgreSQL                   | 16.4         |
| Object Storage   | MinIO                        | 2025-02      |
| ORM              | SQLAlchemy                   | 2.0          |
| HTTP Client      | httpx                        | 0.28         |
| Data Validation  | Pydantic                     | 2.10         |
| Testing          | pytest + pytest-asyncio      | 8.x / 0.25   |
| Container        | Docker Compose               | v2           |

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.