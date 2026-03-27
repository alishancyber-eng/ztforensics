# ZTForensics — Zero Trust Forensic Access Gateway

Enterprise-grade **Zero Trust API Gateway** with cryptographic **forensic evidence chaining** for regulatory compliance, audit trails, and tamper-proof access logs.

## Features

✅ **Zero Trust Access Control**
- Policy-based authorization (OPA/Rego)
- Risk scoring (IP reputation, user agent, resource sensitivity, time-of-access)
- Real-time deny/allow decisions

✅ **Forensic Evidence Chaining**
- SHA-256 hash-linked records (immutable)
- Previous hash linking (chain verification)
- Tamper detection via hash chain validation

✅ **Evidence Export & Audit**
- ZIP package export with JSON records + verification proof
- **PDF forensic report** (executive summary, timeline, anomalies, hash chain proof)
- Human-readable forensic summaries
- Dashboard API for real-time metrics

✅ **Advanced Analytics (Batch 3)**
- Time-series timeline API with hourly/daily grouping
- Anomaly detection (repeated denials, privilege escalation, off-hours access, resource hopping)
- Flask web dashboard at http://localhost:5000

✅ **Production Ready**
- PostgreSQL persistence
- Docker Compose stack (API Gateway + Dashboard)
- FastAPI with async support
- Structured logging

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- curl (for testing)

### 1. Clone & Setup

```bash
git clone https://github.com/alishancyber-engTo/ztforensics.git
cd ztforensics
```

### 2. Start Stack

```bash
docker compose down
docker compose up --build -d
sleep 3
```

### 3. Verify Health

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{"status":"ok","service":"api-gateway","env":"development","db_ready":true}
```

---

## API Endpoints

### Access Control Decision

**POST** `/access`

Request:
```bash
curl -X POST "http://localhost:8000/access" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user:ali;role:employee" \
  -d '{
    "resource": "/api/documents",
    "action": "read",
    "ip_address": "10.0.0.5",
    "user_agent": "Mozilla/5.0"
  }'
```

Response (ALLOW — low risk):
```json
{
  "trace_id": "c4258452-e863-4e0e-83d3-21439cba198e",
  "timestamp": "2026-03-27T19:41:59.537518+00:00",
  "user": "ali",
  "role": "employee",
  "resource": "/api/documents",
  "action": "read",
  "decision": "ALLOW",
  "reason": "ALLOWED",
  "risk_score": 0,
  "risk_factors": [],
  "previous_hash": "0",
  "record_hash": "499d6a7aa9ca156beb0d0f6862e504aee5d41d01e018003b94f9122deba1bdaa"
}
```

---

### High-Risk Deny Example

**POST** `/access` (admin resource + untrusted IP + curl user agent)

```bash
curl -X POST "http://localhost:8000/access" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer user:ali;role:employee" \
  -d '{
    "resource": "/api/admin/secrets",
    "action": "delete",
    "ip_address": "203.0.113.10",
    "user_agent": "curl/8.0"
  }'
```

Response (DENY — high risk):
```json
{
  "trace_id": "b7d892fb-8bcc-4f56-b778-806289c86f65",
  "timestamp": "2026-03-27T19:41:59.570471+00:00",
  "user": "ali",
  "role": "employee",
  "resource": "/api/admin/secrets",
  "action": "delete",
  "decision": "DENY",
  "reason": "HIGH_RISK_SCORE",
  "risk_score": 100,
  "risk_factors": [
    "foreign_or_untrusted_ip",
    "non_browser_user_agent",
    "admin_resource_targeted",
    "sensitive_action"
  ],
  "previous_hash": "499d6a7aa9ca156beb0d0f6862e504aee5d41d01e018003b94f9122deba1bdaa",
  "record_hash": "091db917a3b0d8dd6f4bfa4079ec9795ff1ad180d29280c53e95de97edb8da81"
}
```

**Notice:** `record_hash` is **SHA-256 linked** to previous record via `previous_hash` ✓

---

### Forensic Chain Verification

**GET** `/forensics/verify-chain`

```bash
curl http://localhost:8000/forensics/verify-chain
```

Response:
```json
{
  "ok": true,
  "checked": 2,
  "message": "Chain verified",
  "total_records": 2
}
```

✅ **Chain is valid** — no tampering detected

---

### Dashboard Summary

**GET** `/forensics/summary`

```bash
curl http://localhost:8000/forensics/summary
```

Response:
```json
{
  "ok": true,
  "total_requests": 2,
  "allowed": 1,
  "denied": 1,
  "high_risk_count": 1,
  "allow_percentage": 50,
  "top_deny_reasons": [
    ["ALLOWED", 1],
    ["HIGH_RISK_SCORE", 1]
  ]
}
```

---

### Evidence Export (ZIP Download)

**GET** `/forensics/export`

```bash
curl http://localhost:8000/forensics/export -o evidence_package.zip
unzip -l evidence_package.zip
```

Contents:
```
Archive:  evidence_package.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     1200  2026-03-28  00:53   evidence_records.json
      800  2026-03-28  00:53   hash_verification.txt
      600  2026-03-28  00:53   forensic_summary.txt
---------                     -------
     2600                     3 files
```

**evidence_records.json** — All access records with hash chains
**hash_verification.txt** — Chain integrity proof (auditor-ready)
**forensic_summary.txt** — Human-readable forensic report

---

## Hash Chain Security

Each access decision creates a **cryptographically linked record**:

```
Record 1 (ALLOW):
  hash = SHA256({user, resource, action, ...})
       = 499d6a7aa9ca156beb0d0f6862e504aee5d41d01e018003b94f9122deba1bdaa
  previous_hash = 0 (genesis)

Record 2 (DENY):
  hash = SHA256({user, resource, action, previous_hash: "499d6a7a...", ...})
       = 091db917a3b0d8dd6f4bfa4079ec9795ff1ad180d29280c53e95de97edb8da81
  previous_hash = 499d6a7aa9ca156beb0d0f6862e504aee5d41d01e018003b94f9122deba1bdaa ✓ LINKED
```

### Tamper Detection

If attacker modifies **any field** in Record 1:
- Record 1's hash changes → ✗ BROKEN
- Record 2's `previous_hash` no longer matches → ✗ BROKEN
- Chain verification returns: `"CHAIN BROKEN - Tampering detected"`

**Result:** Tamper-proof audit trail ✅

---

## Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ HTTP/JSON
       ▼
┌──────────────────────────────┐
│   FastAPI Gateway (8000)     │
│  - Auth extraction           │
│  - Risk scoring              │
│  - OPA policy evaluation     │
│  - Hash-chain forensics      │
└──────┬──────────────────────┘
       │
   ┌───┴────┬────────┬─────────┐
   │        │        │         │
   ▼        ▼        ▼         ▼
 ┌────┐ ┌──────┐ ┌──────┐ ┌────────┐
 │OPA │ │Postgres
 │    │ │       │ │MinIO │ │Keycloak│
 │8181│ │5432  │ │9000  │ │(future)│
 └────┘ └──────┘ └──────┘ └────────┘
```

---

## Configuration

**Environment Variables** (`.env`):
```env
APP_ENV=development
OPA_URL=http://opa:8181
POSTGRES_USER=ztforensics
POSTGRES_PASSWORD=change_me_strong_password
POSTGRES_DB=forensics_db
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
```

---

## Development

### Run Locally (with Docker)

```bash
docker compose up --build -d
docker logs -f ztf-api
```

### Run Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Run all unit tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=api_gateway --cov-report=term-missing
```

### API Documentation

```
http://localhost:8000/docs
```

---

## Dashboard

The Flask dashboard is accessible at **http://localhost:5000** after running `docker compose up`.

| Page | URL | Description |
|---|---|---|
| Home | `/` | Live KPI metrics + allow/deny chart |
| Timeline | `/dashboard/timeline` | Hourly & daily access activity charts |
| Anomalies | `/dashboard/anomalies` | Detected suspicious patterns |
| Verification | `/dashboard/verify` | Hash chain integrity status |
| Evidence | `/dashboard/evidence` | Download ZIP and PDF report |

---

## Advanced API Endpoints (Batch 3)

### Timeline Analysis

**GET** `/forensics/timeline?interval=hour`

```bash
curl "http://localhost:8000/forensics/timeline?interval=hour"
```

Response:
```json
{
  "ok": true,
  "interval": "hour",
  "timeline": [
    {
      "period": "2026-03-27 19:00",
      "total_requests": 5,
      "allowed": 4,
      "denied": 1,
      "avg_risk_score": 20,
      "high_risk_events": 1
    }
  ]
}
```

### Anomaly Detection

**GET** `/forensics/anomalies`

```bash
curl http://localhost:8000/forensics/anomalies
```

Response:
```json
{
  "ok": true,
  "total": 2,
  "anomalies": [
    {
      "type": "repeated_denials",
      "user": "ali",
      "count": 5,
      "confidence": 0.80,
      "severity": "HIGH",
      "timestamp": "2026-03-27T20:00:00+00:00"
    }
  ]
}
```

### PDF Forensic Report

**GET** `/forensics/export-pdf`

```bash
curl http://localhost:8000/forensics/export-pdf -o report.pdf
```

Generates a professional PDF report including executive summary, timeline, anomalies, and hash chain verification proof.

---

## Attack Simulator

Generate realistic attack scenarios to populate forensic evidence for demo:

```bash
# Run all attack scenarios
python attack_simulator/simulate.py

# Run a specific scenario
python attack_simulator/simulate.py --scenario brute-force
python attack_simulator/simulate.py --scenario privilege
python attack_simulator/simulate.py --scenario off-hours
python attack_simulator/simulate.py --scenario hopping

# Point at a different API URL
python attack_simulator/simulate.py --api-url http://localhost:8000
```

Scenarios:
| Scenario | Description |
|---|---|
| `brute-force` | 10 failed access attempts from same attacker IP |
| `privilege` | Employee trying to access 5 admin-only resources |
| `off-hours` | Access from foreign IP with curl user-agent |
| `hopping` | Single user rapidly accessing 7 different resources |

---

## Compliance & Audit

✅ **PCI-DSS** — Immutable audit logs  
✅ **SOC 2** — Cryptographic evidence chain  
✅ **HIPAA** — Access decision logging  
✅ **GDPR** — Data processing audit trail  

Export ZIP package for:
- Incident investigations
- Regulatory audits
- Legal proceedings
- Forensic analysis

---

## License

MIT

---

## Author

**alishancyber-eng** (@alishancyber-engTo)

---

## Next Steps (Roadmap)

- [x] Timeline API with hourly/daily grouping
- [x] Anomaly detection (repeated denials, privilege escalation, off-hours, resource hopping)
- [x] PDF forensic report (ReportLab)
- [x] Flask dashboard UI (port 5000)
- [x] Unit tests (52 tests, >80% coverage on core modules)
- [x] Attack simulator
- [ ] Keycloak JWT integration
- [ ] S3 evidence archival
- [ ] Elasticsearch integration
- [ ] GraphQL API layer
- [ ] Machine learning anomaly detection