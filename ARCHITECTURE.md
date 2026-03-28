# ZTForensics System Architecture

## Overview

ZTForensics is a **Zero Trust Forensic Gateway** that enforces continuous, policy-driven access control on every request — regardless of network location or prior authentication. All access decisions are logged in a tamper-evident blockchain-style hash chain and stored in both a relational database and object storage, creating a complete, verifiable audit trail suitable for forensic investigation.

The system is composed of five independently deployable services orchestrated via Docker Compose and communicating over an isolated bridge network (`ztf-net`).

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Client / Browser                           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  HTTP (port 5000)
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                   Dashboard  (Flask · ztf-dashboard:5000)            │
│   • Renders real-time forensic stats                                 │
│   • Proxies /api/stats and /api/health to API Gateway               │
└──────────────────────────────┬───────────────────────────────────────┘
                               │  HTTP (port 8000)
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│              API Gateway  (FastAPI · ztf-api:8000)                   │
│   • POST /access  – evaluate + log every access request              │
│   • GET  /forensics/summary  – aggregate statistics                  │
│   • GET  /forensics/verify-chain – blockchain integrity check        │
│   • GET  /forensics/export – full evidence dump                      │
│   • GET  /health – service health check                              │
└────────┬──────────────────────┬──────────────────┬───────────────────┘
         │ HTTP (port 8181)     │ SQL (port 5432)  │ S3 API (port 9000)
         ▼                      ▼                  ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  OPA            │  │  PostgreSQL      │  │  MinIO           │
│  ztf-opa:8181   │  │  ztf-postgres    │  │  ztf-minio       │
│                 │  │  :5432           │  │  :9000 / :9001   │
│  Policy engine  │  │  Access logs     │  │  Evidence blobs  │
│  Rego rules     │  │  (ztfdb)         │  │  (S3-compatible) │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## Data Flow

### Access Request (POST /access)

```
Client
  │
  ├─1─► API Gateway receives AccessRequest
  │         { user_id, resource, action, ip_address, user_agent, metadata }
  │
  ├─2─► RiskScorer calculates risk_score (0.0 – 1.0)
  │         Evaluates 7 weighted factors in Python
  │
  ├─3─► OPA queried at /v1/data/ztf/authz
  │         Returns { allow: bool, deny_reason: str, risk_score: int }
  │
  ├─4─► BlockchainManager.add_block(log_entry)
  │         SHA-256 hash chained to previous block
  │         Returns chain_hash
  │
  ├─5─► AccessLog persisted to PostgreSQL
  │         Includes chain_hash for cross-reference
  │
  └─6─► AccessResponse returned to client
            { decision, risk_score, reason, chain_hash }
```

### Forensic Export (GET /forensics/export)

```
Client
  │
  ├─1─► API Gateway queries all AccessLog rows (ordered by timestamp ASC)
  │
  ├─2─► BlockchainManager.get_chain_stats() appended
  │
  └─3─► Full evidence bundle returned as JSON
```

---

## Blockchain Tamper-Evident Chain

Every access decision is appended to an in-memory **SHA-256 hash chain**. Each block contains:

| Field           | Description                                       |
|-----------------|---------------------------------------------------|
| `index`         | Sequential block number (genesis = 0)             |
| `timestamp`     | UTC ISO-8601 timestamp                            |
| `data`          | Full access log entry                             |
| `previous_hash` | SHA-256 hash of the preceding block               |
| `hash`          | SHA-256 hash of the entire current block          |

The genesis block has `previous_hash = "0000…0000"` (64 zeros).

**Verification** (`GET /forensics/verify-chain`):
```
For each block i (i ≥ 1):
  1. Recompute hash(block[i] without "hash" field)
  2. Assert recomputed == block[i]["hash"]          ← no tampering
  3. Assert block[i]["previous_hash"] == block[i-1]["hash"]  ← no gap
```

If any assertion fails the chain is marked **invalid** and the block index is reported.

---

## Security Flow

```
Incoming Request
       │
       ▼
┌──────────────────────────────┐
│   Extract Context            │
│   ip, user_agent, resource,  │
│   action, user_id, metadata  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│   Python Risk Scorer         │    ◄── 7 weighted factors
│   risk_score ∈ [0.0, 1.0]   │        see SECURITY.md
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│   OPA Policy Engine          │    ◄── Rego rules (opa_policies.rego)
│   allow / deny               │        10 policy factors
│   deny_reason                │
└──────────────┬───────────────┘
               │
       ┌───────┴───────┐
       │               │
    ALLOW            DENY
       │               │
       ▼               ▼
 Log + Hash       Increment failure_count
 Chain entry      Log + Hash
       │               │
       └───────┬───────┘
               │
               ▼
┌──────────────────────────────┐
│   PostgreSQL + MinIO         │
│   Persist audit record       │
└──────────────────────────────┘
               │
               ▼
       Return decision to client
```

---

## Component Descriptions

### API Gateway (`api_gateway/`)

- **Runtime**: Python 3.12, FastAPI 0.115, Uvicorn
- **Responsibilities**: Request ingestion, risk scoring orchestration, OPA delegation, blockchain management, database persistence, forensic query endpoints
- **Key modules**:
  - `main.py` – FastAPI application, routes, lifespan hooks
  - `risk_scoring.py` – `RiskScorer` class with 7 factor methods
  - `blockchain.py` – `BlockchainManager` with SHA-256 hash chain
  - `database.py` – SQLAlchemy models and session factory
  - `storage.py` – MinIO client wrapper (`StorageManager`)

### OPA (Open Policy Agent) (`opa/policies/`)

- **Runtime**: `openpolicyagent/opa:0.68.0`
- **Responsibilities**: Policy-based access decisions using Rego language
- **Policy file**: `opa_policies.rego` — package `ztf.authz`
- **Endpoint used**: `POST /v1/data/ztf/authz` with full request context
- Policies are hot-reloaded via `--watch` flag; no OPA restart required

### PostgreSQL (`ztf-postgres`)

- **Image**: `postgres:16.4`
- **Database**: `ztfdb`, user `ztf`
- **Schema**: Single `access_logs` table with columns for all request attributes plus `chain_hash` and `timestamp`
- **Health check**: `pg_isready -U ztf -d ztfdb` (API Gateway waits for healthy state before starting)

### MinIO (`ztf-minio`)

- **Image**: `minio/minio:RELEASE.2025-02-28T09-55-16Z`
- **Ports**: `9000` (S3 API), `9001` (web console)
- **Purpose**: Object storage for evidence blobs and exported forensic bundles
- If MinIO is unavailable at startup, the API Gateway degrades gracefully (storage shown as `"down"` in health check)

### Dashboard (`dashboard/`)

- **Runtime**: Python 3.12, Flask
- **Port**: `5000`
- **Responsibilities**: Browser-based visualization of forensic statistics; proxies data from the API Gateway. No business logic — purely presentational.
- **Templates**: Jinja2 (`dashboard/templates/index.html`)

### Blockchain (`api_gateway/blockchain.py`)

- **Type**: In-process, in-memory hash chain (not a distributed ledger)
- **Algorithm**: SHA-256 over JSON-serialized block data (`sort_keys=True`)
- **Scope**: Single API Gateway process lifetime; chain is rebuilt from the database on restart (future enhancement)
- **Purpose**: Forensic non-repudiation — any post-hoc modification to log entries is detectable via `GET /forensics/verify-chain`

---

## Network Topology

All services share the `ztforensics_ztf-net` bridge network. Inter-service communication uses Docker DNS names (`ztf-postgres`, `ztf-opa`, `ztf-minio`, `ztf-api`). The only externally exposed ports are:

| Port | Service         | Purpose                  |
|------|-----------------|--------------------------|
| 5000 | ztf-dashboard   | Web UI                   |
| 8000 | ztf-api         | REST API                 |
| 8181 | ztf-opa         | OPA REST API             |
| 5432 | ztf-postgres    | PostgreSQL (dev only)    |
| 9000 | ztf-minio       | MinIO S3 API             |
| 9001 | ztf-minio       | MinIO web console        |

In production, only ports `5000` and `8000` should be exposed externally. All others should be restricted to internal network access.
