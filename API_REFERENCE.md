# ZTForensics API Reference

## Base URL

| Environment | URL                        |
|-------------|----------------------------|
| Local       | `http://localhost:8000`    |
| Docker      | `http://ztf-api:8000`      |
| Production  | `https://api.your-domain.com` |

All endpoints accept and return **JSON**. The API is built with FastAPI and exposes interactive docs at `/docs` (Swagger UI) and `/redoc`.

---

## Authentication

ZTForensics currently relies on network-level access control and OPA policies for access decisions. Bearer token authentication is planned for a future release. All requests should originate from trusted internal networks or pass through an authenticated reverse proxy in production.

---

## Rate Limiting

Rate limiting is not enforced at the application layer in the current release. Implement rate limiting at the reverse proxy (e.g., nginx `limit_req_zone`) or API gateway (e.g., Kong, AWS API Gateway) layer in production deployments.

---

## Endpoints

### `GET /`

Root endpoint — service identification.

**Request**

```http
GET / HTTP/1.1
Host: localhost:8000
```

**Response** `200 OK`

```json
{
  "message": "ZTForensics API Gateway",
  "version": "1.0.0"
}
```

---

### `GET /health`

Returns the operational status of all downstream services. Suitable for use as a Docker health check or load-balancer probe.

**Request**

```http
GET /health HTTP/1.1
Host: localhost:8000
```

**Response** `200 OK`

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

**Service states**: `"up"` or `"down"`.  
`"storage": "down"` indicates MinIO was unavailable at startup — the API Gateway is still operational for all other functions.

**curl example**

```bash
curl -s http://localhost:8000/health | jq .
```

---

### `POST /access`

Evaluate an access request through the Zero Trust policy engine. This is the primary endpoint for enforcing access control.

**Processing pipeline**:
1. Python `RiskScorer` computes a risk score from request context
2. OPA policy engine makes the allow/deny decision
3. Decision is appended to the blockchain hash chain
4. Full log entry is persisted to PostgreSQL

**Request**

```http
POST /access HTTP/1.1
Host: localhost:8000
Content-Type: application/json
```

**Request Body**

| Field        | Type                | Required | Description                                   |
|--------------|---------------------|----------|-----------------------------------------------|
| `user_id`    | string (min 1 char) | ✅        | Identifier of the requesting user             |
| `resource`   | string (min 1 char) | ✅        | Resource being accessed (path or name)        |
| `action`     | string (min 1 char) | ✅        | Action being performed (READ, WRITE, DELETE…) |
| `ip_address` | string              | ❌        | Source IP address (default: `""`)             |
| `user_agent` | string              | ❌        | HTTP User-Agent header value (default: `""`)  |
| `metadata`   | object              | ❌        | Additional context (see below)                |

**Metadata fields** (all optional):

| Field               | Type    | Description                               |
|---------------------|---------|-------------------------------------------|
| `hour`              | int     | UTC hour (0–23) for time-of-day policy    |
| `country`           | string  | ISO-3166-1 alpha-2 country code           |
| `role`              | string  | User role (`user`, `admin`, `superuser`, `readonly`, `auditor`) |
| `failure_count`     | int     | Prior failure count for this user_id      |
| `device_registered` | bool    | Whether device is registered              |
| `is_vpn`            | bool    | Whether request is via VPN                |
| `is_anonymous`      | bool    | Whether request is via anonymous proxy    |

**Request Example — Standard allow**

```json
{
  "user_id": "alice",
  "resource": "reports/q4-2024",
  "action": "READ",
  "ip_address": "203.0.113.42",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "metadata": {
    "hour": 14,
    "country": "US",
    "role": "user",
    "failure_count": 0,
    "device_registered": true,
    "is_vpn": false
  }
}
```

**Request Example — High-risk (will be denied)**

```json
{
  "user_id": "mallory",
  "resource": "admin/config",
  "action": "DELETE",
  "ip_address": "10.0.0.1",
  "user_agent": "python-requests/2.32.3",
  "metadata": {
    "hour": 3,
    "country": "RU",
    "role": "user",
    "failure_count": 4
  }
}
```

**Response** `200 OK`

```json
{
  "decision": "allow",
  "risk_score": 0.05,
  "reason": "Access granted",
  "chain_hash": "a3f2c1d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
}
```

**Response Fields**

| Field        | Type   | Description                                                         |
|--------------|--------|---------------------------------------------------------------------|
| `decision`   | string | `"allow"` or `"deny"`                                               |
| `risk_score` | float  | Normalised risk score 0.0–1.0 (higher = riskier)                    |
| `reason`     | string | Human-readable explanation of the decision                          |
| `chain_hash` | string | SHA-256 hash of this event's block in the forensic hash chain       |

**curl example — allow**

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

**curl example — deny**

```bash
curl -s -X POST http://localhost:8000/access \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "eve",
    "resource": "admin/settings",
    "action": "DELETE",
    "ip_address": "10.0.0.1",
    "user_agent": "curl/8.0"
  }' | jq .
```

---

### `GET /forensics/summary`

Returns aggregate statistics from the access log database along with the 10 most recent log entries.

**Request**

```http
GET /forensics/summary HTTP/1.1
Host: localhost:8000
```

**Response** `200 OK`

```json
{
  "total_requests": 1024,
  "allowed": 891,
  "denied": 133,
  "high_risk_events": 47,
  "recent_logs": [
    {
      "id": 1024,
      "timestamp": "2025-01-15T14:32:11.123456+00:00",
      "user_id": "alice",
      "resource": "reports/q4",
      "action": "READ",
      "decision": "allow",
      "risk_score": 0.05
    },
    {
      "id": 1023,
      "timestamp": "2025-01-15T14:31:58.654321+00:00",
      "user_id": "eve",
      "resource": "admin/settings",
      "action": "DELETE",
      "decision": "deny",
      "risk_score": 0.85
    }
  ]
}
```

**Response Fields**

| Field              | Type    | Description                                              |
|--------------------|---------|----------------------------------------------------------|
| `total_requests`   | int     | Total number of access requests logged                   |
| `allowed`          | int     | Number of requests that were allowed                     |
| `denied`           | int     | Number of requests that were denied                      |
| `high_risk_events` | int     | Requests with `risk_score >= 0.75`                       |
| `recent_logs`      | array   | Up to 10 most recent log entries, newest first           |

**curl example**

```bash
curl -s http://localhost:8000/forensics/summary | jq '{total: .total_requests, denied: .denied}'
```

---

### `GET /forensics/verify-chain`

Verifies the cryptographic integrity of the forensic blockchain hash chain. Use this endpoint to detect any tampering with historical access log entries.

**Request**

```http
GET /forensics/verify-chain HTTP/1.1
Host: localhost:8000
```

**Response** `200 OK` — chain intact

```json
{
  "valid": true,
  "total_blocks": 1024,
  "verified_blocks": 1024,
  "chain_length": 1025,
  "genesis_hash": "0f4d2a1b3c5e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
  "latest_hash": "a3f2c1d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
}
```

**Response** `200 OK` — chain tampered

```json
{
  "valid": false,
  "total_blocks": 1024,
  "verified_blocks": 511,
  "chain_length": 1025,
  "genesis_hash": "0f4d2a1b3c5e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3",
  "latest_hash": "a3f2c1d4e5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
}
```

**Response Fields**

| Field             | Type   | Description                                                     |
|-------------------|--------|-----------------------------------------------------------------|
| `valid`           | bool   | `true` if all blocks pass integrity checks                      |
| `total_blocks`    | int    | Total data blocks (excludes genesis block)                      |
| `verified_blocks` | int    | Number of blocks that passed verification                       |
| `chain_length`    | int    | Total chain length including genesis block                      |
| `genesis_hash`    | string | SHA-256 hash of the genesis (first) block                       |
| `latest_hash`     | string | SHA-256 hash of the most recent block                           |

**curl example**

```bash
curl -s http://localhost:8000/forensics/verify-chain | jq '{valid: .valid, verified: .verified_blocks, total: .total_blocks}'
```

---

### `GET /forensics/export`

Exports the complete forensic evidence bundle as a JSON structure. Includes all access log entries with full metadata and blockchain statistics.

**Request**

```http
GET /forensics/export HTTP/1.1
Host: localhost:8000
```

**Response** `200 OK`

```json
{
  "export_timestamp": "2025-01-15T14:35:00.000000+00:00",
  "total_records": 1024,
  "chain_stats": {
    "total_blocks": 1024,
    "chain_length": 1025,
    "genesis_hash": "0f4d2a1b3c5e7f9a...",
    "latest_hash": "a3f2c1d4e5b6a7c8..."
  },
  "evidence": [
    {
      "id": 1,
      "timestamp": "2025-01-15T08:00:01.000000+00:00",
      "user_id": "alice",
      "resource": "reports/q1",
      "action": "READ",
      "decision": "allow",
      "risk_score": 0.05,
      "ip_address": "203.0.113.42",
      "user_agent": "Mozilla/5.0",
      "chain_hash": "3e4f5a6b7c8d9e0f..."
    }
  ]
}
```

**Response Fields**

| Field              | Type   | Description                                            |
|--------------------|--------|--------------------------------------------------------|
| `export_timestamp` | string | UTC ISO-8601 timestamp of when the export was created  |
| `total_records`    | int    | Number of evidence records in the export               |
| `chain_stats`      | object | Blockchain statistics (see verify-chain)               |
| `evidence`         | array  | All access log entries, ordered oldest-first           |

**curl example**

```bash
curl -s http://localhost:8000/forensics/export | jq '{records: .total_records, valid_chain: .chain_stats}'

# Save to file
curl -s http://localhost:8000/forensics/export > evidence_export.json
```

---

## Error Codes

| HTTP Status | Meaning                  | Common Causes                                                   |
|-------------|--------------------------|-----------------------------------------------------------------|
| `400`       | Bad Request              | Malformed JSON body                                             |
| `403`       | Forbidden                | Access denied by policy (returned in `decision` field, not HTTP status — policy denials return `200` with `"decision": "deny"`) |
| `422`       | Unprocessable Entity     | Missing required fields (`user_id`, `resource`, `action`) or invalid field types |
| `500`       | Internal Server Error    | Database connection failure, unhandled exception                |

> **Note**: Policy denials are returned as `HTTP 200` with `"decision": "deny"` in the response body. HTTP `4xx`/`5xx` errors indicate infrastructure or input validation failures, not policy outcomes.

**Example 422 response**

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "user_id"],
      "msg": "Field required",
      "input": {}
    }
  ]
}
```

---

## Interactive Documentation

FastAPI automatically generates interactive API documentation:

| URL                              | Interface      |
|----------------------------------|----------------|
| `http://localhost:8000/docs`     | Swagger UI     |
| `http://localhost:8000/redoc`    | ReDoc          |
| `http://localhost:8000/openapi.json` | OpenAPI schema |
