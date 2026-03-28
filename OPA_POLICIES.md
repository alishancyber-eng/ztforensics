# OPA Policies Reference

## Introduction

ZTForensics uses **Open Policy Agent (OPA)** as a dedicated policy-decision point. OPA decouples policy logic from application code, allowing security rules to be updated, tested, and audited independently without redeploying the API Gateway.

### What is OPA?

[Open Policy Agent](https://www.openpolicyagent.org/) is a general-purpose policy engine that evaluates declarative **Rego** policies against structured input data and returns a decision. In ZTForensics, OPA is queried via its REST API on every access request.

### What is Rego?

**Rego** is OPA's purpose-built policy language. It is:
- **Declarative** — you express *what* is true, not *how* to compute it
- **Safe** — no side effects; policies are pure functions of input
- **Composable** — rules build on each other using logical AND/OR

### Policy Location

```
opa/policies/opa_policies.rego
```

OPA is started with `--watch /policies`, so any change to the `.rego` file takes effect within seconds without restarting OPA or the API Gateway.

### Package and Entrypoint

```rego
package ztf.authz
```

The API Gateway queries: `POST /v1/data/ztf/authz`  
The top-level decision variables are: `allow` (bool), `deny_reason` (string), `risk_score` (int 0–10).

---

## Input Schema

Every access request sends the following JSON input to OPA:

```json
{
  "input": {
    "user_id":          "alice",
    "resource":         "reports/q4",
    "action":           "READ",
    "ip_address":       "203.0.113.42",
    "user_agent":       "Mozilla/5.0 ...",
    "metadata": {
      "hour":             14,
      "country":          "US",
      "role":             "user",
      "failure_count":    0,
      "device_registered": true,
      "is_vpn":           false,
      "is_anonymous":     false
    }
  }
}
```

> Fields within `metadata` are promoted to top-level `input.*` keys in OPA (`input.hour`, `input.country`, etc.) by the Rego policy using standard dot notation when supplied directly.

---

## Top-Level Allow Rule

```rego
default allow = false

allow if {
    not deny_ip_reputation
    not deny_user_agent
    not deny_time_of_day
    not deny_resource_sensitivity
    not deny_action_type
    not deny_geolocation
    not deny_repeated_denial
}
```

**Behaviour**: `allow` is `false` by default. It becomes `true` only when *none* of the seven active denial conditions evaluate to `true`. This is a **deny-by-default, allowlist** model — the safest approach.

---

## Policy Rules

### Rule 1 – IP Reputation (`deny_ip_reputation`)

Blocks requests from known-bad IP addresses.

```rego
bad_ips := {"10.0.0.1", "192.168.0.254", "172.16.255.255"}

deny_ip_reputation if {
    input.ip_address in bad_ips
}
```

**Trigger**: `input.ip_address` is an exact match for an entry in `bad_ips`.  
**OPA risk points**: 3  
**Example**:
```json
{ "input": { "ip_address": "10.0.0.1" } }
→ deny_ip_reputation = true, allow = false, deny_reason = "Blocked IP address"
```

---

### Rule 2 – User Agent (`deny_user_agent`)

Blocks automated HTTP clients commonly used in attacks and reconnaissance.

```rego
suspicious_agents := {"curl", "python-requests", "wget", "libwww-perl", "scrapy"}

deny_user_agent if {
    some agent in suspicious_agents
    contains(lower(input.user_agent), agent)
}
```

**Trigger**: User-Agent contains any listed substring (case-insensitive).  
**OPA risk points**: 2  
**Example**:
```json
{ "input": { "user_agent": "python-requests/2.32.3" } }
→ deny_user_agent = true, deny_reason = "Suspicious user agent"
```

---

### Rule 3 – Time of Day (`deny_time_of_day`)

Restricts access outside business hours.

```rego
deny_time_of_day if {
    input.hour < 6
}

deny_time_of_day if {
    input.hour >= 22
}
```

**Trigger**: `input.hour` (0–23, UTC) is before 06:00 or at/after 22:00.  
**OPA risk points**: 2  
**Example**:
```json
{ "input": { "hour": 3 } }
→ deny_time_of_day = true, deny_reason = "Outside allowed hours"
```

---

### Rule 4 – Resource Sensitivity (`deny_resource_sensitivity`)

Protects sensitive resources from non-admin write operations.

```rego
sensitive_resources := {"admin", "root", "sensitive", "secret", "config", "audit"}

deny_resource_sensitivity if {
    some res in sensitive_resources
    contains(lower(input.resource), res)
    input.action != "READ"
    input.role != "admin"
}
```

**Trigger**: Resource name contains a protected keyword AND action is not `READ` AND role is not `admin`.  
**OPA risk points**: 2  
**Example**:
```json
{ "input": { "resource": "admin/settings", "action": "WRITE", "role": "user" } }
→ deny_resource_sensitivity = true, deny_reason = "Resource access not permitted for role"
```

---

### Rule 5 – Action Type (`deny_action_type`)

Restricts destructive operations to elevated roles.

```rego
dangerous_actions := {"DELETE", "WRITE", "ADMIN", "DROP", "TRUNCATE"}

deny_action_type if {
    input.action in dangerous_actions
    input.role != "admin"
    input.role != "superuser"
}
```

**Trigger**: Action is in the dangerous set AND role is not `admin` or `superuser`.  
**OPA risk points**: 2  
**Example**:
```json
{ "input": { "action": "DELETE", "role": "readonly" } }
→ deny_action_type = true, deny_reason = "Action not permitted for role"
```

---

### Rule 6 – Geolocation Blocking (`deny_geolocation`)

Blocks requests from high-risk country codes.

```rego
blocked_countries := {"CN", "RU", "KP", "IR"}

deny_geolocation if {
    input.country in blocked_countries
}
```

**Trigger**: `input.country` is in the blocked set.  
**OPA risk points**: 3  
**Example**:
```json
{ "input": { "country": "KP" } }
→ deny_geolocation = true, deny_reason = "Geolocation blocked"
```

---

### Rule 7 – Device Compliance (Informational)

Tracks device registration status. Currently informational — contributes to risk score but does not independently deny.

```rego
device_compliant if {
    input.device_registered == true
}
```

**Trigger**: `input.device_registered` is `false` or absent → `device_compliant` is undefined → 1 risk point added.  
**OPA risk points**: 1 (unregistered)

---

### Rule 8 – Repeated Denial (`deny_repeated_denial`)

Blocks users after 3 or more prior failures (brute-force protection).

```rego
deny_repeated_denial if {
    input.failure_count >= 3
}
```

**Trigger**: `input.failure_count >= 3`.  
**OPA risk points**: 3  
**Example**:
```json
{ "input": { "failure_count": 5 } }
→ deny_repeated_denial = true, deny_reason = "Too many failed attempts"
```

---

### Rule 9 – User Role Baseline (Informational)

Detects anomalous role values that may indicate token forgery.

```rego
expected_roles := {"user", "admin", "superuser", "readonly", "auditor"}

role_anomaly if {
    not input.role in expected_roles
}
```

**Trigger**: Role is not in the expected set.  
**OPA risk points**: 1

---

### Rule 10 – VPN / Anonymiser Detection (Informational)

Detects use of VPNs or anonymous proxies.

```rego
vpn_detected if {
    input.is_vpn == true
}

vpn_detected if {
    input.is_anonymous == true
}
```

**Trigger**: `input.is_vpn == true` or `input.is_anonymous == true`.  
**OPA risk points**: 1

---

## Deny Reason Priority

When multiple rules fire, `deny_reason` follows this priority order:

1. `deny_ip_reputation` → `"Blocked IP address"`
2. `deny_geolocation` → `"Geolocation blocked"`
3. `deny_repeated_denial` → `"Too many failed attempts"`
4. `deny_user_agent` → `"Suspicious user agent"`
5. `deny_time_of_day` → `"Outside allowed hours"`
6. `deny_resource_sensitivity` → `"Resource access not permitted for role"`
7. `deny_action_type` → `"Action not permitted for role"`
8. `allow` → `"Access granted"`
9. fallback → `"Policy denied"`

---

## Adding a New Policy Rule

### Step 1 – Identify the signal

Determine what input field you will evaluate (e.g., `input.department`).

### Step 2 – Write the Rego rule

Add a new `deny_*` rule to `opa/policies/opa_policies.rego`:

```rego
# ---------------------------------------------------------------------------
# Factor 11 – Department Restriction
# Only the "security" department can access audit resources.
# ---------------------------------------------------------------------------
deny_department if {
    contains(lower(input.resource), "audit")
    input.department != "security"
}
```

### Step 3 – Add it to the allow rule

```rego
allow if {
    not deny_ip_reputation
    not deny_user_agent
    not deny_time_of_day
    not deny_resource_sensitivity
    not deny_action_type
    not deny_geolocation
    not deny_repeated_denial
    not deny_department          # ← add here
}
```

### Step 4 – Add risk points

```rego
# Inside the risk_score computation block:
dept_pts := 2 if deny_department else 0
raw := ip_pts + ua_pts + ... + dept_pts
```

### Step 5 – Add deny reason

```rego
} else = reason if {
    deny_department
    reason := "Department not permitted to access this resource"
}
```

### Step 6 – Verify OPA reloaded

```bash
docker logs ztf-opa | tail -5
# Look for: "Loaded policy ... successfully"
```

### Step 7 – Update documentation

Add the new factor to `SECURITY.md` and `OPA_POLICIES.md`.

---

## Testing Policies

### Test via curl (direct OPA)

```bash
# Allow case – standard user READ
curl -s -X POST http://localhost:8181/v1/data/ztf/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "alice",
      "resource": "reports/q4",
      "action": "READ",
      "ip_address": "203.0.113.42",
      "user_agent": "Mozilla/5.0",
      "hour": 14,
      "country": "US",
      "role": "user",
      "failure_count": 0,
      "device_registered": true,
      "is_vpn": false
    }
  }' | jq .result.allow
# Expected: true

# Deny case – blocked IP
curl -s -X POST http://localhost:8181/v1/data/ztf/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "eve",
      "resource": "reports/q4",
      "action": "READ",
      "ip_address": "10.0.0.1",
      "user_agent": "Mozilla/5.0",
      "hour": 14,
      "country": "US",
      "role": "user",
      "failure_count": 0
    }
  }' | jq '{allow: .result.allow, reason: .result.deny_reason}'
# Expected: { "allow": false, "reason": "Blocked IP address" }

# Deny case – outside hours
curl -s -X POST http://localhost:8181/v1/data/ztf/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "bob",
      "resource": "dashboard",
      "action": "READ",
      "ip_address": "203.0.113.1",
      "user_agent": "Mozilla/5.0",
      "hour": 3,
      "country": "US",
      "role": "user",
      "failure_count": 0
    }
  }' | jq '{allow: .result.allow, reason: .result.deny_reason}'
# Expected: { "allow": false, "reason": "Outside allowed hours" }

# Deny case – dangerous action without admin role
curl -s -X POST http://localhost:8181/v1/data/ztf/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "carol",
      "resource": "users",
      "action": "DELETE",
      "ip_address": "203.0.113.5",
      "user_agent": "Mozilla/5.0",
      "hour": 10,
      "country": "US",
      "role": "user",
      "failure_count": 0
    }
  }' | jq '{allow: .result.allow, reason: .result.deny_reason}'
# Expected: { "allow": false, "reason": "Action not permitted for role" }

# Allow case – admin DELETE
curl -s -X POST http://localhost:8181/v1/data/ztf/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "admin1",
      "resource": "users",
      "action": "DELETE",
      "ip_address": "203.0.113.5",
      "user_agent": "Mozilla/5.0",
      "hour": 10,
      "country": "US",
      "role": "admin",
      "failure_count": 0
    }
  }' | jq .result.allow
# Expected: true

# Risk score
curl -s -X POST http://localhost:8181/v1/data/ztf/authz \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "mallory",
      "resource": "admin/config",
      "action": "WRITE",
      "ip_address": "10.0.0.1",
      "user_agent": "python-requests/2.32.3",
      "hour": 2,
      "country": "RU",
      "role": "unknown",
      "failure_count": 5
    }
  }' | jq .result.risk_score
# Expected: 10 (clamped from: 3+2+2+2+2+3+3+1+1 = 19 → 10)
```

### Test via the API Gateway

```bash
# Via POST /access (API Gateway orchestrates OPA + risk scoring + DB)
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

### Check OPA policy reload

```bash
docker logs ztf-opa 2>&1 | grep -i "loaded\|error\|policy"
```

---

## Common Rego Patterns

```rego
# Set membership (exact match)
input.action in dangerous_actions

# Substring match (case-insensitive)
contains(lower(input.user_agent), "curl")

# Numeric comparison
input.failure_count >= 3

# Boolean check
input.is_vpn == true

# Negation (informational rules use `not`)
not input.role in expected_roles

# Conditional assignment (if/else)
ip_pts := 3 if deny_ip_reputation else 0

# Iterate over set
some agent in suspicious_agents
contains(lower(input.user_agent), agent)
```
