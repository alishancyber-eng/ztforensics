# ZTForensics Security Model

## Zero Trust Principles

ZTForensics is built on the Zero Trust security model: **never trust, always verify**. Every request — regardless of origin, network, or prior authentication state — is evaluated against a full set of contextual signals before access is granted or denied.

| Principle                    | Implementation                                                                 |
|------------------------------|--------------------------------------------------------------------------------|
| Verify explicitly            | All 10 risk factors evaluated on every request                                 |
| Use least-privilege access   | Dangerous actions blocked unless role is `admin` or `superuser`                |
| Assume breach                | Every decision is logged, hashed, and stored for forensic analysis             |
| Continuous evaluation        | Risk scoring and OPA policies re-evaluated per request, not per session        |
| Non-repudiation              | Blockchain hash chain detects any post-hoc tampering with audit logs           |

---

## Risk Scoring

The Python `RiskScorer` (`api_gateway/risk_scoring.py`) computes a **normalised float score in [0.0, 1.0]** by summing individual factor contributions and clamping the result.

### Formula

```
risk_score = clamp(
    ip_reputation(ip)
  + user_agent_risk(ua)
  + time_of_day_risk(utc_hour)
  + resource_sensitivity(resource)
  + action_type_risk(action)
  + repeated_failures(user_id)
  + geolocation_risk(country),
  min=0.0, max=1.0
)
```

### Risk Levels

| Label      | Score Range  | Recommended Response                              |
|------------|--------------|---------------------------------------------------|
| `LOW`      | < 0.25       | Allow; routine logging                            |
| `MEDIUM`   | 0.25 – 0.49  | Allow with enhanced logging; flag for review      |
| `HIGH`     | 0.50 – 0.74  | Require additional verification; alert SOC        |
| `CRITICAL` | ≥ 0.75       | Block or quarantine; immediate investigation      |

> **Note**: The OPA policy engine makes the final allow/deny decision independently of the Python risk score. Both signals are logged to enable correlation analysis.

---

## The 10 Security Factors

### Factor 1 – IP Reputation

**Python weight**: +0.30 (known-bad) / +0.05 (unknown) / 0.00 (loopback)  
**OPA rule**: `deny_ip_reputation`  
**OPA weight**: 3 pts

Requests from IP addresses on the known-bad list are blocked immediately. The blocklist is defined in both the Python scorer (`_SUSPICIOUS_IPS`) and the OPA policy (`bad_ips`). Update both sets when adding new blocked addresses.

```python
# Example – blocked IPs
_SUSPICIOUS_IPS = {"10.0.0.1", "192.168.1.1", "172.16.0.1"}
```

**When triggered**: IP address field exactly matches a blocklisted entry.

---

### Factor 2 – User Agent

**Python weight**: +0.20  
**OPA rule**: `deny_user_agent`  
**OPA weight**: 2 pts

Automated or scripted clients (curl, wget, python-requests, libwww-perl, scrapy) are flagged as suspicious because they are commonly used in reconnaissance and automated attack tooling.

```
Suspicious agents: curl, python-requests, wget, libwww-perl, libwww, scrapy
Matching: case-insensitive substring match
```

**When triggered**: User-Agent header contains any of the above substrings.

---

### Factor 3 – Time of Day

**Python weight**: +0.20 (hours 00:00–05:59 UTC)  
**OPA rule**: `deny_time_of_day`  
**OPA weight**: 2 pts

Access outside business hours (before 06:00 or after 21:59 UTC) is treated as higher risk. Most legitimate enterprise users do not access sensitive resources in the early morning hours UTC.

```
Blocked hours (UTC): 00:00 – 05:59 and 22:00 – 23:59
```

**When triggered**: `input.hour < 6` or `input.hour >= 22`.

---

### Factor 4 – Resource Sensitivity

**Python weight**: +0.20  
**OPA rule**: `deny_resource_sensitivity`  
**OPA weight**: 2 pts

Sensitive resources (those whose names contain keywords like `admin`, `root`, `sensitive`, `secret`, `config`, `audit`) require an `admin` role to perform non-READ operations.

```
Protected keywords: admin, root, sensitive, secret, config, audit
Exception: READ actions by any role are permitted
```

**When triggered**: Resource name contains a protected keyword AND action is not `READ` AND role is not `admin`.

---

### Factor 5 – Action Type

**Python weight**: +0.15  
**OPA rule**: `deny_action_type`  
**OPA weight**: 2 pts

Destructive or mutation actions are restricted to elevated roles. Standard users should never be able to `DELETE`, `WRITE`, `ADMIN`, `DROP`, or `TRUNCATE` resources.

```
High-risk actions: DELETE, WRITE, ADMIN, UPDATE (Python)
                   DELETE, WRITE, ADMIN, DROP, TRUNCATE (OPA)
Permitted roles:   admin, superuser
```

**When triggered**: Action is in the high-risk set AND role is not `admin` or `superuser`.

---

### Factor 6 – Geolocation Blocking

**Python weight**: +0.30  
**OPA rule**: `deny_geolocation`  
**OPA weight**: 3 pts

Requests originating from country codes associated with elevated threat actor activity are blocked. The country code must be supplied by the caller in `input.country` (API field: `metadata.country`).

```
Blocked country codes: CN, RU, KP, IR
```

**When triggered**: `input.country` is in the blocked set.

---

### Factor 7 – Device Compliance (Informational)

**Python weight**: N/A (not implemented in scorer)  
**OPA rule**: `device_compliant` (informational only)  
**OPA weight**: 1 pt (unregistered device)

Tracks whether the requesting device has been registered. Currently informational — contributes to the OPA risk score but does not independently deny access.

```
Input field: input.device_registered (bool)
```

**Planned enhancement**: Block access from unregistered devices once device registry is integrated.

---

### Factor 8 – Repeated Denial / Brute-Force Protection

**Python weight**: +0.30 (≥3 failures) / +0.10 (≥1 failure)  
**OPA rule**: `deny_repeated_denial`  
**OPA weight**: 3 pts

The API Gateway maintains an in-memory `failure_count` per `user_id`. When a user accumulates 3 or more denied requests, subsequent requests are blocked automatically. This prevents brute-force and credential-stuffing attacks.

```
Thresholds:
  1–2 failures → +0.10 risk
  3+ failures  → +0.30 risk + OPA deny
```

**When triggered**: `input.failure_count >= 3`.

---

### Factor 9 – User Role Baseline (Informational)

**Python weight**: N/A  
**OPA rule**: `role_anomaly` (informational only)  
**OPA weight**: 1 pt

Validates that the supplied role is one of the expected set. An unexpected role value may indicate token forgery or misconfiguration.

```
Expected roles: user, admin, superuser, readonly, auditor
```

**When triggered**: Role is not in the expected set (informational, does not independently deny).

---

### Factor 10 – VPN / Anonymiser Detection (Informational)

**Python weight**: N/A  
**OPA rule**: `vpn_detected` (informational only)  
**OPA weight**: 1 pt

Detects the use of VPNs or anonymous proxies via caller-supplied flags. Currently informational — contributes to OPA risk score.

```
Input fields: input.is_vpn (bool), input.is_anonymous (bool)
```

**Planned enhancement**: Optionally block anonymised traffic for high-sensitivity resources.

---

## OPA Risk Score (0–10)

OPA computes a parallel integer risk score (0–10) by accumulating factor points:

```rego
ip_pts  := 3  if deny_ip_reputation       else 0
ua_pts  := 2  if deny_user_agent          else 0
tod_pts := 2  if deny_time_of_day         else 0
res_pts := 2  if deny_resource_sensitivity else 0
act_pts := 2  if deny_action_type         else 0
geo_pts := 3  if deny_geolocation         else 0
rep_pts := 3  if deny_repeated_denial     else 0
dev_pts := 1  if not device_compliant     else 0
role_pts:= 1  if role_anomaly             else 0
vpn_pts := 1  if vpn_detected             else 0

risk_score := min(sum, 10)
```

Maximum possible score: **20** (clamped to **10**).

---

## Threat Model

| Threat                         | Vector                              | Mitigation                                         |
|--------------------------------|-------------------------------------|----------------------------------------------------|
| Credential theft / replay      | Stolen tokens reused from new IP    | IP reputation + geolocation blocking               |
| Brute-force / credential stuff | Rapid repeated auth attempts        | Repeated-denial counter blocks after 3 failures    |
| Insider threat                 | Legitimate user abusing privilege   | Action-type + resource sensitivity restrictions    |
| Automated scanning / scraping  | Scripted HTTP clients               | User-agent blocking                                |
| After-hours access             | Compromised account used at night   | Time-of-day restriction                            |
| Log tampering                  | Attacker modifying audit records    | Blockchain hash chain integrity verification       |
| Nation-state actors            | APT groups from high-risk regions   | Geolocation blocking of CN, RU, KP, IR             |
| Unknown device                 | BYOD / unmanaged endpoint           | Device compliance check (informational)            |
| Anonymised access              | VPN / Tor / proxy usage             | VPN/anonymiser detection (informational)           |
| Privilege escalation           | User claiming elevated role         | Role baseline anomaly detection                    |

---

## Mitigation Strategies

### Defense in Depth
Risk scoring (Python) and policy enforcement (OPA) are independent layers. Even if one layer is bypassed, the other provides a backstop.

### Fail-Safe Defaults
If OPA is unreachable, the API Gateway defaults to **allow** with a warning log. This is a conscious trade-off for availability; in high-security deployments, change the fallback to **deny**.

```python
# api_gateway/main.py – change for high-security mode
return {"allow": False}  # fail-closed
```

### Immutable Audit Trail
The blockchain hash chain ensures that any modification to historical access logs is detectable. Run `GET /forensics/verify-chain` regularly as part of operational monitoring.

### Least-Privilege Role Model
Only `admin` and `superuser` roles can execute dangerous actions or access sensitive resources. Assign the minimum necessary role to each user.

### Continuous Monitoring
The `/forensics/summary` endpoint provides real-time aggregate statistics. Integrate with a SIEM or alerting system to trigger on spikes in `high_risk_events` or `denied` counts.

---

## Security Best Practices

1. **Rotate credentials regularly** — change `MINIO_SECRET_KEY`, `POSTGRES_PASSWORD`, and any API keys on a defined schedule.
2. **Use TLS in production** — terminate TLS at a reverse proxy (nginx/Caddy) in front of both the Dashboard (5000) and API Gateway (8000).
3. **Restrict database port** — remove the `5432:5432` port mapping from `docker-compose.yml` in production; PostgreSQL should not be directly reachable from outside Docker.
4. **Persist the blockchain** — the current in-memory chain is lost on restart. Store chain state to PostgreSQL or a dedicated file for production use.
5. **Update blocklists** — review and update `bad_ips`, `blocked_countries`, and `suspicious_agents` in both `risk_scoring.py` and `opa_policies.rego` as threat intelligence evolves.
6. **Enable OPA bundle signing** — use OPA's bundle signing feature to ensure policies are not tampered with.
7. **Monitor failure counters** — the in-memory `_failure_counts` dict is reset on restart. Use a Redis-backed counter in production for persistence across restarts.
8. **Run `verify-chain` on schedule** — automate calls to `GET /forensics/verify-chain` and alert on `valid: false`.
