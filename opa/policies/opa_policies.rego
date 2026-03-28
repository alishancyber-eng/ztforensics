package ztf.authz

import future.keywords.if
import future.keywords.in

default allow = false

# ---------------------------------------------------------------------------
# Top-level allow rule
# All denial conditions must be absent for access to be granted.
# ---------------------------------------------------------------------------
allow if {
    not deny_ip_reputation
    not deny_user_agent
    not deny_time_of_day
    not deny_resource_sensitivity
    not deny_action_type
    not deny_geolocation
    not deny_repeated_denial
}

# ---------------------------------------------------------------------------
# Factor 1 – IP Reputation
# Block requests originating from known-bad IP addresses.
# ---------------------------------------------------------------------------
bad_ips := {"10.0.0.1", "192.168.0.254", "172.16.255.255"}

deny_ip_reputation if {
    input.ip_address in bad_ips
}

# ---------------------------------------------------------------------------
# Factor 2 – User Agent
# Flag/block suspicious automated user agents.
# ---------------------------------------------------------------------------
suspicious_agents := {"curl", "python-requests", "wget", "libwww-perl", "scrapy"}

deny_user_agent if {
    some agent in suspicious_agents
    contains(lower(input.user_agent), agent)
}

# ---------------------------------------------------------------------------
# Factor 3 – Time of Day
# Restrict access outside business hours (requires input.hour 0-23).
# ---------------------------------------------------------------------------
deny_time_of_day if {
    input.hour < 6
}

deny_time_of_day if {
    input.hour >= 22
}

# ---------------------------------------------------------------------------
# Factor 4 – Resource Sensitivity
# Protect sensitive resources from low-privilege actions.
# ---------------------------------------------------------------------------
sensitive_resources := {"admin", "root", "sensitive", "secret", "config", "audit"}

deny_resource_sensitivity if {
    some res in sensitive_resources
    contains(lower(input.resource), res)
    input.action != "READ"
    input.role != "admin"
}

# ---------------------------------------------------------------------------
# Factor 5 – Action Type
# Restrict dangerous mutation actions without elevated role.
# ---------------------------------------------------------------------------
dangerous_actions := {"DELETE", "WRITE", "ADMIN", "DROP", "TRUNCATE"}

deny_action_type if {
    input.action in dangerous_actions
    input.role != "admin"
    input.role != "superuser"
}

# ---------------------------------------------------------------------------
# Factor 6 – Geolocation Blocking
# Block requests from high-risk countries.
# ---------------------------------------------------------------------------
blocked_countries := {"CN", "RU", "KP", "IR"}

deny_geolocation if {
    input.country in blocked_countries
}

# ---------------------------------------------------------------------------
# Factor 7 – Device Compliance (informational – does not block by itself)
# Unregistered devices are flagged in deny_reason.
# ---------------------------------------------------------------------------
device_compliant if {
    input.device_registered == true
}

# ---------------------------------------------------------------------------
# Factor 8 – Repeated Denial / Brute-Force Protection
# Deny after 3 or more prior failures for the same user.
# ---------------------------------------------------------------------------
deny_repeated_denial if {
    input.failure_count >= 3
}

# ---------------------------------------------------------------------------
# Factor 9 – User Role Baseline
# Flag deviation from expected role patterns (informational).
# ---------------------------------------------------------------------------
expected_roles := {"user", "admin", "superuser", "readonly", "auditor"}

role_anomaly if {
    not input.role in expected_roles
}

# ---------------------------------------------------------------------------
# Factor 10 – VPN / Anonymiser Detection
# Flag requests using anonymous proxies or VPNs.
# ---------------------------------------------------------------------------
vpn_detected if {
    input.is_vpn == true
}

vpn_detected if {
    input.is_anonymous == true
}

# ---------------------------------------------------------------------------
# Risk score computation (0–10 scale)
# ---------------------------------------------------------------------------
risk_score = score if {
    ip_pts    := 3  if deny_ip_reputation   else 0
    ua_pts    := 2  if deny_user_agent      else 0
    tod_pts   := 2  if deny_time_of_day     else 0
    res_pts   := 2  if deny_resource_sensitivity else 0
    act_pts   := 2  if deny_action_type     else 0
    geo_pts   := 3  if deny_geolocation     else 0
    rep_pts   := 3  if deny_repeated_denial else 0
    dev_pts   := 1  if not device_compliant else 0
    role_pts  := 1  if role_anomaly         else 0
    vpn_pts   := 1  if vpn_detected         else 0
    raw       := ip_pts + ua_pts + tod_pts + res_pts + act_pts + geo_pts + rep_pts + dev_pts + role_pts + vpn_pts
    score     := min([raw, 10])
}

# ---------------------------------------------------------------------------
# Deny reason
# ---------------------------------------------------------------------------
deny_reason = reason if {
    deny_ip_reputation
    reason := "Blocked IP address"
} else = reason if {
    deny_geolocation
    reason := "Geolocation blocked"
} else = reason if {
    deny_repeated_denial
    reason := "Too many failed attempts"
} else = reason if {
    deny_user_agent
    reason := "Suspicious user agent"
} else = reason if {
    deny_time_of_day
    reason := "Outside allowed hours"
} else = reason if {
    deny_resource_sensitivity
    reason := "Resource access not permitted for role"
} else = reason if {
    deny_action_type
    reason := "Action not permitted for role"
} else = reason if {
    allow
    reason := "Access granted"
} else = reason if {
    reason := "Policy denied"
}
