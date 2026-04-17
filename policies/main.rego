package ztf.authz

default decision = "deny"
default reason = "DENY_BY_DEFAULT"
default require_otp = false

risk_score = x {
  meta := object.get(input, "metadata", {})
  x := object.get(meta, "risk_score", 0)
}

role = x {
  x := object.get(input, "role", "user")
}

resource = x {
  x := object.get(input, "resource", "")
}

action = x {
  x := object.get(input, "action", "")
}

# Hard deny: forbidden scope/action
hard_deny {
  startswith(resource, "/api/admin")
  role != "admin"
}

hard_deny {
  action == "delete"
  role != "admin"
}

hard_deny {
  resource == "sensitive-data"
  action == "delete"
}

# Very suspicious => deny + security approval flow
very_suspicious {
  risk_score >= 0.85
}

# OTP challenge band
otp_needed {
  not hard_deny
  not very_suspicious
  risk_score >= 0.50
  risk_score < 0.85
}

# Low risk allow
allow_now {
  not hard_deny
  not very_suspicious
  risk_score < 0.50
}

decision = "deny" {
  hard_deny
}

reason = "FORBIDDEN_ACTION_OR_RESOURCE" {
  hard_deny
}

decision = "deny" {
  very_suspicious
}

reason = "VERY_SUSPICIOUS_REQUIRE_SECURITY_APPROVAL" {
  very_suspicious
}

decision = "challenge_otp" {
  otp_needed
}

require_otp = true {
  otp_needed
}

reason = "STEP_UP_OTP_REQUIRED" {
  otp_needed
}

decision = "allow" {
  allow_now
}

reason = "ALLOWED_LOW_RISK" {
  allow_now
}