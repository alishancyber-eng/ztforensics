package ztforensics.authz

default allow = false
default reason = "DENY_BY_DEFAULT"

allow {
  input.role == "admin"
  input.risk_score < 70
}

allow {
  input.role != "admin"
  not startswith(input.resource, "/api/admin")
  input.risk_score < 50
}

reason = "HIGH_RISK_SCORE" {
  input.risk_score >= 70
}

reason = "ADMIN_RESOURCE_REQUIRES_ADMIN_ROLE" {
  startswith(input.resource, "/api/admin")
  input.role != "admin"
}

reason = "MEDIUM_RISK" {
  input.risk_score >= 50
  input.risk_score < 70
}

reason = "ALLOWED" {
  allow
}