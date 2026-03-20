package ztforensics.authz

default allow := false

# Admin role can access all resources if not high-risk
allow if {
    input.role == "admin"
    input.risk_score < 70
}

# Non-admin users: deny admin resources
allow if {
    input.role != "admin"
    not startswith(input.resource, "/api/admin")
    input.risk_score < 50
}

reason := "HIGH_RISK_SCORE: Risk score exceeds safety threshold (>=70)" if {
    input.risk_score >= 70
}

reason := "ADMIN_RESOURCE_REQUIRES_ADMIN_ROLE" if {
    startswith(input.resource, "/api/admin")
    input.role != "admin"
}

reason := "MEDIUM_RISK: Risk score in warning zone (50-69), requires review" if {
    input.risk_score >= 50
    input.risk_score < 70
}

reason := "ALLOWED: All policy checks passed" if {
    allow
}