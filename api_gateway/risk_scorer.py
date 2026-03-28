from datetime import datetime, timezone


def calculate_risk(payload: dict) -> dict:
    """
    Simple deterministic risk model for hackathon demo.
    Returns:
      {risk_score: int, risk_factors: list[str]}
    """
    score = 0
    factors: list[str] = []

    ip = (payload.get("ip_address") or "").strip()
    ua = (payload.get("user_agent") or "").lower()
    resource = (payload.get("resource") or "").lower()
    action = (payload.get("action") or "").lower()

    # Foreign / suspicious IP (very naive demo logic)
    if ip.startswith("196.") or ip.startswith("203."):
        score += 35
        factors.append("foreign_or_untrusted_ip")

    # Script user-agent
    if "python-requests" in ua or "curl/" in ua:
        score += 25
        factors.append("non_browser_user_agent")

    # Sensitive resource
    if "/api/admin" in resource:
        score += 30
        factors.append("admin_resource_targeted")

    # Risky action
    if action in {"write", "delete"}:
        score += 15
        factors.append("sensitive_action")

    # Off-hours
    hour = datetime.now(timezone.utc).hour
    if hour < 6 or hour > 22:
        score += 10
        factors.append("off_business_hours")

    score = min(score, 100)

    return {
        "risk_score": score,
        "risk_factors": factors
    }