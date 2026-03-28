import requests
from config import settings


def _fallback_reason(opa_input: dict) -> str:
    risk = int(opa_input.get("risk_score", 0))
    resource = str(opa_input.get("resource", ""))
    role = str(opa_input.get("role", ""))

    if risk >= 70:
        return "HIGH_RISK_SCORE"
    if resource.startswith("/api/admin") and role != "admin":
        return "ADMIN_RESOURCE_REQUIRES_ADMIN_ROLE"
    if 50 <= risk < 70:
        return "MEDIUM_RISK"
    return "DENY_BY_DEFAULT"


def evaluate_policy(opa_input: dict) -> dict:
    """
    Deterministic auth decision:
    - Prefer OPA result
    - If OPA unavailable/bad response, fallback to local deterministic policy mapping
    """
    base = settings.opa_url.rstrip("/")
    payload = {"input": opa_input}

    try:
        # Try combined object endpoint
        resp = requests.post(f"{base}/v1/data/ztforensics/authz", json=payload, timeout=3)
        if resp.status_code == 200:
            body = resp.json()
            result = body.get("result", {})
            if isinstance(result, dict):
                allow = bool(result.get("allow", False))
                reason = result.get("reason", "ALLOWED" if allow else _fallback_reason(opa_input))
                return {"allow": allow, "reason": reason}
            if isinstance(result, bool):
                return {"allow": result, "reason": "ALLOWED" if result else _fallback_reason(opa_input)}

        # Try split endpoints
        allow_resp = requests.post(f"{base}/v1/data/ztforensics/authz/allow", json=payload, timeout=3)
        allow_resp.raise_for_status()
        allow = bool(allow_resp.json().get("result", False))

        reason_resp = requests.post(f"{base}/v1/data/ztforensics/authz/reason", json=payload, timeout=3)
        reason_resp.raise_for_status()
        reason = reason_resp.json().get("result", "ALLOWED" if allow else _fallback_reason(opa_input))

        return {"allow": allow, "reason": reason}

    except requests.Timeout:
        return {"allow": False, "reason": _fallback_reason(opa_input)}
    except requests.RequestException:
        return {"allow": False, "reason": _fallback_reason(opa_input)}
    except ValueError:
        return {"allow": False, "reason": _fallback_reason(opa_input)}
    except Exception:
        return {"allow": False, "reason": _fallback_reason(opa_input)}