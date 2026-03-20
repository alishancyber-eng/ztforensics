import requests

from config import settings


def evaluate_policy(input_doc: dict) -> dict:
    """
    Calls OPA policy:
      data.ztforensics.authz
    """
    url = f"{settings.opa_url}/v1/data/ztforensics/authz"
    try:
        resp = requests.post(url, json={"input": input_doc}, timeout=5)
        resp.raise_for_status()
        data = resp.json().get("result", {})
        return {
            "allow": bool(data.get("allow", False)),
            "reason": data.get("reason", "DENY_BY_DEFAULT")
        }
    except Exception as exc:
        # Fail secure
        return {
            "allow": False,
            "reason": f"OPA_ERROR: {exc}"
        }