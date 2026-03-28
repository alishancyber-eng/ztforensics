import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_sha256(data: Dict[str, Any]) -> str:
    raw = canonical_json(data).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_evidence_payload(
    user: str,
    role: str,
    resource: str,
    action: str,
    ip_address: str,
    user_agent: str,
    risk_score: int,
    risk_factors: List[str],
    decision: str,
    reason: str,
    previous_hash: str,
    trace_id: str,
) -> Dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "trace_id": trace_id,
        "user": user,
        "role": role,
        "resource": resource,
        "action": action,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "decision": decision,
        "reason": reason,
        "previous_hash": previous_hash,
    }


def make_record_hash(payload: Dict[str, Any]) -> str:
    return compute_sha256(payload)


def verify_chain(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not records:
        return {"ok": True, "checked": 0, "message": "No records found"}

    expected_prev = "0"
    checked = 0

    for r in records:
        payload = {
            "timestamp": r["timestamp"],
            "trace_id": r["trace_id"],
            "user": r["user_name"],
            "role": r["role"],
            "resource": r["resource"],
            "action": r["action"],
            "ip_address": r["ip_address"],
            "user_agent": r["user_agent"],
            "risk_score": r["risk_score"],
            "risk_factors": r["risk_factors"],
            "decision": r["decision"],
            "reason": r["reason"],
            "previous_hash": r["previous_hash"],
        }

        recalculated = make_record_hash(payload)

        if r["previous_hash"] != expected_prev:
            return {
                "ok": False,
                "checked": checked,
                "broken_at_id": r["id"],
                "error": "PREVIOUS_HASH_MISMATCH",
            }

        if r["record_hash"] != recalculated:
            return {
                "ok": False,
                "checked": checked,
                "broken_at_id": r["id"],
                "error": "RECORD_HASH_MISMATCH",
            }

        expected_prev = r["record_hash"]
        checked += 1

    return {"ok": True, "checked": checked, "message": "Chain verified"}