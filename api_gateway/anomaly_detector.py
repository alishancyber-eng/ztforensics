from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List


def _get_user(record: Dict[str, Any]) -> str:
    """Return user identifier from a record (handles both DB and in-memory naming)."""
    return record.get("user_name") or record.get("user") or "unknown"


def detect_anomalies(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect suspicious patterns in access logs.

    Checks for:
    1. Repeated denials from same user (>= 3 denials)
    2. Repeated denials from same IP address (>= 3 denials)
    3. Off-hours access (outside 06:00–22:00 UTC)
    4. Privilege escalation attempts (non-admin accessing admin resources)
    5. Resource hopping (single user accessing 5+ distinct resources)
    """
    anomalies: List[Dict[str, Any]] = []

    # --- 1. Repeated denials per user ---
    user_denials: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        if r.get("decision") == "DENY":
            user_denials[_get_user(r)].append(r)

    for user, denials in user_denials.items():
        if len(denials) >= 3:
            confidence = round(min(0.99, 0.70 + (len(denials) - 3) * 0.05), 2)
            severity = "HIGH" if len(denials) >= 5 else "MEDIUM"
            anomalies.append(
                {
                    "type": "repeated_denials",
                    "user": user,
                    "count": len(denials),
                    "confidence": confidence,
                    "severity": severity,
                    "timestamp": denials[-1].get("timestamp", ""),
                }
            )

    # --- 2. Repeated denials per IP ---
    ip_denials: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        if r.get("decision") == "DENY":
            ip = r.get("ip_address", "")
            if ip:
                ip_denials[ip].append(r)

    for ip, denials in ip_denials.items():
        if len(denials) >= 3:
            confidence = round(min(0.99, 0.65 + (len(denials) - 3) * 0.05), 2)
            severity = "HIGH" if len(denials) >= 5 else "MEDIUM"
            anomalies.append(
                {
                    "type": "repeated_denials_from_ip",
                    "ip_address": ip,
                    "count": len(denials),
                    "confidence": confidence,
                    "severity": severity,
                    "timestamp": denials[-1].get("timestamp", ""),
                }
            )

    # --- 3. Off-hours access (06:00–22:00 UTC considered business hours) ---
    off_hours_by_user: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        ts = r.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.hour < 6 or dt.hour >= 22:
                off_hours_by_user[_get_user(r)].append(r)
        except (ValueError, AttributeError):
            pass

    for user, off_records in off_hours_by_user.items():
        if len(off_records) >= 2:
            anomalies.append(
                {
                    "type": "off_hours_access",
                    "user": user,
                    "count": len(off_records),
                    "confidence": 0.75,
                    "severity": "MEDIUM",
                    "timestamp": off_records[-1].get("timestamp", ""),
                }
            )

    # --- 4. Privilege escalation attempts ---
    priv_by_user: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        resource = r.get("resource", "")
        role = r.get("role", "")
        if "/api/admin" in resource and role != "admin":
            priv_by_user[_get_user(r)].append(r)

    for user, attempts in priv_by_user.items():
        anomalies.append(
            {
                "type": "privilege_escalation_attempt",
                "user": user,
                "count": len(attempts),
                "confidence": 0.90,
                "severity": "HIGH",
                "timestamp": attempts[-1].get("timestamp", ""),
            }
        )

    # --- 5. Resource hopping (>= 5 distinct resources by same user) ---
    user_resources: Dict[str, List[str]] = defaultdict(list)
    user_last_ts: Dict[str, str] = {}
    for r in records:
        user = _get_user(r)
        resource = r.get("resource", "")
        if resource:
            user_resources[user].append(resource)
        ts = r.get("timestamp", "")
        if ts:
            user_last_ts[user] = ts

    for user, resources in user_resources.items():
        distinct = set(resources)
        if len(distinct) >= 5:
            anomalies.append(
                {
                    "type": "resource_hopping",
                    "user": user,
                    "count": len(distinct),
                    "confidence": 0.70,
                    "severity": "LOW",
                    "timestamp": user_last_ts.get(user, ""),
                }
            )

    return anomalies
