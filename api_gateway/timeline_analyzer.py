from datetime import datetime
from typing import Any, Dict, List


def group_records_by_period(
    records: List[Dict[str, Any]], interval: str = "hour"
) -> List[Dict[str, Any]]:
    """
    Group evidence records into time-period buckets.

    Args:
        records: List of evidence record dicts (from DB or in-memory).
        interval: ``"hour"`` (default) or ``"day"``.

    Returns:
        Sorted list of period buckets with allow/deny counts and risk stats.
    """
    buckets: Dict[str, Dict[str, Any]] = {}

    for r in records:
        ts = r.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue

        if interval == "day":
            period_key = dt.strftime("%Y-%m-%d")
        else:  # default: hour
            period_key = dt.strftime("%Y-%m-%d %H:00")

        if period_key not in buckets:
            buckets[period_key] = {
                "period": period_key,
                "total_requests": 0,
                "allowed": 0,
                "denied": 0,
                "_risk_scores": [],
                "high_risk_events": 0,
            }

        b = buckets[period_key]
        b["total_requests"] += 1

        decision = r.get("decision", "")
        if decision == "ALLOW":
            b["allowed"] += 1
        else:
            b["denied"] += 1

        risk = int(r.get("risk_score", 0))
        b["_risk_scores"].append(risk)
        if risk >= 70:
            b["high_risk_events"] += 1

    result = []
    for key in sorted(buckets.keys()):
        b = buckets[key]
        scores = b.pop("_risk_scores")
        b["avg_risk_score"] = int(sum(scores) / len(scores)) if scores else 0
        result.append(b)

    return result
