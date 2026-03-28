"""
Unit tests for api_gateway/anomaly_detector.py
"""
import pytest
from anomaly_detector import detect_anomalies


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record(
    user="alice",
    ip="10.0.0.1",
    resource="/api/docs",
    role="employee",
    decision="ALLOW",
    risk=0,
    hour=10,
    idx=1,
):
    """Build a minimal evidence record dict suitable for the anomaly detector."""
    ts = f"2026-03-27T{hour:02d}:00:00+00:00"
    return {
        "id": idx,
        "user_name": user,
        "ip_address": ip,
        "resource": resource,
        "role": role,
        "decision": decision,
        "risk_score": risk,
        "timestamp": ts,
        "action": "read",
        "reason": "ALLOWED" if decision == "ALLOW" else "HIGH_RISK_SCORE",
    }


# ---------------------------------------------------------------------------
# Tests: empty / baseline
# ---------------------------------------------------------------------------

class TestNoAnomalies:
    def test_empty_records_returns_empty(self):
        assert detect_anomalies([]) == []

    def test_all_allowed_no_anomaly(self):
        records = [_record(idx=i) for i in range(5)]
        anomalies = detect_anomalies(records)
        assert anomalies == []

    def test_two_denials_not_enough_to_trigger(self):
        records = [_record(decision="DENY", idx=i) for i in range(2)]
        anomalies = detect_anomalies(records)
        assert not any(a["type"] == "repeated_denials" for a in anomalies)


# ---------------------------------------------------------------------------
# Tests: repeated denials per user
# ---------------------------------------------------------------------------

class TestRepeatedDenials:
    def test_three_denials_from_same_user_flagged(self):
        records = [_record(user="bob", decision="DENY", idx=i) for i in range(3)]
        anomalies = detect_anomalies(records)
        types = [a["type"] for a in anomalies]
        assert "repeated_denials" in types

    def test_five_denials_classified_high_severity(self):
        records = [_record(user="eve", decision="DENY", idx=i) for i in range(5)]
        anomalies = detect_anomalies(records)
        by_type = {a["type"]: a for a in anomalies}
        assert "repeated_denials" in by_type
        assert by_type["repeated_denials"]["severity"] == "HIGH"

    def test_denial_count_matches(self):
        records = [_record(user="dave", decision="DENY", idx=i) for i in range(4)]
        anomalies = detect_anomalies(records)
        by_type = {a["type"]: a for a in anomalies}
        assert by_type["repeated_denials"]["count"] == 4


# ---------------------------------------------------------------------------
# Tests: repeated denials per IP
# ---------------------------------------------------------------------------

class TestRepeatedDenialsFromIP:
    def test_three_denials_from_same_ip_flagged(self):
        records = [
            _record(user=f"u{i}", ip="203.0.113.5", decision="DENY", idx=i)
            for i in range(3)
        ]
        anomalies = detect_anomalies(records)
        types = [a["type"] for a in anomalies]
        assert "repeated_denials_from_ip" in types


# ---------------------------------------------------------------------------
# Tests: off-hours access
# ---------------------------------------------------------------------------

class TestOffHoursAccess:
    def test_two_off_hours_records_flagged(self):
        records = [
            _record(user="carol", hour=3, idx=1),
            _record(user="carol", hour=4, idx=2),
        ]
        anomalies = detect_anomalies(records)
        types = [a["type"] for a in anomalies]
        assert "off_hours_access" in types

    def test_business_hours_not_flagged(self):
        records = [_record(user="alice", hour=h, idx=h) for h in range(6, 22)]
        anomalies = detect_anomalies(records)
        assert not any(a["type"] == "off_hours_access" for a in anomalies)


# ---------------------------------------------------------------------------
# Tests: privilege escalation
# ---------------------------------------------------------------------------

class TestPrivilegeEscalation:
    def test_non_admin_accessing_admin_resource_flagged(self):
        records = [
            _record(user="frank", role="employee", resource="/api/admin/secrets", idx=1),
        ]
        anomalies = detect_anomalies(records)
        types = [a["type"] for a in anomalies]
        assert "privilege_escalation_attempt" in types

    def test_admin_accessing_admin_resource_not_flagged(self):
        records = [
            _record(user="root", role="admin", resource="/api/admin/secrets", idx=1),
        ]
        anomalies = detect_anomalies(records)
        assert not any(a["type"] == "privilege_escalation_attempt" for a in anomalies)

    def test_confidence_is_high_for_priv_escalation(self):
        records = [
            _record(user="grace", role="employee", resource="/api/admin/users", idx=1),
        ]
        anomalies = detect_anomalies(records)
        priv = next(a for a in anomalies if a["type"] == "privilege_escalation_attempt")
        assert priv["confidence"] >= 0.85
        assert priv["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Tests: resource hopping
# ---------------------------------------------------------------------------

class TestResourceHopping:
    def test_five_distinct_resources_flagged(self):
        resources = [f"/api/resource/{i}" for i in range(5)]
        records = [
            _record(user="heidi", resource=r, idx=i)
            for i, r in enumerate(resources)
        ]
        anomalies = detect_anomalies(records)
        types = [a["type"] for a in anomalies]
        assert "resource_hopping" in types

    def test_four_distinct_resources_not_flagged(self):
        resources = [f"/api/resource/{i}" for i in range(4)]
        records = [
            _record(user="ivan", resource=r, idx=i)
            for i, r in enumerate(resources)
        ]
        anomalies = detect_anomalies(records)
        assert not any(a["type"] == "resource_hopping" for a in anomalies)
