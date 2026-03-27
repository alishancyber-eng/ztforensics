"""
Unit tests for api_gateway/forensic_engine.py
"""
import hashlib
import json
import pytest

from forensic_engine import (
    build_evidence_payload,
    canonical_json,
    compute_sha256,
    make_record_hash,
    verify_chain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db_record(
    idx: int,
    user: str = "alice",
    role: str = "employee",
    resource: str = "/api/docs",
    action: str = "read",
    ip: str = "10.0.0.1",
    ua: str = "Mozilla/5.0",
    risk: int = 0,
    decision: str = "ALLOW",
    reason: str = "ALLOWED",
    previous_hash: str = "0",
    trace_id: str = "trace-1",
    timestamp: str = "2026-03-27T10:00:00+00:00",
):
    """Build a DB-shaped evidence record dict with a valid record_hash."""
    payload = {
        "timestamp": timestamp,
        "trace_id": trace_id,
        "user": user,
        "role": role,
        "resource": resource,
        "action": action,
        "ip_address": ip,
        "user_agent": ua,
        "risk_score": risk,
        "risk_factors": [],
        "decision": decision,
        "reason": reason,
        "previous_hash": previous_hash,
    }
    record_hash = make_record_hash(payload)
    return {
        "id": idx,
        "timestamp": timestamp,
        "trace_id": trace_id,
        "user_name": user,
        "role": role,
        "resource": resource,
        "action": action,
        "ip_address": ip,
        "user_agent": ua,
        "risk_score": risk,
        "risk_factors": [],
        "decision": decision,
        "reason": reason,
        "previous_hash": previous_hash,
        "record_hash": record_hash,
    }


def _chain_of(n: int):
    """Build an n-record valid hash chain."""
    records = []
    prev = "0"
    for i in range(1, n + 1):
        r = _make_db_record(idx=i, previous_hash=prev, trace_id=f"t{i}",
                            timestamp=f"2026-03-27T10:0{i}:00+00:00")
        prev = r["record_hash"]
        records.append(r)
    return records


# ---------------------------------------------------------------------------
# canonical_json / compute_sha256
# ---------------------------------------------------------------------------

class TestCanonicalJson:
    def test_sorted_keys(self):
        data = {"b": 2, "a": 1}
        result = canonical_json(data)
        assert result.index('"a"') < result.index('"b"')

    def test_no_extra_whitespace(self):
        result = canonical_json({"key": "val"})
        assert " " not in result


class TestComputeSha256:
    def test_known_value(self):
        """Verify against a manually computed hash."""
        data = {"key": "value"}
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha256(raw).hexdigest()
        assert compute_sha256(data) == expected

    def test_deterministic(self):
        data = {"x": 1, "y": 2}
        assert compute_sha256(data) == compute_sha256(data)


# ---------------------------------------------------------------------------
# build_evidence_payload
# ---------------------------------------------------------------------------

class TestBuildEvidencePayload:
    def test_required_fields_present(self):
        payload = build_evidence_payload(
            user="bob", role="admin", resource="/api/admin",
            action="read", ip_address="10.0.0.1", user_agent="Mozilla/5.0",
            risk_score=0, risk_factors=[], decision="ALLOW",
            reason="ALLOWED", previous_hash="0", trace_id="t1",
        )
        for field in ("timestamp", "trace_id", "user", "role", "resource",
                      "action", "ip_address", "user_agent", "risk_score",
                      "risk_factors", "decision", "reason", "previous_hash"):
            assert field in payload, f"Missing field: {field}"

    def test_values_stored_correctly(self):
        payload = build_evidence_payload(
            user="carol", role="employee", resource="/api/docs",
            action="write", ip_address="192.168.1.1", user_agent="curl/8",
            risk_score=25, risk_factors=["non_browser_user_agent"],
            decision="DENY", reason="HIGH_RISK_SCORE",
            previous_hash="abc", trace_id="xyz",
        )
        assert payload["user"] == "carol"
        assert payload["risk_score"] == 25
        assert "non_browser_user_agent" in payload["risk_factors"]

    def test_no_record_hash_in_payload(self):
        """build_evidence_payload must NOT include record_hash (hash is computed separately)."""
        payload = build_evidence_payload(
            user="dave", role="employee", resource="/r", action="read",
            ip_address="1.1.1.1", user_agent="Mozilla", risk_score=0,
            risk_factors=[], decision="ALLOW", reason="ALLOWED",
            previous_hash="0", trace_id="t",
        )
        assert "record_hash" not in payload


# ---------------------------------------------------------------------------
# make_record_hash
# ---------------------------------------------------------------------------

class TestMakeRecordHash:
    def test_returns_hex_string(self):
        payload = build_evidence_payload(
            user="u", role="r", resource="/r", action="read",
            ip_address="1.1.1.1", user_agent="Mozilla", risk_score=0,
            risk_factors=[], decision="ALLOW", reason="ALLOWED",
            previous_hash="0", trace_id="t",
        )
        h = make_record_hash(payload)
        assert isinstance(h, str)
        assert len(h) == 64
        int(h, 16)  # must be valid hex

    def test_different_data_gives_different_hash(self):
        p1 = build_evidence_payload(
            user="u1", role="r", resource="/r", action="read",
            ip_address="1.1.1.1", user_agent="Mozilla", risk_score=0,
            risk_factors=[], decision="ALLOW", reason="ALLOWED",
            previous_hash="0", trace_id="t1",
        )
        p2 = build_evidence_payload(
            user="u2", role="r", resource="/r", action="read",
            ip_address="1.1.1.1", user_agent="Mozilla", risk_score=0,
            risk_factors=[], decision="ALLOW", reason="ALLOWED",
            previous_hash="0", trace_id="t2",
        )
        assert make_record_hash(p1) != make_record_hash(p2)


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------

class TestVerifyChain:
    def test_empty_records(self):
        result = verify_chain([])
        assert result["ok"] is True
        assert result["checked"] == 0

    def test_single_valid_record(self):
        records = _chain_of(1)
        result = verify_chain(records)
        assert result["ok"] is True
        assert result["checked"] == 1

    def test_three_record_valid_chain(self):
        records = _chain_of(3)
        result = verify_chain(records)
        assert result["ok"] is True
        assert result["checked"] == 3

    def test_tampered_record_hash_detected(self):
        records = _chain_of(3)
        # Tamper: change a field in record 2
        records[1]["user_name"] = "attacker"
        result = verify_chain(records)
        assert result["ok"] is False
        assert "broken_at_id" in result or "error" in result

    def test_tampered_previous_hash_detected(self):
        records = _chain_of(3)
        records[1]["previous_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        result = verify_chain(records)
        assert result["ok"] is False

    def test_broken_link_between_records(self):
        """Break the link by pointing record 2's previous_hash to the wrong value."""
        records = _chain_of(2)
        # The second record's previous_hash should equal record 1's record_hash.
        # Override it with something else.
        records[1]["previous_hash"] = "deadbeef" * 8
        result = verify_chain(records)
        assert result["ok"] is False
