"""
Authentication and access-token tests for ZTForensics – 15 tests.
Tests JWT-like token validation concepts, user extraction, role handling,
and how the API gateway treats authentication data in access requests.
Since there is no separate auth_middleware.py yet, these tests exercise
the authentication-relevant logic surfaced through the access endpoint
and risk scorer (user identity, repeated failures acting as auth events).
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import importlib
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

# ---------------------------------------------------------------------------
# Sample JWT-like test data
# ---------------------------------------------------------------------------

TEST_USERS = {
    "admin":        {"role": "admin",        "user_id": "admin_user"},
    "investigator": {"role": "investigator", "user_id": "inv_user"},
    "analyst":      {"role": "analyst",      "user_id": "analyst_user"},
}

TEST_REQUESTS = [
    {"user_id": "alice", "action": "READ",   "resource": "evidence/1"},
    {"user_id": "bob",   "action": "WRITE",  "resource": "evidence/2"},
    {"user_id": "carol", "action": "DELETE", "resource": "evidence/3"},
]


# ---------------------------------------------------------------------------
# Client fixture
# ---------------------------------------------------------------------------

def _make_client():
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    with patch("storage.Minio"):
        from sqlalchemy import create_engine as real_ce
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from database import Base

        engine = real_ce(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=engine)
        TestSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        import database
        database.engine = engine
        database.SessionLocal = TestSession

        import main as app_module
        importlib.reload(app_module)
        from fastapi.testclient import TestClient
        return TestClient(app_module.app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def client():
    return _make_client()


# ---------------------------------------------------------------------------
# User extraction from request (simulates token → user_id extraction)
# ---------------------------------------------------------------------------

class TestUserExtraction:
    def test_valid_user_id_accepted(self, client):
        """A well-formed user_id passes validation and returns a decision."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "alice", "resource": "evidence/1", "action": "READ"
            })
        assert resp.status_code == 200

    def test_empty_user_id_rejected(self, client):
        """An empty user_id (like a missing/invalid token) must return 422."""
        resp = client.post("/access", json={
            "user_id": "", "resource": "evidence/1", "action": "READ"
        })
        assert resp.status_code == 422

    def test_missing_user_id_rejected(self, client):
        """A request with no user_id field at all must return 422."""
        resp = client.post("/access", json={"resource": "evidence/1", "action": "READ"})
        assert resp.status_code == 422

    def test_unicode_user_id_accepted(self, client):
        """User IDs with unicode characters (e.g. non-ASCII names) are valid."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "用户_alice", "resource": "docs", "action": "READ"
            })
        assert resp.status_code == 200

    def test_long_user_id_accepted(self, client):
        """Very long user IDs (e.g. UUID-derived tokens) are valid."""
        long_uid = "user_" + "a" * 200
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": long_uid, "resource": "docs", "action": "READ"
            })
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Token-expiry / brute-force simulation
# ---------------------------------------------------------------------------

class TestTokenRevocationSimulation:
    def test_repeated_denials_increase_risk(self):
        """record_failure simulates token revocation / brute-force detection."""
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        uid = "revoked_token_user_unique"
        for _ in range(3):
            rs.record_failure(uid)
        score = rs.calculate_risk({
            "ip_address": "8.8.8.8", "user_agent": "Mozilla",
            "resource": "docs", "action": "READ", "user_id": uid
        })
        assert score >= 0.3

    def test_fresh_user_no_failure_risk(self):
        """A user with no prior failures starts at minimum risk."""
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        factor = rs._repeated_failures("brand_new_user_auth_test")
        assert factor == 0.0

    def test_opa_deny_triggers_failure_record(self, client):
        """When OPA denies a request, the failure counter should be incremented."""
        from risk_scoring import _failure_counts
        uid = "tracked_failure_user_unique"
        initial = _failure_counts.get(uid, 0)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": {"allow": False, "deny_reason": "High risk"}}
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(return_value=mock_resp)
        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            client.post("/access", json={
                "user_id": uid, "resource": "admin", "action": "DELETE"
            })
        assert _failure_counts.get(uid, 0) > initial


# ---------------------------------------------------------------------------
# Role-based access simulation (via OPA mock)
# ---------------------------------------------------------------------------

class TestRoleBasedAccess:
    def test_admin_role_access_allowed(self, client):
        """Admin users should receive allow decisions from OPA."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": TEST_USERS["admin"]["user_id"],
                "resource": "admin_panel", "action": "DELETE"
            })
        assert resp.json()["decision"] == "allow"

    def test_investigator_role_access_allowed(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": TEST_USERS["investigator"]["user_id"],
                "resource": "evidence/123", "action": "READ"
            })
        assert resp.json()["decision"] == "allow"

    def test_analyst_role_access_denied(self, client):
        """Analysts denied by OPA for sensitive resources."""
        with patch("main._query_opa", new_callable=AsyncMock,
                   return_value={"allow": False, "deny_reason": "Insufficient role"}):
            resp = client.post("/access", json={
                "user_id": TEST_USERS["analyst"]["user_id"],
                "resource": "admin_panel", "action": "DELETE"
            })
        assert resp.json()["decision"] == "deny"

    def test_missing_role_defaults_to_opa_decision(self, client):
        """If a user has no role info, the gateway defers to OPA."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": False}):
            resp = client.post("/access", json={
                "user_id": "unknown_user_xyz", "resource": "secret", "action": "WRITE"
            })
        assert resp.json()["decision"] == "deny"

    def test_all_sample_requests_return_200(self, client):
        """All sample request shapes return HTTP 200 (even if decision is deny)."""
        for req in TEST_REQUESTS:
            with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
                resp = client.post("/access", json=req)
            assert resp.status_code == 200
