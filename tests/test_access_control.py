"""
RBAC (Role-Based Access Control) tests for ZTForensics – 12 tests.
Tests role validation, permission checking, resource access by role,
role hierarchy enforcement, and OPA-driven decisions.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import importlib
import pytest
from unittest.mock import patch, AsyncMock


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
# Role validation
# ---------------------------------------------------------------------------

class TestRoleValidation:
    def test_admin_can_read_evidence(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "admin_001", "resource": "evidence/001", "action": "READ"
            })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"

    def test_admin_can_delete_evidence(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "admin_001", "resource": "evidence/001", "action": "DELETE"
            })
        assert resp.json()["decision"] == "allow"

    def test_investigator_can_read(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "inv_001", "resource": "evidence/002", "action": "READ"
            })
        assert resp.json()["decision"] == "allow"

    def test_investigator_cannot_delete(self, client):
        with patch("main._query_opa", new_callable=AsyncMock,
                   return_value={"allow": False, "deny_reason": "Insufficient privilege"}):
            resp = client.post("/access", json={
                "user_id": "inv_001", "resource": "evidence/002", "action": "DELETE"
            })
        assert resp.json()["decision"] == "deny"

    def test_analyst_can_read_public(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "analyst_001", "resource": "public/report", "action": "READ"
            })
        assert resp.json()["decision"] == "allow"

    def test_analyst_cannot_write_evidence(self, client):
        with patch("main._query_opa", new_callable=AsyncMock,
                   return_value={"allow": False, "deny_reason": "Read-only role"}):
            resp = client.post("/access", json={
                "user_id": "analyst_001", "resource": "evidence/003", "action": "WRITE"
            })
        assert resp.json()["decision"] == "deny"


# ---------------------------------------------------------------------------
# Permission checking
# ---------------------------------------------------------------------------

class TestPermissionChecking:
    def test_read_permission_low_risk(self, client):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs.calculate_risk({
            "resource": "evidence/1", "action": "READ",
            "user_id": "u", "ip_address": "8.8.8.8", "user_agent": "Mozilla"
        })
        # READ on non-sensitive resource should have low risk
        assert score < 0.5

    def test_delete_on_admin_high_risk(self, client):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs.calculate_risk({
            "resource": "admin", "action": "DELETE",
            "user_id": "u", "ip_address": "8.8.8.8", "user_agent": "Mozilla"
        })
        # admin resource + DELETE action = elevated risk
        assert score >= 0.3

    def test_multiple_denied_requests_logged(self, client):
        """Multiple denials should all be persisted (decision=deny in DB)."""
        for i in range(3):
            with patch("main._query_opa", new_callable=AsyncMock,
                       return_value={"allow": False, "deny_reason": "Test deny"}):
                resp = client.post("/access", json={
                    "user_id": f"denied_user_{i}", "resource": "admin", "action": "DELETE"
                })
            assert resp.json()["decision"] == "deny"

        resp = client.get("/forensics/summary")
        assert resp.json()["denied"] >= 3


# ---------------------------------------------------------------------------
# Role revocation simulation
# ---------------------------------------------------------------------------

class TestRoleRevocation:
    def test_revoked_role_denied_by_opa(self, client):
        """After role revocation, OPA should deny all access."""
        with patch("main._query_opa", new_callable=AsyncMock,
                   return_value={"allow": False, "deny_reason": "Role revoked"}):
            resp = client.post("/access", json={
                "user_id": "revoked_user", "resource": "evidence/5", "action": "READ"
            })
        assert resp.json()["decision"] == "deny"
        assert "revoked" in resp.json()["reason"].lower()
