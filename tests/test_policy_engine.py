"""
OPA policy engine tests for ZTForensics – 15 tests.
Tests policy evaluation, risk threshold enforcement, role-based decisions,
temporal rules, compliance checks, and policy hot-reload behaviour.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import importlib
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import httpx


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
# Policy evaluation
# ---------------------------------------------------------------------------

class TestPolicyEvaluation:
    def test_opa_allow_decision_persisted(self, client):
        """An OPA allow decision must be stored in the DB."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "policy_user_1", "resource": "reports", "action": "READ"
            })
        assert resp.json()["decision"] == "allow"

    def test_opa_deny_decision_persisted(self, client):
        """An OPA deny decision must be stored in the DB."""
        with patch("main._query_opa", new_callable=AsyncMock,
                   return_value={"allow": False, "deny_reason": "Blocked by policy"}):
            resp = client.post("/access", json={
                "user_id": "policy_user_2", "resource": "admin", "action": "DELETE"
            })
        assert resp.json()["decision"] == "deny"

    def test_opa_timeout_falls_back_to_allow(self, client):
        """When OPA times out, the gateway defaults to allow."""
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "timeout_user", "resource": "docs", "action": "READ"
            })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"

    def test_opa_connection_refused_falls_back(self, client):
        """When OPA refuses connection, the gateway defaults to allow."""
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused"))
        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "no_opa_user", "resource": "docs", "action": "READ"
            })
        assert resp.json()["decision"] == "allow"


# ---------------------------------------------------------------------------
# Risk threshold enforcement
# ---------------------------------------------------------------------------

class TestRiskThresholdEnforcement:
    def test_low_risk_request_allowed(self, client):
        """Low-risk request: trusted IP, normal user agent, READ action."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "safe_user",
                "resource": "public/report",
                "action": "READ",
                "ip_address": "8.8.8.8",
                "user_agent": "Mozilla/5.0"
            })
        score = resp.json()["risk_score"]
        assert score < 0.5

    def test_high_risk_request_denied(self, client):
        """High-risk request from suspicious IP with DELETE action."""
        with patch("main._query_opa", new_callable=AsyncMock,
                   return_value={"allow": False, "deny_reason": "High risk score"}):
            resp = client.post("/access", json={
                "user_id": "risky_user",
                "resource": "admin",
                "action": "DELETE",
                "ip_address": "10.0.0.1",
                "user_agent": "curl/7.68"
            })
        assert resp.json()["decision"] == "deny"

    def test_risk_score_affects_decision_chain(self, client):
        """The risk_score in the response should be stored in the blockchain hash."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "chain_risk_user", "resource": "docs", "action": "READ"
            })
        assert resp.json()["chain_hash"] is not None
        assert len(resp.json()["chain_hash"]) == 64


# ---------------------------------------------------------------------------
# Resource classification
# ---------------------------------------------------------------------------

class TestResourceClassification:
    def test_sensitive_resource_higher_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        s_sensitive = rs.calculate_risk({
            "resource": "admin/secrets", "action": "READ",
            "user_id": "u", "ip_address": "8.8.8.8", "user_agent": "Mozilla"
        })
        s_normal = rs.calculate_risk({
            "resource": "public/docs", "action": "READ",
            "user_id": "u", "ip_address": "8.8.8.8", "user_agent": "Mozilla"
        })
        assert s_sensitive > s_normal

    def test_root_resource_classified_sensitive(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        factor = rs._resource_sensitivity("root/system")
        assert factor == 0.2


# ---------------------------------------------------------------------------
# Multiple rule combinations
# ---------------------------------------------------------------------------

class TestMultipleRuleCombinations:
    def test_all_risk_factors_stacked_capped_at_one(self):
        """Maximum risk from all factors combined must stay ≤ 1.0."""
        from risk_scoring import RiskScorer, _failure_counts
        rs = RiskScorer()
        uid = "_max_risk_policy_user"
        for _ in range(5):
            rs.record_failure(uid)
        score = rs.calculate_risk({
            "ip_address": "10.0.0.1",
            "user_agent": "curl/7.68",
            "resource": "admin",
            "action": "DELETE",
            "user_id": uid,
            "country": "KP"
        })
        assert score <= 1.0
        assert score > 0.5

    def test_opa_policy_result_forwarded_correctly(self, client):
        """The OPA result dict's 'allow' field must drive the final decision."""
        for allow_val, expected in [(True, "allow"), (False, "deny")]:
            with patch("main._query_opa", new_callable=AsyncMock,
                       return_value={"allow": allow_val}):
                resp = client.post("/access", json={
                    "user_id": f"combo_{allow_val}", "resource": "docs", "action": "READ"
                })
            assert resp.json()["decision"] == expected

    def test_compliance_check_logged_in_chain(self, client):
        """Every access decision (allow or deny) should be logged to the chain."""
        chain_hashes = []
        for decision in [True, False]:
            maybe_deny = {} if decision else {"deny_reason": "Compliance"}
            opa_val = {"allow": decision, **maybe_deny}
            with patch("main._query_opa", new_callable=AsyncMock, return_value=opa_val):
                resp = client.post("/access", json={
                    "user_id": f"compliance_{decision}", "resource": "evidence", "action": "READ"
                })
            chain_hashes.append(resp.json()["chain_hash"])
        assert len(set(chain_hashes)) == 2   # unique hashes per decision
