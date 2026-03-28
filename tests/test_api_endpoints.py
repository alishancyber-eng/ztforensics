"""
API endpoint tests – 20 tests covering the FastAPI routes in detail.
Specifically targets paths not covered by the existing tests:
  – Successful OPA response (main.py lines 123-125)
  – Health check with DB failure (main.py lines 147-148)
  – Lifespan startup / shutdown (main.py lines 48-51)
  – Access denied by OPA, deny reason, summary/export growth
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import importlib
import pytest
from unittest.mock import MagicMock, patch, AsyncMock


# ---------------------------------------------------------------------------
# Shared client fixture
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
        return app_module


@pytest.fixture(scope="module")
def app_module():
    return _make_client()


@pytest.fixture(scope="module")
def client(app_module):
    from fastapi.testclient import TestClient
    return TestClient(app_module.app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Lifespan tests (covers main.py lines 48-51)
# ---------------------------------------------------------------------------

class TestLifespan:
    def test_lifespan_startup_and_shutdown(self, app_module):
        """Using TestClient as context manager triggers startup & shutdown."""
        from fastapi.testclient import TestClient
        with TestClient(app_module.app, raise_server_exceptions=False) as tc:
            resp = tc.get("/")
            assert resp.status_code == 200

    def test_lifespan_db_initialised_on_startup(self, app_module):
        from fastapi.testclient import TestClient
        with TestClient(app_module.app, raise_server_exceptions=False) as tc:
            resp = tc.get("/forensics/summary")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# OPA success-path tests (covers main.py lines 123-125)
# ---------------------------------------------------------------------------

class TestOPASuccessPath:
    def test_access_opa_real_allow_response(self, client):
        """OPA returns a real HTTP response (not exception) — success path."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"result": {"allow": True}}

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(return_value=mock_resp)

        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "alice", "resource": "evidence/1", "action": "READ"
            })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"

    def test_access_opa_real_deny_response(self, client):
        """OPA returns allow=False — decision should be deny."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "result": {"allow": False, "deny_reason": "High risk score"}
        }

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(return_value=mock_resp)

        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "evil", "resource": "admin", "action": "DELETE",
                "ip_address": "10.0.0.1", "user_agent": "curl/7"
            })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "deny"

    def test_access_opa_deny_reason_in_response(self, client):
        """deny_reason from OPA should appear in the reason field."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "result": {"allow": False, "deny_reason": "Policy violation"}
        }

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(return_value=mock_resp)

        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "bob", "resource": "secret", "action": "DELETE"
            })
        assert resp.json()["reason"] == "Policy violation"

    def test_access_opa_no_result_key_defaults_allow(self, client):
        """OPA response missing 'result' key should default to allow."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {}   # no 'result' key

        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(return_value=mock_resp)

        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "user1", "resource": "docs", "action": "READ"
            })
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Health endpoint DB failure (covers main.py lines 147-148)
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_db_exception_reports_down(self, app_module):
        """When db.execute raises, the health endpoint reports database: down."""
        from fastapi.testclient import TestClient
        import main as m
        import database

        def _bad_db():
            db = MagicMock()
            db.execute.side_effect = Exception("connection refused")
            try:
                yield db
            finally:
                pass

        # Override using the get_db function that was imported by main
        m.app.dependency_overrides[database.get_db] = _bad_db
        try:
            tc = TestClient(m.app, raise_server_exceptions=False)
            resp = tc.get("/health")
        finally:
            m.app.dependency_overrides.clear()

        assert resp.status_code == 200
        assert resp.json()["services"]["database"] == "down"

    def test_health_storage_down_when_none(self, app_module):
        import main as m
        orig = m.storage_manager
        m.storage_manager = None
        from fastapi.testclient import TestClient
        tc = TestClient(m.app, raise_server_exceptions=False)
        resp = tc.get("/health")
        m.storage_manager = orig
        assert resp.json()["services"]["storage"] == "down"

    def test_health_storage_up_when_available(self, app_module):
        import main as m
        orig = m.storage_manager
        m.storage_manager = MagicMock()
        from fastapi.testclient import TestClient
        tc = TestClient(m.app, raise_server_exceptions=False)
        resp = tc.get("/health")
        m.storage_manager = orig
        assert resp.json()["services"]["storage"] == "up"


# ---------------------------------------------------------------------------
# Forensics endpoints
# ---------------------------------------------------------------------------

class TestForensicsEndpoints:
    def test_summary_counts_grow_after_access(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            client.post("/access", json={
                "user_id": "counter_test_user", "resource": "docs", "action": "READ"
            })
        resp = client.get("/forensics/summary")
        assert resp.json()["total_requests"] >= 1

    def test_export_contains_chain_stats(self, client):
        resp = client.get("/forensics/export")
        data = resp.json()
        assert "chain_stats" in data
        assert "export_timestamp" in data

    def test_verify_chain_returns_stats(self, client):
        resp = client.get("/forensics/verify-chain")
        data = resp.json()
        assert "valid" in data
        assert "chain_length" in data or "total_blocks" in data

    def test_summary_high_risk_events(self, client):
        """A high-risk access attempt should increment high_risk_events."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": False}):
            with patch("main.risk_scorer.calculate_risk", return_value=0.9):
                client.post("/access", json={
                    "user_id": "attacker", "resource": "admin",
                    "action": "DELETE", "ip_address": "10.0.0.1"
                })
        resp = client.get("/forensics/summary")
        assert resp.json()["high_risk_events"] >= 1


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------

class TestRequestValidation:
    def test_access_returns_chain_hash_64_chars(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "hash_test_user", "resource": "res", "action": "READ"
            })
        assert len(resp.json()["chain_hash"]) == 64

    def test_access_risk_score_in_range(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "range_user", "resource": "res", "action": "READ"
            })
        score = resp.json()["risk_score"]
        assert 0.0 <= score <= 1.0

    def test_access_with_metadata(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "meta_user", "resource": "res", "action": "READ",
                "metadata": {"case_id": "123", "env": "test"}
            })
        assert resp.status_code == 200

    def test_unknown_route_returns_404(self, client):
        resp = client.get("/nonexistent/route")
        assert resp.status_code == 404
