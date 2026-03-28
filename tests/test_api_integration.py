"""
Integration tests for the ZTForensics API Gateway.
20 tests covering end-to-end endpoint behaviour with mocked external services.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))

import pytest
import importlib
from unittest.mock import patch, MagicMock, AsyncMock


@pytest.fixture(scope="module")
def client():
    """Create a TestClient backed by SQLite in-memory."""
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    with patch("storage.Minio"):
        from sqlalchemy import create_engine as real_create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from database import Base

        engine = real_create_engine(
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

        from auth_middleware import get_current_user
        from schemas import UserContext
        app_module.app.dependency_overrides[get_current_user] = lambda: UserContext(user_id="testuser")

        from fastapi.testclient import TestClient
        tc = TestClient(app_module.app, raise_server_exceptions=False)
        yield tc


def _access_payload(**kwargs):
    base = {
        "user_id": "alice",
        "resource": "documents",
        "action": "READ",
        "ip_address": "10.10.10.10",
        "user_agent": "Mozilla/5.0",
        "metadata": {}
    }
    base.update(kwargs)
    return base


# 1. Valid access request returns expected structure
def test_access_valid_request(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json=_access_payload())
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] in ("allow", "deny")
    assert "risk_score" in data
    assert "chain_hash" in data


# 2. Access with invalid data (missing fields) returns 422
def test_access_invalid_data_422(client):
    resp = client.post("/access", json={"user_id": "u1"})
    assert resp.status_code == 422


# 3. OPA deny decision flows through
def test_access_deny_decision(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": False, "deny_reason": "Test deny"}):
        resp = client.post("/access", json=_access_payload())
    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"


# 4. Health endpoint returns 200
def test_health_returns_200(client):
    resp = client.get("/health")
    assert resp.status_code == 200


# 5. Forensics summary returns structure
def test_forensics_summary_structure(client):
    resp = client.get("/forensics/summary")
    assert resp.status_code == 200
    data = resp.json()
    for key in ("total_requests", "allowed", "denied", "high_risk_events", "recent_logs"):
        assert key in data


# 6. Verify chain returns valid status
def test_verify_chain_returns_valid(client):
    resp = client.get("/forensics/verify-chain")
    assert resp.status_code == 200
    assert "valid" in resp.json()


# 7. Export endpoint returns evidence list
def test_export_returns_evidence(client):
    resp = client.get("/forensics/export")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["evidence"], list)


# 8. Concurrent requests – submit multiple access requests
def test_concurrent_requests(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        responses = [client.post("/access", json=_access_payload(user_id=f"user{i}")) for i in range(5)]
    assert all(r.status_code == 200 for r in responses)


# 9. Database transaction – denied request is persisted
def test_database_persistence_deny(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": False}):
        client.post("/access", json=_access_payload(user_id="persist_deny_user"))
    summary = client.get("/forensics/summary").json()
    assert summary["denied"] >= 1


# 10. Risk score integration – high-risk request has elevated score
def test_risk_score_integration(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json=_access_payload(
            user_agent="curl/7.68",
            resource="admin_config",
            action="DELETE"
        ))
    assert resp.json()["risk_score"] > 0.0


# 11. Blockchain grows after multiple entries
def test_blockchain_grows(client):
    before = client.get("/forensics/verify-chain").json()["chain_length"]
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        client.post("/access", json=_access_payload())
    after = client.get("/forensics/verify-chain").json()["chain_length"]
    assert after > before


# 12. OPA policy evaluation mock returns correct structure
def test_opa_mock_allow(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json=_access_payload())
    assert resp.json()["decision"] == "allow"


# 13. Error response format validation (422)
def test_error_response_format_422(client):
    resp = client.post("/access", json={})
    assert resp.status_code == 422
    assert "detail" in resp.json()


# 14. Large payload is handled
def test_large_payload(client):
    payload = _access_payload(metadata={"key": "x" * 5000})
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json=payload)
    assert resp.status_code == 200


# 15. Missing required field returns 422
def test_missing_required_field(client):
    resp = client.post("/access", json={"user_id": "u1", "action": "READ"})
    assert resp.status_code == 422


# 16. Invalid action type (empty string) rejected
def test_invalid_action_empty(client):
    resp = client.post("/access", json={"user_id": "u1", "resource": "r", "action": ""})
    assert resp.status_code == 422


# 17. Invalid IP address format handled gracefully
def test_invalid_ip_format(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json=_access_payload(ip_address="not-an-ip"))
    assert resp.status_code == 200


# 18. Database persistence across multiple requests
def test_database_persistence_across_requests(client):
    initial = client.get("/forensics/summary").json()["total_requests"]
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        client.post("/access", json=_access_payload(user_id="persist_user_1"))
        client.post("/access", json=_access_payload(user_id="persist_user_2"))
    after = client.get("/forensics/summary").json()["total_requests"]
    assert after >= initial + 2


# 19. Response schema validation – all fields present
def test_response_schema_validation(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json=_access_payload())
    data = resp.json()
    for key in ("decision", "risk_score", "reason", "chain_hash"):
        assert key in data


# 20. Export format includes chain_stats
def test_export_format_chain_stats(client):
    resp = client.get("/forensics/export")
    data = resp.json()
    assert "chain_stats" in data
    assert "export_timestamp" in data
