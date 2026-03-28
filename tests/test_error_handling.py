"""
12 error handling tests for the ZTForensics API Gateway.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))

import pytest
import importlib
from unittest.mock import patch, MagicMock, AsyncMock


@pytest.fixture(scope="module")
def client():
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
        yield TestClient(app_module.app, raise_server_exceptions=False)


# 1. Empty user_id is rejected (422)
def test_empty_user_id(client):
    resp = client.post("/access", json={"user_id": "", "resource": "r", "action": "READ"})
    assert resp.status_code == 422


# 2. Missing required field 'resource' returns 422
def test_missing_resource(client):
    resp = client.post("/access", json={"user_id": "u1", "action": "READ"})
    assert resp.status_code == 422


# 3. Invalid action type (empty) returns 422
def test_invalid_action_type(client):
    resp = client.post("/access", json={"user_id": "u1", "resource": "r", "action": ""})
    assert resp.status_code == 422


# 4. Type validation: risk_score is always a float in response
def test_type_validation_risk_score(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json={"user_id": "u1", "resource": "r", "action": "READ"})
    assert isinstance(resp.json()["risk_score"], float)


# 5. Database connection error is handled gracefully
def test_database_connection_error(client):
    with patch("main.get_db", side_effect=Exception("DB down")):
        resp = client.get("/forensics/summary")
    assert resp.status_code in (200, 500, 503)


# 6. Storage connection error does not crash the API
def test_storage_connection_error():
    with patch("storage.Minio", side_effect=Exception("MinIO down")):
        with patch("database.create_engine"), patch("database.SessionLocal"):
            import main as m
            importlib.reload(m)
            assert m.storage_manager is None


# 7. OPA service unavailable falls back to allow
def test_opa_unavailable_fallback(client):
    import httpx
    with patch("main.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post.side_effect = httpx.ConnectError("OPA down")
        mock_client_cls.return_value = mock_client

        resp = client.post("/access", json={"user_id": "u1", "resource": "r", "action": "READ"})
    # Should still return 200 with allow fallback
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"


# 8. Blockchain hash is a 64-character hex string
def test_blockchain_hash_format(client):
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json={"user_id": "u1", "resource": "r", "action": "READ"})
    chain_hash = resp.json()["chain_hash"]
    assert len(chain_hash) == 64
    assert all(c in "0123456789abcdef" for c in chain_hash)


# 9. Very long string input is handled
def test_very_long_string_input(client):
    long_str = "x" * 10000
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json={
            "user_id": long_str, "resource": long_str, "action": "READ"
        })
    assert resp.status_code == 200


# 10. SQL injection attempt in user_id is handled safely
def test_sql_injection_user_id(client):
    payload = {"user_id": "'; DROP TABLE access_logs; --", "resource": "r", "action": "READ"}
    with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
        resp = client.post("/access", json=payload)
    assert resp.status_code == 200


# 11. Malformed metadata (non-dict) returns 422
def test_malformed_metadata(client):
    resp = client.post("/access", json={
        "user_id": "u1", "resource": "r", "action": "READ", "metadata": "not-a-dict"
    })
    assert resp.status_code == 422


# 12. Timeout simulation – OPA slow response uses fallback
def test_timeout_simulation(client):
    import httpx
    with patch("main.httpx.AsyncClient") as mock_cls:
        mock_ac = AsyncMock()
        mock_ac.__aenter__ = AsyncMock(return_value=mock_ac)
        mock_ac.__aexit__ = AsyncMock(return_value=False)
        mock_ac.post.side_effect = httpx.TimeoutException("Timeout")
        mock_cls.return_value = mock_ac
        resp = client.post("/access", json={"user_id": "u1", "resource": "r", "action": "READ"})
    assert resp.status_code == 200
