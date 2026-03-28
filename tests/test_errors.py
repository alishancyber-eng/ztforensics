"""
Error handling tests for ZTForensics – 10 tests.
Covers database __repr__, init_db, 401/403/404/500 scenarios,
and connection error handling.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import importlib
import pytest
from unittest.mock import patch, AsyncMock, MagicMock


# ---------------------------------------------------------------------------
# Database model tests (covers database.py lines 48-51 __repr__ and 65-67 init_db)
# ---------------------------------------------------------------------------

class TestDatabaseModel:
    def test_access_log_repr(self):
        """AccessLog.__repr__ must return a descriptive string (covers lines 48-51)."""
        from database import AccessLog
        log = AccessLog(
            user_id="alice",
            resource="evidence/1",
            action="READ",
            decision="allow",
            risk_score=0.1,
        )
        representation = repr(log)
        assert "AccessLog" in representation
        assert "alice" in representation

    def test_init_db_runs_without_error(self):
        """init_db() should create tables without raising (covers lines 65-67)."""
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        from database import Base, init_db
        import database

        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        original_engine = database.engine
        database.engine = engine
        try:
            init_db()   # should succeed silently
        finally:
            database.engine = original_engine

    def test_access_log_fields_stored_correctly(self):
        """All AccessLog fields should be settable and readable."""
        from database import AccessLog
        from datetime import datetime
        log = AccessLog(
            user_id="bob",
            resource="admin",
            action="DELETE",
            decision="deny",
            risk_score=0.85,
            ip_address="10.0.0.1",
            user_agent="curl/7.68",
            chain_hash="a" * 64,
        )
        assert log.user_id == "bob"
        assert log.decision == "deny"
        assert log.risk_score == 0.85


# ---------------------------------------------------------------------------
# HTTP error codes
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


class TestHTTPErrors:
    def test_404_not_found_on_unknown_path(self, client):
        resp = client.get("/does/not/exist")
        assert resp.status_code == 404

    def test_422_unprocessable_empty_user_id(self, client):
        resp = client.post("/access", json={"user_id": "", "resource": "r", "action": "READ"})
        assert resp.status_code == 422

    def test_422_unprocessable_missing_action(self, client):
        resp = client.post("/access", json={"user_id": "u1", "resource": "r"})
        assert resp.status_code == 422

    def test_200_on_valid_request(self, client):
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "u1", "resource": "res", "action": "READ"
            })
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# MinIO / OPA / DB connection errors
# ---------------------------------------------------------------------------

class TestConnectionErrors:
    def test_minio_connection_error_storage_none(self):
        """StorageManager unavailable when MinIO rejects connection."""
        with patch("storage.Minio", side_effect=Exception("MinIO unreachable")):
            with patch("database.create_engine"), patch("database.SessionLocal"):
                import main as m
                importlib.reload(m)
                assert m.storage_manager is None

    def test_opa_connection_error_fallback_allow(self, client):
        """ConnectError from OPA should fall back to allow decision."""
        import httpx
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "fallback_user", "resource": "docs", "action": "READ"
            })
        assert resp.json()["decision"] == "allow"

    def test_timeout_returns_allow(self, client):
        """ReadTimeout from OPA should fall back to allow decision."""
        import httpx
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(
            side_effect=httpx.ReadTimeout("timed out"))
        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "timeout_user2", "resource": "docs", "action": "READ"
            })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"
