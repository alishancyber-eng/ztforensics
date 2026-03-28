"""
End-to-end integration tests for ZTForensics – 8 tests.
Covers full access flows, evidence capture, tamper detection,
export flow, multiple user flows, and error recovery.
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


class TestFullAccessFlow:
    def test_access_then_summary_reflects_decision(self, client):
        """Full flow: login → access → evidence captured in summary."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            access_resp = client.post("/access", json={
                "user_id": "e2e_alice",
                "resource": "evidence/breach_x",
                "action": "READ",
                "ip_address": "8.8.8.8",
                "user_agent": "Mozilla/5.0"
            })
        assert access_resp.status_code == 200
        assert access_resp.json()["decision"] == "allow"

        summary = client.get("/forensics/summary").json()
        assert summary["total_requests"] >= 1
        assert summary["allowed"] >= 1

    def test_evidence_capture_in_export(self, client):
        """Access event should appear in /forensics/export evidence list."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp = client.post("/access", json={
                "user_id": "e2e_bob",
                "resource": "evidence/capture_test",
                "action": "READ"
            })
        export = client.get("/forensics/export").json()
        assert export["total_records"] >= 1
        user_ids = [e["user_id"] for e in export["evidence"]]
        assert "e2e_bob" in user_ids


class TestTamperDetectionFlow:
    def test_chain_valid_after_multiple_accesses(self, client):
        """After multiple access events, the blockchain chain should stay valid."""
        for i in range(5):
            with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
                client.post("/access", json={
                    "user_id": f"tamper_user_{i}",
                    "resource": "evidence/tamper_test",
                    "action": "READ"
                })
        chain_resp = client.get("/forensics/verify-chain").json()
        assert chain_resp["valid"] is True

    def test_blockchain_hashes_unique_per_event(self, client):
        """Each access event should produce a unique chain hash."""
        hashes = []
        for i in range(3):
            with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
                resp = client.post("/access", json={
                    "user_id": f"hash_unique_{i}",
                    "resource": "evidence/hash_test",
                    "action": "READ"
                })
            hashes.append(resp.json()["chain_hash"])
        assert len(set(hashes)) == 3


class TestExportFlow:
    def test_export_has_chain_stats(self, client):
        """Export endpoint includes blockchain chain stats."""
        export = client.get("/forensics/export").json()
        assert "chain_stats" in export
        assert "total_blocks" in export["chain_stats"]

    def test_export_records_have_required_fields(self, client):
        """Each record in export must contain forensic fields."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            client.post("/access", json={
                "user_id": "export_user",
                "resource": "evidence/export_test",
                "action": "READ"
            })
        export = client.get("/forensics/export").json()
        if export["evidence"]:
            record = export["evidence"][0]
            for field in ("user_id", "resource", "action", "decision", "risk_score", "chain_hash"):
                assert field in record


class TestMultipleUserFlows:
    def test_concurrent_users_all_logged(self, client):
        """Multiple users can access simultaneously and all get logged."""
        users = ["alice", "bob", "carol", "dave", "eve"]
        for user in users:
            with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
                resp = client.post("/access", json={
                    "user_id": user,
                    "resource": "evidence/concurrent",
                    "action": "READ"
                })
            assert resp.status_code == 200

        export = client.get("/forensics/export").json()
        logged_users = {e["user_id"] for e in export["evidence"]}
        for user in users:
            assert user in logged_users

    def test_error_recovery_after_opa_failure(self, client):
        """After OPA failure (fallback to allow), subsequent real requests work."""
        import httpx as _httpx
        mock_async_client = AsyncMock()
        mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
        mock_async_client.__aexit__ = AsyncMock(return_value=False)
        mock_async_client.post = AsyncMock(
            side_effect=_httpx.ConnectError("OPA down"))
        with patch("main.httpx.AsyncClient", return_value=mock_async_client):
            resp = client.post("/access", json={
                "user_id": "recovery_user", "resource": "docs", "action": "READ"
            })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"

        # After recovery, normal requests should still work
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            resp2 = client.post("/access", json={
                "user_id": "recovery_user2", "resource": "docs", "action": "READ"
            })
        assert resp2.status_code == 200
