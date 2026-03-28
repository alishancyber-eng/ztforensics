"""
Performance tests for ZTForensics – 6 tests.
Verifies that risk scoring, OPA decisions, hash chain verification,
evidence listing, and API responses all complete within specified limits.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import importlib
import time
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


# ---------------------------------------------------------------------------
# Performance tests
# ---------------------------------------------------------------------------

class TestPerformance:
    def test_risk_scoring_under_50ms(self):
        """risk_scorer.calculate_risk() must complete in < 50 ms."""
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        request = {
            "ip_address": "8.8.8.8", "user_agent": "Mozilla/5.0",
            "resource": "evidence/perf_test", "action": "READ",
            "user_id": "perf_user"
        }
        start = time.perf_counter()
        for _ in range(10):
            rs.calculate_risk(request)
        elapsed_ms = (time.perf_counter() - start) * 1000 / 10
        assert elapsed_ms < 50, f"Risk scoring took {elapsed_ms:.1f} ms (limit: 50 ms)"

    def test_hash_chain_verification_under_200ms(self):
        """BlockchainManager.verify_chain() on 100 blocks must complete in < 200 ms."""
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        for i in range(100):
            bm.add_block({"event": f"access_{i}", "user": "perf_user"})
        start = time.perf_counter()
        result = bm.verify_chain()
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert result["valid"] is True
        assert elapsed_ms < 200, f"Chain verify took {elapsed_ms:.1f} ms (limit: 200 ms)"

    def test_opa_decision_mock_under_100ms(self, client):
        """A full /access call with mocked OPA should complete in < 100 ms."""
        with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
            start = time.perf_counter()
            resp = client.post("/access", json={
                "user_id": "perf_opa_user", "resource": "docs", "action": "READ",
                "ip_address": "8.8.8.8", "user_agent": "Mozilla/5.0"
            })
            elapsed_ms = (time.perf_counter() - start) * 1000
        assert resp.status_code == 200
        assert elapsed_ms < 100, f"OPA decision took {elapsed_ms:.1f} ms (limit: 100 ms)"

    def test_evidence_listing_under_500ms(self, client):
        """The /forensics/export endpoint should respond in < 500 ms."""
        # Pre-populate some entries
        for i in range(20):
            with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
                client.post("/access", json={
                    "user_id": f"listing_user_{i}",
                    "resource": "evidence/perf",
                    "action": "READ"
                })
        start = time.perf_counter()
        resp = client.get("/forensics/export")
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert resp.status_code == 200
        assert elapsed_ms < 500, f"Evidence listing took {elapsed_ms:.1f} ms (limit: 500 ms)"

    def test_concurrent_access_10_users(self, client):
        """10 sequential access requests (simulating concurrency) must all succeed."""
        results = []
        for i in range(10):
            with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
                resp = client.post("/access", json={
                    "user_id": f"concurrent_user_{i}",
                    "resource": "evidence/concurrent_perf",
                    "action": "READ",
                    "ip_address": "8.8.8.8",
                    "user_agent": "Mozilla/5.0"
                })
            results.append(resp.status_code)
        assert all(s == 200 for s in results)
        assert len(results) == 10

    def test_api_response_time_under_load(self, client):
        """Average response time for 20 requests must stay below 100 ms each."""
        times = []
        for i in range(20):
            with patch("main._query_opa", new_callable=AsyncMock, return_value={"allow": True}):
                start = time.perf_counter()
                resp = client.post("/access", json={
                    "user_id": f"load_user_{i}",
                    "resource": "docs",
                    "action": "READ"
                })
                elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)
        avg_ms = sum(times) / len(times)
        assert avg_ms < 100, f"Average response time was {avg_ms:.1f} ms (limit: 100 ms)"
