"""
Comprehensive unit tests for ZTForensics API gateway components.
52 tests covering models, blockchain, risk scoring, storage, and API endpoints.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime

# ---------------------------------------------------------------------------
# AccessRequest model validation (10 tests)
# ---------------------------------------------------------------------------

class TestAccessRequestModel:
    """Tests for the AccessRequest Pydantic model."""

    def test_valid_request(self):
        from main import AccessRequest
        req = AccessRequest(user_id="u1", resource="res", action="READ")
        assert req.user_id == "u1"
        assert req.resource == "res"
        assert req.action == "READ"

    def test_default_ip_address(self):
        from main import AccessRequest
        req = AccessRequest(user_id="u1", resource="res", action="READ")
        assert req.ip_address == ""

    def test_default_user_agent(self):
        from main import AccessRequest
        req = AccessRequest(user_id="u1", resource="res", action="READ")
        assert req.user_agent == ""

    def test_default_metadata_none(self):
        from main import AccessRequest
        req = AccessRequest(user_id="u1", resource="res", action="READ")
        assert req.metadata is None

    def test_custom_metadata(self):
        from main import AccessRequest
        req = AccessRequest(user_id="u1", resource="res", action="READ", metadata={"key": "val"})
        assert req.metadata == {"key": "val"}

    def test_empty_user_id_rejected(self):
        from main import AccessRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            AccessRequest(user_id="", resource="res", action="READ")

    def test_empty_resource_rejected(self):
        from main import AccessRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            AccessRequest(user_id="u1", resource="", action="READ")

    def test_empty_action_rejected(self):
        from main import AccessRequest
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            AccessRequest(user_id="u1", resource="res", action="")

    def test_full_request(self):
        from main import AccessRequest
        req = AccessRequest(
            user_id="alice",
            resource="admin_panel",
            action="DELETE",
            ip_address="1.2.3.4",
            user_agent="curl/7.68",
            metadata={"env": "prod"}
        )
        assert req.ip_address == "1.2.3.4"
        assert req.user_agent == "curl/7.68"

    def test_unicode_user_id(self):
        from main import AccessRequest
        req = AccessRequest(user_id="用户123", resource="res", action="READ")
        assert req.user_id == "用户123"


# ---------------------------------------------------------------------------
# Blockchain tests (10 tests)
# ---------------------------------------------------------------------------

class TestBlockchain:
    """Tests for BlockchainManager."""

    def test_genesis_block_created(self):
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        assert len(bm._chain) == 1

    def test_genesis_block_has_previous_hash_zeros(self):
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        assert bm._chain[0]["previous_hash"] == "0" * 64

    def test_add_block_returns_hash(self):
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        h = bm.add_block({"user": "alice", "action": "READ"})
        assert isinstance(h, str) and len(h) == 64

    def test_add_block_increases_chain_length(self):
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        bm.add_block({"a": 1})
        bm.add_block({"a": 2})
        assert len(bm._chain) == 3

    def test_verify_chain_valid(self):
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        bm.add_block({"x": 1})
        result = bm.verify_chain()
        assert result["valid"] is True
        assert result["verified_blocks"] == 1

    def test_verify_chain_detects_tampering(self):
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        bm.add_block({"x": 1})
        # Tamper with the hash
        bm._chain[1]["hash"] = "deadbeef" * 8
        result = bm.verify_chain()
        assert result["valid"] is False

    def test_create_hash_deterministic(self):
        from blockchain import BlockchainManager
        data = {"key": "value", "num": 42}
        h1 = BlockchainManager.create_hash(data)
        h2 = BlockchainManager.create_hash(data)
        assert h1 == h2

    def test_create_hash_returns_64_chars(self):
        from blockchain import BlockchainManager
        h = BlockchainManager.create_hash({"a": 1})
        assert len(h) == 64

    def test_get_chain_stats(self):
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        bm.add_block({"y": 99})
        stats = bm.get_chain_stats()
        assert stats["total_blocks"] == 1
        assert stats["chain_length"] == 2

    def test_verify_empty_chain(self):
        from blockchain import BlockchainManager
        bm = BlockchainManager()
        result = bm.verify_chain()
        assert result["valid"] is True
        assert result["total_blocks"] == 0


# ---------------------------------------------------------------------------
# Risk scoring tests (12 tests)
# ---------------------------------------------------------------------------

class TestRiskScoring:
    """Tests for RiskScorer."""

    def test_default_low_risk(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs.calculate_risk({"ip_address": "8.8.8.8", "user_agent": "Mozilla/5.0",
                                    "resource": "docs", "action": "READ", "user_id": "u1"})
        assert 0.0 <= score <= 1.0

    def test_curl_user_agent_increases_score(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score_curl   = rs.calculate_risk({"ip_address": "8.8.8.8", "user_agent": "curl/7.68",
                                           "resource": "docs", "action": "READ", "user_id": "uA"})
        score_normal = rs.calculate_risk({"ip_address": "8.8.8.8", "user_agent": "Mozilla/5.0",
                                           "resource": "docs", "action": "READ", "user_id": "uB"})
        assert score_curl > score_normal

    def test_admin_resource_increases_score(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score_admin  = rs.calculate_risk({"resource": "admin_panel", "action": "READ",
                                           "user_id": "u1", "ip_address": "8.8.8.8", "user_agent": "Mozilla"})
        score_normal = rs.calculate_risk({"resource": "public_docs", "action": "READ",
                                           "user_id": "u1", "ip_address": "8.8.8.8", "user_agent": "Mozilla"})
        assert score_admin > score_normal

    def test_delete_action_increases_score(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        s_del = rs.calculate_risk({"resource": "docs", "action": "DELETE",
                                    "user_id": "u1", "ip_address": "8.8.8.8", "user_agent": "Mozilla"})
        s_read = rs.calculate_risk({"resource": "docs", "action": "READ",
                                     "user_id": "u1", "ip_address": "8.8.8.8", "user_agent": "Mozilla"})
        assert s_del > s_read

    def test_high_risk_country(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        s = rs.calculate_risk({"resource": "docs", "action": "READ",
                                "user_id": "u1", "ip_address": "8.8.8.8",
                                "user_agent": "Mozilla", "country": "CN"})
        assert s > 0.0

    def test_get_risk_label_low(self):
        from risk_scoring import RiskScorer
        assert RiskScorer.get_risk_label(0.1) == "LOW"

    def test_get_risk_label_medium(self):
        from risk_scoring import RiskScorer
        assert RiskScorer.get_risk_label(0.35) == "MEDIUM"

    def test_get_risk_label_high(self):
        from risk_scoring import RiskScorer
        assert RiskScorer.get_risk_label(0.6) == "HIGH"

    def test_get_risk_label_critical(self):
        from risk_scoring import RiskScorer
        assert RiskScorer.get_risk_label(0.9) == "CRITICAL"

    def test_score_capped_at_one(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        # Pile on every risk factor
        score = rs.calculate_risk({
            "ip_address": "10.0.0.1",
            "user_agent": "curl/7.68",
            "resource": "admin",
            "action": "DELETE",
            "user_id": "evil",
            "country": "KP"
        })
        assert score <= 1.0

    def test_score_is_float(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        score = rs.calculate_risk({"resource": "x", "action": "READ",
                                    "user_id": "u", "ip_address": "1.1.1.1", "user_agent": "A"})
        assert isinstance(score, float)

    def test_repeated_failures_increase_score(self):
        from risk_scoring import RiskScorer
        rs = RiskScorer()
        uid = "brute_force_user_unique_test"
        for _ in range(3):
            rs.record_failure(uid)
        score = rs.calculate_risk({"resource": "docs", "action": "READ",
                                    "user_id": uid, "ip_address": "8.8.8.8", "user_agent": "Mozilla"})
        # After 3 failures the failure factor adds 0.3
        assert score >= 0.3


# ---------------------------------------------------------------------------
# Storage tests (10 tests)
# ---------------------------------------------------------------------------

class TestStorage:
    """Tests for StorageManager (MinIO mocked)."""

    def _make_manager(self):
        """Return a StorageManager with a mocked Minio client."""
        with patch("storage.Minio") as MockMinio:
            mock_client = MagicMock()
            MockMinio.return_value = mock_client
            from storage import StorageManager
            mgr = StorageManager()
            mgr._client = mock_client
            return mgr, mock_client

    def test_ensure_bucket_creates_when_missing(self):
        mgr, mock_client = self._make_manager()
        mock_client.bucket_exists.return_value = False
        result = mgr.ensure_bucket("test-bucket")
        assert result is True
        mock_client.make_bucket.assert_called_once_with("test-bucket")

    def test_ensure_bucket_skips_existing(self):
        mgr, mock_client = self._make_manager()
        mock_client.bucket_exists.return_value = True
        result = mgr.ensure_bucket("existing-bucket")
        assert result is True
        mock_client.make_bucket.assert_not_called()

    def test_upload_file_success(self):
        mgr, mock_client = self._make_manager()
        mock_client.bucket_exists.return_value = True
        result = mgr.upload_file("bucket", "file.txt", b"hello", "text/plain")
        assert result is True
        mock_client.put_object.assert_called_once()

    def test_upload_file_failure(self):
        from minio.error import S3Error
        mgr, mock_client = self._make_manager()
        mock_client.bucket_exists.return_value = True
        mock_client.put_object.side_effect = S3Error(
            code="InternalError", message="error", resource="/", request_id="1",
            host_id="h", response=MagicMock(status=500, headers={}, data=b"")
        )
        result = mgr.upload_file("bucket", "file.txt", b"data", "text/plain")
        assert result is False

    def test_download_file_success(self):
        mgr, mock_client = self._make_manager()
        mock_response = MagicMock()
        mock_response.read.return_value = b"file content"
        mock_client.get_object.return_value = mock_response
        content = mgr.download_file("bucket", "file.txt")
        assert content == b"file content"

    def test_download_file_not_found(self):
        from minio.error import S3Error
        mgr, mock_client = self._make_manager()
        mock_client.get_object.side_effect = S3Error(
            code="NoSuchKey", message="Not found", resource="/", request_id="1",
            host_id="h", response=MagicMock(status=404, headers={}, data=b"")
        )
        with pytest.raises(S3Error):
            mgr.download_file("bucket", "missing.txt")

    def test_delete_file_success(self):
        mgr, mock_client = self._make_manager()
        result = mgr.delete_file("bucket", "file.txt")
        assert result is True
        mock_client.remove_object.assert_called_once_with("bucket", "file.txt")

    def test_delete_file_failure(self):
        from minio.error import S3Error
        mgr, mock_client = self._make_manager()
        mock_client.remove_object.side_effect = S3Error(
            code="InternalError", message="err", resource="/", request_id="1",
            host_id="h", response=MagicMock(status=500, headers={}, data=b"")
        )
        result = mgr.delete_file("bucket", "file.txt")
        assert result is False

    def test_list_files_success(self):
        mgr, mock_client = self._make_manager()
        obj = MagicMock()
        obj.object_name = "file.txt"
        obj.size = 100
        obj.last_modified = "2024-01-01T00:00:00"
        mock_client.list_objects.return_value = [obj]
        files = mgr.list_files("bucket")
        assert len(files) == 1
        assert files[0]["name"] == "file.txt"

    def test_list_files_empty(self):
        mgr, mock_client = self._make_manager()
        mock_client.list_objects.return_value = []
        files = mgr.list_files("bucket")
        assert files == []


# ---------------------------------------------------------------------------
# API endpoint tests (10 tests)
# ---------------------------------------------------------------------------

class TestAPIEndpoints:
    """Tests for FastAPI route handlers."""

    @pytest.fixture(autouse=True)
    def client(self):
        """Create a TestClient with SQLite in-memory database."""
        import importlib
        from sqlalchemy import create_engine as real_ce
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        from database import Base

        with patch("storage.Minio"):
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
            self.tc = TestClient(app_module.app, raise_server_exceptions=False)

    def test_root_endpoint(self):
        resp = self.tc.get("/")
        assert resp.status_code == 200
        assert resp.json()["message"] == "ZTForensics API Gateway"

    def test_root_version(self):
        resp = self.tc.get("/")
        assert resp.json()["version"] == "1.0.0"

    def test_health_endpoint_structure(self):
        resp = self.tc.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "services" in data

    def test_health_services_keys(self):
        resp = self.tc.get("/health")
        services = resp.json()["services"]
        assert "database" in services
        assert "blockchain" in services
        assert "storage" in services

    def test_verify_chain_endpoint(self):
        resp = self.tc.get("/forensics/verify-chain")
        assert resp.status_code == 200
        data = resp.json()
        assert "valid" in data

    def test_verify_chain_initially_valid(self):
        resp = self.tc.get("/forensics/verify-chain")
        assert resp.json()["valid"] is True

    def test_summary_endpoint_structure(self):
        resp = self.tc.get("/forensics/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "allowed" in data
        assert "denied" in data

    def test_export_endpoint_structure(self):
        resp = self.tc.get("/forensics/export")
        assert resp.status_code == 200
        data = resp.json()
        assert "evidence" in data
        assert "total_records" in data

    def test_access_missing_user_id(self):
        resp = self.tc.post("/access", json={"resource": "res", "action": "READ"})
        assert resp.status_code == 422

    def test_access_missing_resource(self):
        resp = self.tc.post("/access", json={"user_id": "u1", "action": "READ"})
        assert resp.status_code == 422
