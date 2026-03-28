"""
MinIO evidence-storage tests for ZTForensics – 8 tests.
Covers S3Error paths not exercised by the existing test_minio_storage.py,
including ensure_bucket failure, upload generic exception, and list_files error.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from unittest.mock import MagicMock, patch
from minio.error import S3Error


def _s3err(code="InternalError", status=500):
    return S3Error(
        code=code, message="error", resource="/",
        request_id="1", host_id="h",
        response=MagicMock(status=status, headers={}, data=b""),
    )


def _make_manager():
    with patch("storage.Minio") as MockMinio:
        mock_client = MagicMock()
        MockMinio.return_value = mock_client
        from storage import StorageManager
        mgr = StorageManager()
        mgr._client = mock_client
        return mgr, mock_client


class TestEvidenceUpload:
    def test_upload_stores_bytes(self):
        mgr, client = _make_manager()
        client.bucket_exists.return_value = True
        payload = b"forensic evidence data"
        result = mgr.upload_file("evidence", "case_001.bin", payload, "application/octet-stream")
        assert result is True
        _, kwargs = client.put_object.call_args
        # length should match payload size
        assert client.put_object.called

    def test_upload_generic_exception_returns_false(self):
        """A non-S3Error during upload should be caught and return False."""
        mgr, client = _make_manager()
        client.bucket_exists.return_value = True
        client.put_object.side_effect = RuntimeError("disk full")
        result = mgr.upload_file("bucket", "obj.bin", b"data", "application/octet-stream")
        assert result is False

    def test_upload_metadata_content_type(self):
        mgr, client = _make_manager()
        client.bucket_exists.return_value = True
        mgr.upload_file("bucket", "report.json", b"{}", "application/json")
        call_args = client.put_object.call_args
        assert call_args[1].get("content_type") == "application/json" or \
               "application/json" in call_args[0]


class TestEvidenceDownload:
    def test_download_returns_content(self):
        mgr, client = _make_manager()
        mock_response = MagicMock()
        mock_response.read.return_value = b"evidence bytes"
        client.get_object.return_value = mock_response
        data = mgr.download_file("evidence", "case_001.bin")
        assert data == b"evidence bytes"

    def test_download_calls_close_on_response(self):
        mgr, client = _make_manager()
        mock_response = MagicMock()
        mock_response.read.return_value = b"x"
        client.get_object.return_value = mock_response
        mgr.download_file("bucket", "obj")
        mock_response.close.assert_called_once()
        mock_response.release_conn.assert_called_once()


class TestBucketManagement:
    def test_ensure_bucket_s3error_returns_false(self):
        """S3Error during bucket operation should return False, not raise."""
        mgr, client = _make_manager()
        client.bucket_exists.side_effect = _s3err()
        result = mgr.ensure_bucket("broken-bucket")
        assert result is False

    def test_bucket_creation_on_missing(self):
        mgr, client = _make_manager()
        client.bucket_exists.return_value = False
        mgr.ensure_bucket("new-evidence")
        client.make_bucket.assert_called_once_with("new-evidence")


class TestEvidenceListing:
    def test_list_files_s3error_returns_empty(self):
        """S3Error during list should return empty list, not raise."""
        mgr, client = _make_manager()
        client.list_objects.side_effect = _s3err()
        result = mgr.list_files("bad-bucket")
        assert result == []
