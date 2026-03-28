"""
15 tests for the MinIO StorageManager.
All tests mock minio.Minio to avoid requiring a live MinIO instance.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))

import pytest
from unittest.mock import MagicMock, patch
from minio.error import S3Error


def _s3_error(code="InternalError"):
    return S3Error(
        code=code, message="err", resource="/", request_id="1",
        host_id="h", response=MagicMock(status=500, headers={}, data=b"")
    )


def make_manager(**env_overrides):
    """Return a StorageManager with a mocked Minio client."""
    env = {
        "MINIO_ENDPOINT": "localhost:9000",
        "MINIO_ACCESS_KEY": "minioadmin",
        "MINIO_SECRET_KEY": "minioadmin",
    }
    env.update(env_overrides)
    with patch.dict(os.environ, env):
        with patch("storage.Minio") as MockMinio:
            mock_client = MagicMock()
            MockMinio.return_value = mock_client
            from storage import StorageManager
            mgr = StorageManager()
            mgr._client = mock_client
            return mgr, mock_client


# 1. Initialisation succeeds
def test_storage_manager_init():
    mgr, _ = make_manager()
    assert mgr is not None


# 2. Initialisation failure raises
def test_storage_manager_init_failure():
    with patch("storage.Minio", side_effect=Exception("conn refused")):
        from storage import StorageManager
        with pytest.raises(Exception, match="conn refused"):
            StorageManager()


# 3. ensure_bucket creates bucket when missing
def test_ensure_bucket_creates():
    mgr, client = make_manager()
    client.bucket_exists.return_value = False
    assert mgr.ensure_bucket("new-bucket") is True
    client.make_bucket.assert_called_once_with("new-bucket")


# 4. ensure_bucket returns True when bucket exists
def test_ensure_bucket_exists():
    mgr, client = make_manager()
    client.bucket_exists.return_value = True
    assert mgr.ensure_bucket("existing") is True
    client.make_bucket.assert_not_called()


# 5. upload_file success
def test_upload_file_success():
    mgr, client = make_manager()
    client.bucket_exists.return_value = True
    assert mgr.upload_file("b", "obj.txt", b"data", "text/plain") is True
    client.put_object.assert_called_once()


# 6. upload_file failure (S3Error)
def test_upload_file_failure():
    mgr, client = make_manager()
    client.bucket_exists.return_value = True
    client.put_object.side_effect = _s3_error()
    assert mgr.upload_file("b", "obj.txt", b"data", "text/plain") is False


# 7. download_file success
def test_download_file_success():
    mgr, client = make_manager()
    mock_resp = MagicMock()
    mock_resp.read.return_value = b"hello"
    client.get_object.return_value = mock_resp
    assert mgr.download_file("b", "f.txt") == b"hello"


# 8. download_file raises on not found
def test_download_file_not_found():
    mgr, client = make_manager()
    client.get_object.side_effect = _s3_error("NoSuchKey")
    with pytest.raises(S3Error):
        mgr.download_file("b", "missing.txt")


# 9. delete_file success
def test_delete_file_success():
    mgr, client = make_manager()
    assert mgr.delete_file("b", "f.txt") is True
    client.remove_object.assert_called_once_with("b", "f.txt")


# 10. delete_file failure
def test_delete_file_failure():
    mgr, client = make_manager()
    client.remove_object.side_effect = _s3_error()
    assert mgr.delete_file("b", "f.txt") is False


# 11. list_files success
def test_list_files_success():
    mgr, client = make_manager()
    obj = MagicMock()
    obj.object_name = "report.pdf"
    obj.size = 2048
    obj.last_modified = "2024-06-01T12:00:00"
    client.list_objects.return_value = [obj]
    files = mgr.list_files("b")
    assert len(files) == 1
    assert files[0]["name"] == "report.pdf"


# 12. list_files returns empty list
def test_list_files_empty():
    mgr, client = make_manager()
    client.list_objects.return_value = []
    assert mgr.list_files("b") == []


# 13. Multiple uploads to same bucket
def test_multiple_uploads():
    mgr, client = make_manager()
    client.bucket_exists.return_value = True
    for i in range(5):
        result = mgr.upload_file("b", f"file{i}.txt", b"x" * i, "text/plain")
        assert result is True
    assert client.put_object.call_count == 5


# 14. File content preserved across upload/download cycle
def test_file_content_preserved():
    mgr, client = make_manager()
    client.bucket_exists.return_value = True
    original = b"ZTForensics test content 12345"
    mgr.upload_file("b", "test.bin", original, "application/octet-stream")

    mock_resp = MagicMock()
    mock_resp.read.return_value = original
    client.get_object.return_value = mock_resp

    downloaded = mgr.download_file("b", "test.bin")
    assert downloaded == original


# 15. Custom credentials are passed to Minio
def test_custom_credentials():
    with patch.dict(os.environ, {
        "MINIO_ENDPOINT": "minio.example.com:9000",
        "MINIO_ACCESS_KEY": "mykey",
        "MINIO_SECRET_KEY": "mysecret",
    }):
        with patch("storage.Minio") as MockMinio:
            MockMinio.return_value = MagicMock()
            from storage import StorageManager
            StorageManager()
            call_kwargs = MockMinio.call_args
            assert call_kwargs[0][0] == "minio.example.com:9000"
