"""
MinIO object-storage module for ZTForensics API Gateway.
"""
import io
import logging
import os
from typing import Any

from dotenv import load_dotenv
from minio import Minio
from minio.error import S3Error

load_dotenv()

logger = logging.getLogger(__name__)


class StorageManager:
    """High-level wrapper around a MinIO client."""

    def __init__(self) -> None:
        endpoint: str = os.getenv("MINIO_ENDPOINT", "localhost:9000")
        access_key: str = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        secret_key: str = os.getenv("MINIO_SECRET_KEY", "minioadmin")
        secure: bool = os.getenv("MINIO_SECURE", "false").lower() == "true"

        try:
            self._client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
            logger.info("StorageManager connected to MinIO at %s", endpoint)
        except Exception as exc:
            logger.error("Failed to initialise MinIO client: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Bucket management
    # ------------------------------------------------------------------

    def ensure_bucket(self, bucket: str) -> bool:
        """Create *bucket* if it does not already exist.

        Args:
            bucket: Name of the S3/MinIO bucket.

        Returns:
            True on success, False on error.
        """
        try:
            if not self._client.bucket_exists(bucket):
                self._client.make_bucket(bucket)
                logger.info("Bucket '%s' created.", bucket)
            return True
        except S3Error as exc:
            logger.error("ensure_bucket failed for '%s': %s", bucket, exc)
            return False

    # ------------------------------------------------------------------
    # Object operations
    # ------------------------------------------------------------------

    def upload_file(
        self,
        bucket: str,
        object_name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> bool:
        """Upload *data* as *object_name* into *bucket*.

        Args:
            bucket: Target bucket name.
            object_name: Object key / path inside the bucket.
            data: Raw bytes to upload.
            content_type: MIME type of the object.

        Returns:
            True on success, False on error.
        """
        try:
            self.ensure_bucket(bucket)
            self._client.put_object(
                bucket,
                object_name,
                io.BytesIO(data),
                length=len(data),
                content_type=content_type,
            )
            logger.debug("Uploaded '%s' to bucket '%s' (%d bytes).", object_name, bucket, len(data))
            return True
        except S3Error as exc:
            logger.error("upload_file failed for '%s/%s': %s", bucket, object_name, exc)
            return False
        except Exception as exc:
            logger.error("Unexpected error during upload_file: %s", exc)
            return False

    def download_file(self, bucket: str, object_name: str) -> bytes:
        """Download and return the bytes of *object_name* from *bucket*.

        Args:
            bucket: Source bucket name.
            object_name: Object key inside the bucket.

        Returns:
            Raw bytes of the object.

        Raises:
            S3Error: If the object does not exist or cannot be retrieved.
        """
        try:
            response = self._client.get_object(bucket, object_name)
            content: bytes = response.read()
            response.close()
            response.release_conn()
            logger.debug("Downloaded '%s' from bucket '%s'.", object_name, bucket)
            return content
        except S3Error as exc:
            logger.error("download_file failed for '%s/%s': %s", bucket, object_name, exc)
            raise

    def delete_file(self, bucket: str, object_name: str) -> bool:
        """Delete *object_name* from *bucket*.

        Args:
            bucket: Target bucket name.
            object_name: Object key to delete.

        Returns:
            True on success, False on error.
        """
        try:
            self._client.remove_object(bucket, object_name)
            logger.debug("Deleted '%s' from bucket '%s'.", object_name, bucket)
            return True
        except S3Error as exc:
            logger.error("delete_file failed for '%s/%s': %s", bucket, object_name, exc)
            return False

    def list_files(self, bucket: str) -> list[dict[str, Any]]:
        """List all objects in *bucket*.

        Args:
            bucket: Bucket name to list.

        Returns:
            List of dicts with keys ``name``, ``size``, ``last_modified``.
        """
        try:
            objects = self._client.list_objects(bucket)
            result: list[dict[str, Any]] = []
            for obj in objects:
                result.append(
                    {
                        "name": obj.object_name,
                        "size": obj.size,
                        "last_modified": str(obj.last_modified),
                    }
                )
            return result
        except S3Error as exc:
            logger.error("list_files failed for bucket '%s': %s", bucket, exc)
            return []
