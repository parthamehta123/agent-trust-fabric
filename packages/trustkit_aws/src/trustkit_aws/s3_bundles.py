"""S3 bundle transport (ADR-0022 §7): versioned bucket, publisher-only writes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from botocore.exceptions import BotoCoreError, ClientError

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


class S3BundleError(Exception):
    """The object exists but could not be read, or the bucket is unreachable."""


class S3BundleSink:
    def __init__(self, client: S3Client, *, bucket: str, key: str) -> None:
        self._c, self._bucket, self._key = client, bucket, key

    def publish(self, data: bytes) -> None:
        try:
            self._c.put_object(
                Bucket=self._bucket, Key=self._key, Body=data, ContentType="application/jose"
            )
        except (ClientError, BotoCoreError):
            raise S3BundleError("bundle publish failed") from None


class S3BundleSource:
    def __init__(self, client: S3Client, *, bucket: str, key: str, max_bytes: int) -> None:
        self._c, self._bucket, self._key, self._max = client, bucket, key, max_bytes

    def fetch(self) -> bytes | None:
        """``None`` if the object doesn't exist; ``S3BundleError`` on any other failure.
        Reads at most ``max_bytes + 1`` bytes (the verifier rejects anything larger)."""
        try:
            obj = self._c.get_object(Bucket=self._bucket, Key=self._key)
            return obj["Body"].read(self._max + 1)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
                return None
            raise S3BundleError("bundle fetch failed") from None
        except BotoCoreError:
            raise S3BundleError("bundle store unreachable") from None
