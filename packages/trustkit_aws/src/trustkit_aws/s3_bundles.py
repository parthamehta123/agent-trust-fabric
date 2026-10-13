"""S3 bundle transport (ADR-0022 §7): versioned bucket, publisher-only writes."""

from __future__ import annotations

from collections.abc import Callable
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


MAX_BUNDLE_BYTES = 4 * 1024 * 1024
"""Mirrors ``trustkit_policy.bundle.MAX_BUNDLE_BYTES`` (kept local: no dependency on it)."""


def s3_source_factory(region: str) -> Callable[[str, str], S3BundleSource]:
    """``(bucket, key) -> S3BundleSource`` for ``trustkit_policy.runtime.policy_from_env``."""
    import boto3

    client = boto3.client("s3", region_name=region)

    def make(bucket: str, key: str) -> S3BundleSource:
        return S3BundleSource(client, bucket=bucket, key=key, max_bytes=MAX_BUNDLE_BYTES)

    return make
