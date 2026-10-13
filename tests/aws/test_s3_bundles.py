"""S3 bundle transport (ADR-0022 §7), against moto."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from trustkit_aws.s3_bundles import S3BundleError, S3BundleSink, S3BundleSource

BUCKET, KEY = "atf-bundles", "agents/bundle.jws"


@pytest.fixture
def s3() -> Iterator[Any]:
    with mock_aws():
        c = boto3.client("s3", region_name="us-east-1")
        c.create_bucket(Bucket=BUCKET)
        c.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        yield c


def test_publish_and_fetch(s3: Any) -> None:
    src = S3BundleSource(s3, bucket=BUCKET, key=KEY, max_bytes=1024)
    assert src.fetch() is None
    S3BundleSink(s3, bucket=BUCKET, key=KEY).publish(b"one")
    S3BundleSink(s3, bucket=BUCKET, key=KEY).publish(b"two")
    assert src.fetch() == b"two"
    head = s3.head_object(Bucket=BUCKET, Key=KEY)
    assert head["ContentType"] == "application/jose"
    versions = s3.list_object_versions(Bucket=BUCKET, Prefix=KEY)["Versions"]
    assert len(versions) == 2  # history kept for forensics


def test_read_is_capped(s3: Any) -> None:
    s3.put_object(Bucket=BUCKET, Key=KEY, Body=b"a" * 5000)
    assert len(S3BundleSource(s3, bucket=BUCKET, key=KEY, max_bytes=1024).fetch() or b"") == 1025


@pytest.mark.security
def test_access_denied_is_error_not_absent() -> None:
    """Only NoSuchKey means 'absent'; anything else must not look like 'no bundle yet'."""
    c = boto3.client(
        "s3", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
    )
    stub = Stubber(c)
    stub.add_client_error("get_object", service_error_code="AccessDenied", http_status_code=403)
    with stub, pytest.raises(S3BundleError):
        S3BundleSource(c, bucket=BUCKET, key=KEY, max_bytes=10).fetch()


@pytest.mark.security
def test_publish_failure_raises() -> None:
    c = boto3.client(
        "s3", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
    )
    stub = Stubber(c)
    stub.add_client_error("put_object", service_error_code="AccessDenied", http_status_code=403)
    with stub, pytest.raises(S3BundleError):
        S3BundleSink(c, bucket=BUCKET, key=KEY).publish(b"x")


@pytest.mark.security
def test_unreachable_is_error_not_absent() -> None:
    from botocore.exceptions import EndpointConnectionError

    class Down:
        def get_object(self, **_: Any) -> None:
            raise EndpointConnectionError(endpoint_url="https://s3.invalid")

    with pytest.raises(S3BundleError):
        S3BundleSource(Down(), bucket=BUCKET, key=KEY, max_bytes=10).fetch()  # type: ignore[arg-type]


def test_factory_builds_capped_source(s3: Any) -> None:
    from trustkit_aws.s3_bundles import s3_source_factory

    s3.put_object(Bucket=BUCKET, Key=KEY, Body=b"x")
    assert s3_source_factory("us-east-1")(BUCKET, KEY).fetch() == b"x"


def test_size_constant_matches_policy_package() -> None:
    """Drift guard: the S3 cap mirrors the verifier's cap (kept local to avoid a dependency)."""
    from trustkit_aws.s3_bundles import MAX_BUNDLE_BYTES as AWS_MAX
    from trustkit_policy.bundle import MAX_BUNDLE_BYTES as POLICY_MAX

    assert AWS_MAX == POLICY_MAX
