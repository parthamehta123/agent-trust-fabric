"""Pins, audit and denied writes (A-11, ADR-0026 §14/§18/§27, TM-INT-03, TM-KB-04)."""

from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError


def test_bundle_pin_matches_the_kms_key(aws: Any, outputs: dict[str, Any]) -> None:
    """A-11: the PEM every verifier pins is the bundle key's public half, read via its alias."""
    pinned = outputs["service_environment"]["mcp-gateway"]["ATF_BUNDLE_PUBLIC_KEY_PEM"]
    der = aws.client("kms").get_public_key(KeyId=outputs["signing_keys"]["bundle"])["PublicKey"]
    from cryptography.hazmat.primitives import serialization as ser

    live = ser.load_der_public_key(der).public_bytes(
        ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo
    )
    assert live.decode().strip() == pinned.strip()


def test_ed4_get_public_key_reports_keyspec(aws: Any, outputs: dict[str, Any]) -> None:
    """ED-4: real KMS returns ``KeySpec`` (moto returned only the deprecated field)."""
    r = aws.client("kms").get_public_key(KeyId=outputs["signing_keys"]["interceptor"])
    assert r["KeySpec"] == "ECC_NIST_P256"


def test_trail_is_logging_with_the_agreed_selectors(aws: Any, outputs: dict[str, Any]) -> None:
    ct = aws.client("cloudtrail")
    arn = outputs["audit"]["trail_arn"]
    assert ct.get_trail_status(Name=arn)["IsLogging"] is True
    names = {s["Name"] for s in ct.get_event_selectors(TrailName=arn)["AdvancedEventSelectors"]}
    assert names == {
        "management",
        "s3-writes-bundles-and-corpus",
        "interceptor-invokes",
        "control-plane-table-writes",
    }


@pytest.mark.security
def test_operator_cannot_delete_audit_logs(aws: Any, outputs: dict[str, Any]) -> None:
    """The deny is evaluated before existence: a made-up key still answers AccessDenied."""
    with pytest.raises(ClientError) as e:
        aws.client("s3").delete_object(
            Bucket=outputs["audit"]["bucket"], Key="AWSLogs/probe/does-not-exist"
        )
    assert e.value.response["Error"]["Code"] == "AccessDenied"


@pytest.mark.security
def test_operator_cannot_write_the_corpus(aws: Any, outputs: dict[str, Any]) -> None:
    """TM-KB-04: only kb-ingest writes the corpus, not even an administrator."""
    with pytest.raises(ClientError) as e:
        aws.client("s3").put_object(
            Bucket=outputs["knowledge"]["source_bucket"], Key="corpus/probe.txt", Body=b"probe"
        )
    assert e.value.response["Error"]["Code"] == "AccessDenied"
