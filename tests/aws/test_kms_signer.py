"""KMS ES256 signer against moto (ADR-0007, TM-EXC-01)."""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import boto3
import pytest
from botocore.exceptions import ClientError
from joserfc import jwt as jose_jwt
from joserfc.jwk import ECKey
from moto import mock_aws

from tests.conftest import NOW
from trustkit.signing import ES256_SIGNATURE_BYTES, SigningError, build_client_assertion
from trustkit_aws.kms import KmsEs256Signer

if TYPE_CHECKING:
    from mypy_boto3_kms import KMSClient

TOKEN_ENDPOINT = "https://idp.example.test/oauth2/v1/token"


@pytest.fixture
def kms() -> Iterator[KMSClient]:
    with mock_aws():
        yield boto3.client("kms", region_name="us-east-1")


def make_key(kms: KMSClient, spec: str = "ECC_NIST_P256", usage: str = "SIGN_VERIFY") -> str:
    meta = kms.create_key(KeySpec=spec, KeyUsage=usage)["KeyMetadata"]  # type: ignore[arg-type]
    return meta["Arn"]


class TestKmsSigner:
    def test_assertion_verifies_against_kms_public_key(self, kms: KMSClient) -> None:
        arn = make_key(kms)
        signer = KmsEs256Signer(kms, arn)
        tok = build_client_assertion(
            signer, client_id="0oa-x", token_endpoint=TOKEN_ENDPOINT, now=lambda: NOW
        )
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        pub = load_der_public_key(kms.get_public_key(KeyId=arn)["PublicKey"])
        verified = jose_jwt.decode(tok, ECKey.import_key(pub), algorithms=["ES256"])  # type: ignore[arg-type]
        assert verified.claims["iss"] == "0oa-x"
        assert verified.header["kid"] == signer.key_id

    def test_kid_is_stable_across_instances(self, kms: KMSClient) -> None:
        arn = make_key(kms)
        assert KmsEs256Signer(kms, arn).key_id == KmsEs256Signer(kms, arn).key_id

    def test_signature_is_jose_width(self, kms: KMSClient) -> None:
        assert len(KmsEs256Signer(kms, make_key(kms)).sign(b"a.b")) == ES256_SIGNATURE_BYTES


@pytest.mark.security
class TestKmsSignerFailsClosed:
    @pytest.mark.parametrize(
        ("spec", "usage"),
        [
            ("RSA_2048", "SIGN_VERIFY"),
            ("ECC_NIST_P384", "SIGN_VERIFY"),
            ("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT"),
        ],
    )
    def test_wrong_key_spec_or_usage_rejected_at_construction(
        self, kms: KMSClient, spec: str, usage: str
    ) -> None:
        """TM-EXC-01: misconfigured key is caught at cold start, not on the first request."""
        with pytest.raises(SigningError):
            KmsEs256Signer(kms, make_key(kms, spec, usage))

    def test_unknown_key_rejected_at_construction(self, kms: KMSClient) -> None:
        """TM-EXC-01"""
        with pytest.raises(SigningError):
            KmsEs256Signer(
                kms, "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
            )

    @pytest.mark.parametrize(
        "code", ["DisabledException", "KMSInvalidStateException", "AccessDeniedException"]
    )
    def test_kms_sign_errors_deny(self, kms: KMSClient, code: str) -> None:
        """TM-EXC-01: key disabled/pending deletion/permission revoked after cold start -> deny.

        Injected rather than driven through moto: moto signs with disabled keys (ED-2).
        """
        signer = KmsEs256Signer(kms, make_key(kms))

        def refuse(**_: Any) -> Any:
            raise ClientError({"Error": {"Code": code, "Message": "x"}}, "Sign")

        kms.sign = refuse  # type: ignore[method-assign]
        with pytest.raises(SigningError):
            signer.sign(b"a.b")

    def test_oversized_signing_input_refused_before_kms_call(self, kms: KMSClient) -> None:
        """ADR-0010: KMS RAW messages are limited to 4 KiB."""
        signer = KmsEs256Signer(kms, make_key(kms))
        with pytest.raises(SigningError):
            signer.sign(b"x" * 4097)

    def test_unreadable_public_key_rejected(self, kms: KMSClient) -> None:
        """TM-EXC-01"""
        arn = make_key(kms)
        real = kms.get_public_key

        def corrupt(**kw: Any) -> Any:
            return {**real(**kw), "PublicKey": b"not-der"}

        kms.get_public_key = corrupt  # type: ignore[method-assign]
        with pytest.raises(SigningError):
            KmsEs256Signer(kms, arn)

    def test_public_key_type_mismatch_rejected(self, kms: KMSClient) -> None:
        """TM-EXC-01: metadata claims P-256 but the key material is RSA -> trust neither."""
        ec_arn, rsa_arn = make_key(kms), make_key(kms, "RSA_2048")
        real = kms.get_public_key

        def lying(**kw: Any) -> Any:
            return {**real(KeyId=ec_arn), "PublicKey": real(KeyId=rsa_arn)["PublicKey"]}

        kms.get_public_key = lying  # type: ignore[method-assign]
        with pytest.raises(SigningError):
            KmsEs256Signer(kms, ec_arn)

    def test_repr_is_kid_only(self, kms: KMSClient) -> None:
        """TM-ING-06"""
        arn = make_key(kms)
        signer = KmsEs256Signer(kms, arn)
        assert repr(signer) == f"KmsEs256Signer(kid={signer.key_id!r})"

    def test_kms_returning_signature_from_other_key_is_caught(self, kms: KMSClient) -> None:
        """TM-EXC-01: self-verification catches a wrong-key / corrupted / mis-hashed signature."""
        arn, other = make_key(kms), make_key(kms)
        signer = KmsEs256Signer(kms, arn)
        real_sign = kms.sign

        def sign_with_other(**kw: Any) -> Any:
            return real_sign(**{**kw, "KeyId": other})

        kms.sign = sign_with_other  # type: ignore[method-assign]
        with pytest.raises(SigningError):
            signer.sign(b"a.b")

    def test_error_message_is_log_safe(self, kms: KMSClient) -> None:
        """TM-ING-06: no ARNs or account ids in messages (they aid recon in shared logs)."""
        arn = make_key(kms, "RSA_2048")
        with pytest.raises(SigningError) as ei:
            KmsEs256Signer(kms, arn)
        assert "123456789012" not in str(ei.value)
        assert arn not in str(ei.value)
