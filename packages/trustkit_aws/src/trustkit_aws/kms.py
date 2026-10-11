"""KMS-backed ES256 signer: the private key never leaves KMS (ADR-0007, ADR-0010, TM-EXC-01).

At construction (cold start), the signer:

* calls ``GetPublicKey`` once and caches the result;
* fails closed unless KeySpec is ``ECC_NIST_P256``, KeyUsage is ``SIGN_VERIFY``, and
  ``ECDSA_SHA_256`` is an allowed signing algorithm;
* derives ``kid`` as the RFC 7638 thumbprint of that public key.

Per signature:

* ``Sign`` with ``MessageType=RAW``. The assertion is ~400 non-secret bytes, well under KMS's
  4 KiB RAW limit. RAW avoids a moto divergence where ``DIGEST`` is double-hashed, which would
  make emulated and real behaviour disagree (RR-3).
* convert DER -> JOSE, then **verify locally** against the cached public key before returning.
  A signer that returns a bad signature is a deny, not a retry.

Error messages never include the key ARN or account id.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal

from botocore.exceptions import BotoCoreError, ClientError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from joserfc.jwk import thumbprint

from trustkit.signing import SigningError, der_to_jose_es256, es256_public_jwk, verify_es256

if TYPE_CHECKING:
    from mypy_boto3_kms import KMSClient

_KMS_RAW_MESSAGE_LIMIT: Final = 4096
_REQUIRED_SPEC: Final = "ECC_NIST_P256"
_REQUIRED_USAGE: Final = "SIGN_VERIFY"
_SIGNING_ALGORITHM: Final = "ECDSA_SHA_256"


class KmsEs256Signer:
    def __init__(self, kms: KMSClient, key_arn: str) -> None:
        self._kms = kms
        self._key_arn = key_arn
        try:
            meta = kms.get_public_key(KeyId=key_arn)
        except (ClientError, BotoCoreError):
            raise SigningError("kms signing key unavailable") from None

        # Real KMS returns KeySpec; moto returns only the deprecated CustomerMasterKeySpec (ED-4).
        # The stubs mark KeySpec as always present, so read both through a plain dict.
        fields: dict[str, object] = dict(meta)
        spec = fields.get("KeySpec", fields.get("CustomerMasterKeySpec"))
        if (
            spec != _REQUIRED_SPEC
            or meta.get("KeyUsage") != _REQUIRED_USAGE
            or _SIGNING_ALGORITHM not in meta.get("SigningAlgorithms", [])
        ):
            raise SigningError("kms key is not an ES256 signing key")

        try:
            public_key = load_der_public_key(meta["PublicKey"])
        except (ValueError, KeyError):
            raise SigningError("kms public key unreadable") from None
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise SigningError("kms key is not an ES256 signing key")
        self._public_key = public_key
        self._kid = thumbprint(es256_public_jwk(public_key))

    def __repr__(self) -> str:
        return f"KmsEs256Signer(kid={self._kid!r})"

    @property
    def key_id(self) -> str:
        return self._kid

    @property
    def algorithm(self) -> Literal["ES256"]:
        return "ES256"

    def sign(self, signing_input: bytes) -> bytes:
        if len(signing_input) > _KMS_RAW_MESSAGE_LIMIT:
            raise SigningError("signing input exceeds KMS RAW limit")
        try:
            resp = self._kms.sign(
                KeyId=self._key_arn,
                Message=signing_input,
                MessageType="RAW",
                SigningAlgorithm=_SIGNING_ALGORITHM,
            )
        except (ClientError, BotoCoreError):
            raise SigningError("kms sign failed") from None
        jose = der_to_jose_es256(resp["Signature"])
        verify_es256(self._public_key, signing_input, jose)
        return jose
