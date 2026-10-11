"""``private_key_jwt`` client assertions signed through a pluggable ``KeySigner`` (ADR-0007/0010).

Only ES256 (ECDSA P-256 / SHA-256) is supported. Signers return the **JOSE** signature encoding
(RFC 7518 §3.4: fixed-width ``r || s``, 64 bytes), not the DER encoding that KMS and most crypto
libraries produce. ``der_to_jose_es256`` is the single conversion point, so getting it wrong
breaks every signer at once, loudly.

Threat-model refs: TM-EXC-01, TM-EXC-08.
"""

from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from typing import Final, Literal, Protocol

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from joserfc.jwk import thumbprint

ES256_SIGNATURE_BYTES: Final = 64
MAX_ASSERTION_LIFETIME_S: Final = 60
_P256_COORD_BYTES: Final = 32
_P256_ORDER: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class SigningError(Exception):
    """Log-safe signing failure. The caller must deny; never retry with another key."""


class KeySigner(Protocol):
    @property
    def key_id(self) -> str:
        """JOSE ``kid``: the RFC 7638 JWK thumbprint of the public key (stable, derivable)."""
        ...

    @property
    def algorithm(self) -> Literal["ES256"]: ...

    def sign(self, signing_input: bytes) -> bytes:
        """Sign ``signing_input`` (the ASCII ``header.payload``) and return a JOSE ES256 signature.

        Implementations must verify their own output against the public key before returning,
        and raise ``SigningError`` on any failure.
        """
        ...


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def der_to_jose_es256(der: bytes) -> bytes:
    """DER ``ECDSA-Sig-Value`` -> 64-byte ``r || s``. Raises ``SigningError`` on anything odd."""
    try:
        r, s = decode_dss_signature(der)
    except (ValueError, TypeError):
        raise SigningError("signature is not valid DER") from None
    if not (0 < r < _P256_ORDER and 0 < s < _P256_ORDER):
        raise SigningError("signature values out of range for P-256")
    return r.to_bytes(_P256_COORD_BYTES, "big") + s.to_bytes(_P256_COORD_BYTES, "big")


def es256_public_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """Public JWK for a P-256 key. Raises ``SigningError`` for any other curve."""
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise SigningError("key is not P-256")
    nums = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(nums.x.to_bytes(_P256_COORD_BYTES, "big")),
        "y": _b64url(nums.y.to_bytes(_P256_COORD_BYTES, "big")),
    }


def verify_es256(
    public_key: ec.EllipticCurvePublicKey, signing_input: bytes, signature: bytes
) -> None:
    """Self-verification used by every signer before it returns (ADR-0010)."""
    if len(signature) != ES256_SIGNATURE_BYTES:
        raise SigningError("signature has wrong length")
    r = int.from_bytes(signature[:_P256_COORD_BYTES], "big")
    s = int.from_bytes(signature[_P256_COORD_BYTES:], "big")
    try:
        public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SigningError("signature failed self-verification") from None


@dataclass(frozen=True)
class InMemoryEs256Signer:
    """Signer over a local P-256 private key, for tests and the local stack only.

    Profiles reference it as ``local:<name>``. It is never used with a KMS ARN.
    """

    private_key_pem: bytes = field(repr=False)

    @cached_property
    def _private_key(self) -> ec.EllipticCurvePrivateKey:
        try:
            key = serialization.load_pem_private_key(self.private_key_pem, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise SigningError("private key could not be loaded") from None
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise SigningError("private key is not an EC key")
        es256_public_jwk(key.public_key())  # raises SigningError unless P-256
        return key

    @property
    def key_id(self) -> str:
        return thumbprint(self.public_jwk())

    @property
    def algorithm(self) -> Literal["ES256"]:
        return "ES256"

    def public_jwk(self) -> dict[str, str]:
        return es256_public_jwk(self._private_key.public_key())

    def sign(self, signing_input: bytes) -> bytes:
        der = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        jose = der_to_jose_es256(der)
        verify_es256(self._private_key.public_key(), signing_input, jose)
        return jose


def build_client_assertion(
    signer: KeySigner,
    *,
    client_id: str,
    token_endpoint: str,
    now: Callable[[], int],
    lifetime_s: int = MAX_ASSERTION_LIFETIME_S,
    new_jti: Callable[[], str] = lambda: secrets.token_urlsafe(32),
) -> str:
    """RFC 7523 §2.2 / OIDC Core §9 ``private_key_jwt`` assertion.

    Header ``{"alg": "ES256", "kid": <thumbprint>, "typ": "JWT"}``. Claims are exactly
    ``iss = sub = client_id``, ``aud = token_endpoint``, ``iat``, ``exp = iat + lifetime_s``
    (0 < lifetime_s <= 60), and a fresh high-entropy ``jti``.
    """
    if not client_id:
        raise ValueError("client_id must be non-empty")
    if not token_endpoint.startswith("https://"):
        raise ValueError("token_endpoint must be an https URL")
    if not 0 < lifetime_s <= MAX_ASSERTION_LIFETIME_S:
        raise ValueError(f"assertion lifetime must be within 1..{MAX_ASSERTION_LIFETIME_S}s")
    if signer.algorithm != "ES256":
        raise SigningError("unsupported signer algorithm")

    iat = now()
    header = {"alg": "ES256", "kid": signer.key_id, "typ": "JWT"}
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "iat": iat,
        "exp": iat + lifetime_s,
        "jti": new_jti(),
    }
    signing_input = ".".join(
        _b64url(json.dumps(part, separators=(",", ":"), sort_keys=True).encode())
        for part in (header, claims)
    )
    signature = signer.sign(signing_input.encode("ascii"))
    if len(signature) != ES256_SIGNATURE_BYTES:
        raise SigningError("signer returned a signature of the wrong length")
    return f"{signing_input}.{_b64url(signature)}"
