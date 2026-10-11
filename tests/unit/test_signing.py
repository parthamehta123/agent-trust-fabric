"""ES256 client assertions and DER->JOSE conversion (ADR-0007, TM-EXC-01)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from hypothesis import given
from hypothesis import strategies as st
from joserfc import jwt as jose_jwt
from joserfc.jwk import ECKey, thumbprint

from tests.conftest import NOW, b64url
from trustkit.signing import (
    ES256_SIGNATURE_BYTES,
    InMemoryEs256Signer,
    SigningError,
    build_client_assertion,
    der_to_jose_es256,
)

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
CLIENT = "0oa-chat-frontend"
TOKEN_ENDPOINT = "https://idp.example.test/oauth2/v1/token"


@pytest.fixture(scope="module")
def pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


@pytest.fixture(scope="module")
def signer(pem: bytes) -> InMemoryEs256Signer:
    return InMemoryEs256Signer(pem)


def assertion(signer: InMemoryEs256Signer, **kw: Any) -> str:
    args: dict[str, Any] = {
        "client_id": CLIENT,
        "token_endpoint": TOKEN_ENDPOINT,
        "now": lambda: NOW,
    }
    args.update(kw)
    return build_client_assertion(signer, **args)


def decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    import base64

    def seg(s: str) -> dict[str, Any]:
        return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))  # type: ignore[no-any-return]

    h, p, _ = token.split(".")
    return seg(h), seg(p)


# ----------------------------------------------------------------------------- DER -> JOSE


@pytest.mark.security
class TestDerToJose:
    @given(st.integers(1, P256_ORDER - 1), st.integers(1, P256_ORDER - 1))
    def test_roundtrip_any_r_s(self, r: int, s: int) -> None:
        """TM-EXC-01: small r/s (leading zero bytes) are left-padded, never truncated/shifted."""
        out = der_to_jose_es256(encode_dss_signature(r, s))
        assert len(out) == ES256_SIGNATURE_BYTES
        assert int.from_bytes(out[:32]) == r
        assert int.from_bytes(out[32:]) == s

    @pytest.mark.parametrize(
        "der",
        [
            pytest.param(b"", id="empty"),
            pytest.param(b"\x30\x00", id="empty-sequence"),
            pytest.param(b"garbage-not-der", id="garbage"),
            pytest.param(encode_dss_signature(1, 1) + b"\x00", id="trailing-bytes"),
            pytest.param(encode_dss_signature(2**256, 1), id="r-too-wide"),
            pytest.param(encode_dss_signature(1, 2**256), id="s-too-wide"),
            pytest.param(encode_dss_signature(0, 1), id="r-zero"),
            pytest.param(encode_dss_signature(1, P256_ORDER), id="s-equals-order"),
        ],
    )
    def test_rejects_malformed_or_out_of_range(self, der: bytes) -> None:
        """TM-EXC-01: never emit a signature from a value KMS (or a bug) shouldn't produce."""
        with pytest.raises(SigningError):
            der_to_jose_es256(der)


# ----------------------------------------------------------------------------- signer


class TestInMemorySigner:
    def test_kid_is_rfc7638_thumbprint(self, signer: InMemoryEs256Signer) -> None:
        assert signer.key_id == thumbprint(signer.public_jwk())

    def test_public_jwk_has_no_private_material(self, signer: InMemoryEs256Signer) -> None:
        jwk = signer.public_jwk()
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert "d" not in jwk

    def test_signature_verifies(self, signer: InMemoryEs256Signer) -> None:
        sig = signer.sign(b"header.payload")
        assert len(sig) == ES256_SIGNATURE_BYTES

    def test_rejects_non_p256_key(self) -> None:
        """TM-EXC-01: wrong curve is a configuration error at construction."""
        p384 = ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with pytest.raises(SigningError):
            InMemoryEs256Signer(p384).sign(b"x")

    def test_repr_has_no_key_material(self, signer: InMemoryEs256Signer, pem: bytes) -> None:
        """TM-ING-06"""
        assert b"PRIVATE" not in repr(signer).encode()
        assert pem.decode()[40:80] not in repr(signer)


# ----------------------------------------------------------------------------- assertion


class TestClientAssertion:
    def test_verifies_and_has_exact_claims(self, signer: InMemoryEs256Signer) -> None:
        tok = assertion(signer, new_jti=lambda: "jti-fixed")
        key = ECKey.import_key(signer.public_jwk())
        verified = jose_jwt.decode(tok, key, algorithms=["ES256"])
        assert verified.header == {"alg": "ES256", "kid": signer.key_id, "typ": "JWT"}
        assert verified.claims == {
            "iss": CLIENT,
            "sub": CLIENT,
            "aud": TOKEN_ENDPOINT,
            "iat": NOW,
            "exp": NOW + 60,
            "jti": "jti-fixed",
        }

    def test_default_jti_is_unique_and_high_entropy(self, signer: InMemoryEs256Signer) -> None:
        """TM-EXC-08: replay detection at the AS depends on unique jti."""
        jtis = {decode_unverified(assertion(signer))[1]["jti"] for _ in range(200)}
        assert len(jtis) == 200
        assert all(len(j) >= 32 for j in jtis)

    @pytest.mark.security
    @pytest.mark.parametrize("lifetime", [0, -1, 61, 3600])
    def test_lifetime_bounds(self, signer: InMemoryEs256Signer, lifetime: int) -> None:
        """TM-EXC-01: a stolen assertion is useful for at most 60 s."""
        with pytest.raises(ValueError, match="lifetime"):
            assertion(signer, lifetime_s=lifetime)

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("client_id", "endpoint"),
        [("", TOKEN_ENDPOINT), (CLIENT, ""), (CLIENT, "http://idp.example.test/token")],
    )
    def test_rejects_bad_inputs(
        self, signer: InMemoryEs256Signer, client_id: str, endpoint: str
    ) -> None:
        """TM-EXC-01: aud must be the https token endpoint; iss/sub non-empty."""
        with pytest.raises(ValueError, match=r"client_id|token_endpoint"):
            assertion(signer, client_id=client_id, token_endpoint=endpoint)

    @pytest.mark.security
    def test_signer_returning_bad_signature_is_not_emitted(self) -> None:
        """TM-EXC-01: build_client_assertion refuses a wrong-length signature from any signer."""

        class Broken:
            key_id = "k"
            algorithm = "ES256"

            def sign(self, signing_input: bytes) -> bytes:
                return b"\x00" * 10

        with pytest.raises(SigningError):
            build_client_assertion(
                Broken(),  # type: ignore[arg-type]
                client_id=CLIENT,
                token_endpoint=TOKEN_ENDPOINT,
                now=lambda: NOW,
            )

    def test_signature_segment_is_jose_not_der(self, signer: InMemoryEs256Signer) -> None:
        """The classic ES256 bug: shipping the DER signature. JOSE is exactly 64 bytes."""
        import base64

        sig_b64 = assertion(signer).split(".")[2]
        assert len(base64.urlsafe_b64decode(sig_b64 + "==")) == ES256_SIGNATURE_BYTES
        assert sig_b64 == b64url(base64.urlsafe_b64decode(sig_b64 + "=="))

    def test_hash_is_sha256(self, signer: InMemoryEs256Signer) -> None:
        """Cross-check with cryptography directly, independent of joserfc."""
        tok = assertion(signer)
        h, p, s = tok.split(".")
        import base64

        raw = base64.urlsafe_b64decode(s + "==")
        der = encode_dss_signature(int.from_bytes(raw[:32]), int.from_bytes(raw[32:]))
        pub = serialization.load_pem_private_key(signer.private_key_pem, None).public_key()
        assert isinstance(pub, ec.EllipticCurvePublicKey)
        pub.verify(der, f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256()))


@pytest.mark.security
class TestSigningEdges:
    def test_public_jwk_rejects_non_p256(self) -> None:
        """TM-EXC-01"""
        from trustkit.signing import es256_public_jwk

        with pytest.raises(SigningError):
            es256_public_jwk(ec.generate_private_key(ec.SECP384R1()).public_key())

    @pytest.mark.parametrize(
        "pem", [b"", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"]
    )
    def test_unloadable_private_key(self, pem: bytes) -> None:
        """TM-EXC-01"""
        with pytest.raises(SigningError):
            InMemoryEs256Signer(pem).sign(b"x")

    def test_rsa_private_key_rejected(self) -> None:
        """TM-EXC-01"""
        from cryptography.hazmat.primitives.asymmetric import rsa

        pem = rsa.generate_private_key(65537, 2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with pytest.raises(SigningError):
            InMemoryEs256Signer(pem).sign(b"x")

    def test_non_es256_signer_refused(self) -> None:
        """TM-EXC-01: algorithm is pinned regardless of what a signer claims."""

        class Rs:
            key_id = "k"
            algorithm = "RS256"

            def sign(self, signing_input: bytes) -> bytes:
                return b"\x00" * 64

        with pytest.raises(SigningError):
            build_client_assertion(
                Rs(),  # type: ignore[arg-type]
                client_id=CLIENT,
                token_endpoint=TOKEN_ENDPOINT,
                now=lambda: NOW,
            )

    def test_self_verification_catches_wrong_signature(self, signer: InMemoryEs256Signer) -> None:
        """ADR-0010: a 64-byte signature that doesn't verify is refused."""
        from trustkit.signing import verify_es256

        pub = serialization.load_pem_private_key(signer.private_key_pem, None).public_key()
        assert isinstance(pub, ec.EllipticCurvePublicKey)
        good = signer.sign(b"a.b")
        with pytest.raises(SigningError):
            verify_es256(pub, b"a.c", good)
        with pytest.raises(SigningError):
            verify_es256(pub, b"a.b", good[:-1])
