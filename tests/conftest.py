"""Shared test fixtures: real keys, and a minting helper that can also forge bad tokens."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Mapping
from typing import Any

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey, RSAKey

from trustkit.jwt import PublicKey

ISSUER = "https://idp.example.test/oauth2/ingress"
AUDIENCE = "api://agent-ingress"
NOW = 1_800_000_000  # fixed clock: every test is deterministic


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def raw_jws(header: Mapping[str, Any], claims: Mapping[str, Any], signature: bytes = b"") -> str:
    """Assemble a compact JWS by hand, for tokens no compliant library would produce."""
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(claims).encode())
    return f"{h}.{p}.{b64url(signature)}"


@pytest.fixture(scope="session")
def rsa_key() -> RSAKey:
    return RSAKey.generate_key(2048, parameters={"kid": "rsa-1"}, private=True)


@pytest.fixture(scope="session")
def ec_key() -> ECKey:
    return ECKey.generate_key("P-256", parameters={"kid": "ec-1"}, private=True)


@pytest.fixture(scope="session")
def attacker_rsa_key() -> RSAKey:
    """Same kid as the legitimate key, different key material."""
    return RSAKey.generate_key(2048, parameters={"kid": "rsa-1"}, private=True)


def good_claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "00u-user-1",
        "aud": AUDIENCE,
        "iat": NOW - 10,
        "exp": NOW + 300,
        "jti": "jti-1",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


Mint = Callable[..., str]


@pytest.fixture
def mint(rsa_key: RSAKey) -> Mint:
    def _mint(
        claims: Mapping[str, Any] | None = None,
        *,
        key: RSAKey | ECKey | None = None,
        alg: str = "RS256",
        header: Mapping[str, Any] | None = None,
    ) -> str:
        k = key or rsa_key
        hdr: dict[str, Any] = {"alg": alg, "kid": k.kid}
        hdr.update(header or {})
        hdr = {key_: v for key_, v in hdr.items() if v is not None}
        return jwt.encode(hdr, dict(claims or good_claims()), k, algorithms=[alg])

    return _mint


class StaticKeys:
    """KeyResolver over a fixed set of public keys."""

    def __init__(self, *keys: RSAKey | ECKey) -> None:
        self._by_kid: dict[str, PublicKey] = {}
        for k in keys:
            pub = k.as_dict(private=False)
            imported = RSAKey.import_key(pub) if pub["kty"] == "RSA" else ECKey.import_key(pub)
            assert k.kid is not None
            self._by_kid[k.kid] = imported

    def resolve(self, kid: str) -> PublicKey | None:
        return self._by_kid.get(kid)
