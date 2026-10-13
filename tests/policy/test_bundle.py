"""Signed bundles: signing, verification, holder semantics (ADR-0022 §5-§6)."""

from __future__ import annotations

import base64
import json
import pathlib
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tests.policy.test_pdp import AGENT, GUARDRAILS, grant
from trustkit.signing import InMemoryEs256Signer
from trustkit_policy.bundle import (
    BUNDLE_TYP,
    MAX_BUNDLE_BYTES,
    Bundle,
    BundleError,
    BundleFailure,
    BundleHolder,
    BundleVerifier,
    RefreshOutcome,
    sign_bundle,
)
from trustkit_policy.grants import generate_permits
from trustkit_policy.sources import BundleSourceError, FileBundleSink, FileBundleSource

T = 1_800_000_000
ISS = "atf-bundle-publisher"


def new_signer() -> InMemoryEs256Signer:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return InMemoryEs256Signer(pem)


SIGNER, ATTACKER = new_signer(), new_signer()


def bundle(version: int = 1, iat: int = T, **over: Any) -> Bundle:
    g = {AGENT: grant()}
    doc: dict[str, Any] = {
        "iss": ISS,
        "bundle_version": version,
        "iat": iat,
        "exp": iat + 600,
        "agents": g,
        "policies": generate_permits(g) + "\n" + GUARDRAILS,
    }
    doc.update(over)
    return Bundle(**doc)


def verifier(now: int = T, signer: InMemoryEs256Signer = SIGNER) -> BundleVerifier:
    return BundleVerifier(signer.public_jwk(), issuer=ISS, now=lambda: now)


def b64(obj: Any) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def forge(header: dict[str, Any], payload: Any, signer: InMemoryEs256Signer = SIGNER) -> bytes:
    signing_input = f"{b64(header)}.{b64(payload)}".encode()
    return signing_input + b"." + b64(signer.sign(signing_input)).encode()


def header(**over: Any) -> dict[str, Any]:
    h = {"alg": "ES256", "kid": SIGNER.key_id, "typ": BUNDLE_TYP}
    h.update(over)
    return {k: v for k, v in h.items() if v is not None}


def payload(**over: Any) -> dict[str, Any]:
    p: dict[str, Any] = json.loads(bundle().model_dump_json())
    p.update(over)
    return p


def fails(failure: BundleFailure, token: bytes, now: int = T) -> None:
    with pytest.raises(BundleError) as e:
        verifier(now).verify(token)
    assert e.value.failure is failure, e.value


class TestSignVerify:
    def test_roundtrip(self) -> None:
        b = bundle()
        token = sign_bundle(b, SIGNER)
        assert verifier().verify(token) == b
        hdr = json.loads(base64.urlsafe_b64decode(token.split(b".")[0] + b"=="))
        assert hdr == {"alg": "ES256", "kid": SIGNER.key_id, "typ": BUNDLE_TYP}

    def test_canonical_bytes(self) -> None:
        """Same content -> identical bytes (equivocation detection depends on it)."""
        g = grant(tools={"tickets": ["b", "a"]})
        b1 = bundle(agents={AGENT: g}, policies=GUARDRAILS)
        b2 = bundle(agents={AGENT: grant(tools={"tickets": ["a", "b"]})}, policies=GUARDRAILS)
        assert sign_bundle(b1, SIGNER).split(b".")[1] == sign_bundle(b2, SIGNER).split(b".")[1]


@pytest.mark.security
class TestVerifyRejects:
    def test_tampered_payload(self) -> None:
        h, _, s = sign_bundle(bundle(), SIGNER).split(b".")
        evil = b64(payload(bundle_version=99)).encode()
        fails(BundleFailure.BAD_SIGNATURE, b".".join([h, evil, s]))

    def test_attacker_key_same_kid(self) -> None:
        fails(BundleFailure.BAD_SIGNATURE, forge(header(), payload(), ATTACKER))

    def test_attacker_kid(self) -> None:
        fails(BundleFailure.WRONG_KEY, forge(header(kid=ATTACKER.key_id), payload(), ATTACKER))

    @pytest.mark.parametrize(
        "h",
        [
            header(alg="none"),
            header(alg="HS256"),
            header(alg="ES384"),
            header(typ="JWT"),
            header(typ=None),
            header(jku="https://attacker.example/jwks"),
            header(x5u="https://attacker.example/cert"),
            header(crit=["exp"]),
            header(jwk={"kty": "EC"}),
        ],
    )
    def test_bad_header(self, h: dict[str, Any]) -> None:
        fails(BundleFailure.BAD_HEADER, forge(h, payload()))

    def test_too_large(self) -> None:
        fails(BundleFailure.TOO_LARGE, b"a" * (MAX_BUNDLE_BYTES + 1))

    @pytest.mark.parametrize(
        "token",
        [b"", b"a.b", b"a.b.c.d", b"!!!.???.###", b"e30.e30.", "é.é.é".encode()],
    )
    def test_malformed(self, token: bytes) -> None:
        with pytest.raises(BundleError) as e:
            verifier().verify(token)
        assert e.value.failure in (BundleFailure.MALFORMED, BundleFailure.BAD_HEADER)

    def test_duplicate_payload_keys(self) -> None:
        dup = json.dumps(payload())[:-1] + ', "bundle_version": 999}'
        fails(BundleFailure.BAD_PAYLOAD, forge(header(), dup.encode()))

    @pytest.mark.parametrize(
        "over",
        [
            {"extra": 1},
            {"bundle_version": "1"},
            {"agents": {"0oa-wrong-key": "GRANT"}},
            None,
        ],
        ids=["extra", "type", "agent-key-mismatch", "not-object"],
    )
    def test_bad_payload(self, over: dict[str, Any] | None) -> None:
        if over is None:
            body: Any = [1, 2]
        else:
            if over.get("agents") == {"0oa-wrong-key": "GRANT"}:
                over = {"agents": {"0oa-wrong-key": json.loads(grant().model_dump_json())}}
            body = payload(**over)
        fails(BundleFailure.BAD_PAYLOAD, forge(header(), body))

    def test_wrong_issuer(self) -> None:
        fails(BundleFailure.WRONG_ISSUER, forge(header(), payload(iss="someone-else")))

    def test_time(self) -> None:
        token = sign_bundle(bundle(), SIGNER)
        fails(BundleFailure.NOT_YET_VALID, token, now=T - 31)
        verifier(T - 30).verify(token)  # leeway
        verifier(T + 599).verify(token)
        fails(BundleFailure.EXPIRED, token, now=T + 600)

    def test_short_lived_bundle_expires_early(self) -> None:
        fails(BundleFailure.EXPIRED, forge(header(), payload(exp=T + 100)), now=T + 100)

    def test_cannot_claim_longer_life_than_max_age(self) -> None:
        fails(BundleFailure.TOO_LONG_LIVED, forge(header(), payload(exp=T + 86_400)))


# ----------------------------------------------------------------------------- holder


class MemSource:
    def __init__(self) -> None:
        self.data: bytes | None = None
        self.fail = False

    def fetch(self) -> bytes | None:
        if self.fail:
            raise BundleSourceError("down")
        return self.data


class Clock:
    def __init__(self) -> None:
        self.t = T

    def __call__(self) -> int:
        return self.t


@pytest.fixture
def holder() -> tuple[BundleHolder, MemSource, Clock]:
    src, clock = MemSource(), Clock()
    v = BundleVerifier(SIGNER.public_jwk(), issuer=ISS, now=clock)
    return BundleHolder(v, src, now=clock), src, clock


class TestHolder:
    def test_nothing_loaded_means_deny_all(self, holder: Any) -> None:
        h, _, _ = holder
        assert h.current() is None
        assert h.refresh() is RefreshOutcome.UNAVAILABLE

    def test_accept_then_newer(self, holder: Any) -> None:
        h, src, clock = holder
        src.data = sign_bundle(bundle(1), SIGNER)
        assert h.refresh() is RefreshOutcome.ACCEPTED
        assert h.current().bundle.bundle_version == 1
        assert h.refresh() is RefreshOutcome.UNCHANGED
        clock.t += 60
        src.data = sign_bundle(bundle(2, iat=clock.t), SIGNER)
        assert h.refresh() is RefreshOutcome.ACCEPTED
        assert h.current().bundle.bundle_version == 2

    @pytest.mark.security
    def test_rollback_rejected(self, holder: Any) -> None:
        h, src, _ = holder
        src.data = sign_bundle(bundle(5), SIGNER)
        h.refresh()
        src.data = sign_bundle(bundle(4), SIGNER)  # validly signed, older
        assert h.refresh() is RefreshOutcome.REJECTED_ROLLBACK
        assert h.current().bundle.bundle_version == 5

    @pytest.mark.security
    def test_equivocation_rejected(self, holder: Any) -> None:
        h, src, _ = holder
        src.data = sign_bundle(bundle(3), SIGNER)
        h.refresh()
        src.data = sign_bundle(bundle(3, agents={}), SIGNER)
        assert h.refresh() is RefreshOutcome.REJECTED_EQUIVOCATION
        assert AGENT in h.current().bundle.agents

    @pytest.mark.security
    def test_invalid_policies_rejected_keeps_current(self, holder: Any) -> None:
        h, src, _ = holder
        src.data = sign_bundle(bundle(1), SIGNER)
        h.refresh()
        src.data = sign_bundle(bundle(2, policies="permit("), SIGNER)
        assert h.refresh() is RefreshOutcome.REJECTED_INVALID
        assert h.current().bundle.bundle_version == 1

    @pytest.mark.security
    def test_source_outage_keeps_current_until_stale(self, holder: Any) -> None:
        h, src, clock = holder
        src.data = sign_bundle(bundle(1), SIGNER)
        h.refresh()
        src.fail = True
        clock.t = T + 599
        assert h.refresh() is RefreshOutcome.UNAVAILABLE
        assert h.current() is not None
        clock.t = T + 601
        assert h.current() is None  # fail closed: deny everything

    @pytest.mark.security
    def test_grant_expiry_inside_fresh_bundle(self, holder: Any) -> None:
        h, src, _ = holder
        g = grant(tier="privileged", expires_at=T + 100)
        src.data = sign_bundle(bundle(1, agents={AGENT: g}), SIGNER)
        h.refresh()
        assert h.current().grant(AGENT, T + 99) == g
        assert h.current().grant(AGENT, T + 100) is None
        assert h.current().grant("0oa-nobody", T) is None


# ----------------------------------------------------------------------------- file transport


class TestFileTransport:
    def test_publish_fetch(self, tmp_path: pathlib.Path) -> None:
        sink, src = FileBundleSink(tmp_path), FileBundleSource(tmp_path / "bundle.jws")
        assert src.fetch() is None
        sink.publish(b"one")
        sink.publish(b"two")
        assert src.fetch() == b"two"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["bundle.jws"]  # no temp left

    def test_world_readable_not_writable(self, tmp_path: pathlib.Path) -> None:
        FileBundleSink(tmp_path).publish(b"x")
        assert (tmp_path / "bundle.jws").stat().st_mode & 0o777 == 0o644

    def test_size_capped_read(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "bundle.jws").write_bytes(b"a" * (MAX_BUNDLE_BYTES + 100))
        assert len(FileBundleSource(tmp_path / "bundle.jws").fetch() or b"") == MAX_BUNDLE_BYTES + 1

    def test_unreadable_is_error(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "bundle.jws").mkdir()
        with pytest.raises(BundleSourceError):
            FileBundleSource(tmp_path / "bundle.jws").fetch()


@pytest.mark.security
class TestKeyHandling:
    def test_non_es256_signer_refused(self) -> None:
        from trustkit.signing import SigningError

        class Rs:
            key_id, algorithm = "k", "RS256"

            def sign(self, data: bytes) -> bytes:
                return b""

        with pytest.raises(SigningError):
            sign_bundle(bundle(), Rs())  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "jwk",
        [{"kty": "RSA", "n": "x", "e": "AQAB"}, {"kty": "EC", "crv": "P-384", "x": "x", "y": "y"}],
    )
    def test_pinned_key_must_be_p256(self, jwk: dict[str, str]) -> None:
        with pytest.raises(ValueError, match="P-256"):
            BundleVerifier(jwk, issuer=ISS)
