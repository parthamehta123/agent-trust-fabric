"""Signed policy bundles: build, sign, verify, hold (ADR-0022 §5-§6)."""

from __future__ import annotations

import base64
import binascii
import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Final

from cryptography.hazmat.primitives.asymmetric import ec
from joserfc.jwk import thumbprint
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from trustkit.signing import KeySigner, SigningError, verify_es256
from trustkit_policy.grants import AgentGrant
from trustkit_policy.pdp import CedarPdp, PolicyConfigError

if TYPE_CHECKING:
    from trustkit_policy.sources import BundleSource

BUNDLE_TYP: Final = "atf-bundle+jwt"
MAX_BUNDLE_BYTES: Final = 4 * 1024 * 1024
MAX_AGE_S: Final = 600
LEEWAY_S: Final = 30


class Bundle(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    iss: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    bundle_version: Annotated[int, Field(gt=0)]
    iat: Annotated[int, Field(gt=0)]
    exp: Annotated[int, Field(gt=0)]
    agents: dict[str, AgentGrant]
    policies: Annotated[str, StringConstraints(max_length=MAX_BUNDLE_BYTES)]

    @model_validator(mode="after")
    def _keys_match(self) -> Bundle:
        if any(k != g.agent_id for k, g in self.agents.items()):
            raise ValueError("agent map key does not match its grant")
        return self


class BundleFailure(StrEnum):
    TOO_LARGE = "too_large"
    MALFORMED = "malformed"
    BAD_HEADER = "bad_header"
    WRONG_KEY = "wrong_key"
    BAD_SIGNATURE = "bad_signature"
    BAD_PAYLOAD = "bad_payload"
    WRONG_ISSUER = "wrong_issuer"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    TOO_LONG_LIVED = "too_long_lived"


class BundleError(Exception):
    def __init__(self, failure: BundleFailure) -> None:
        self.failure = failure
        super().__init__(failure.value)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(part: bytes) -> bytes:
    if not part or any(c not in _B64_ALPHABET for c in part):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(part + b"=" * (-len(part) % 4))


_B64_ALPHABET: Final = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _canonical(bundle: Bundle) -> bytes:
    def norm(x: object) -> object:
        if isinstance(x, dict):
            return {k: norm(v) for k, v in x.items()}
        if isinstance(x, list):
            items = [norm(v) for v in x]
            return sorted(items) if all(isinstance(i, str) for i in items) else items  # type: ignore[type-var]
        return x

    doc = norm(json.loads(bundle.model_dump_json()))
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def sign_bundle(bundle: Bundle, signer: KeySigner) -> bytes:
    """Compact JWS over canonical JSON (sorted keys, sorted sets, no whitespace)."""
    if signer.algorithm != "ES256":
        raise SigningError("unsupported signer algorithm")
    header = {"alg": "ES256", "kid": signer.key_id, "typ": BUNDLE_TYP}
    signing_input = (
        _b64(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
        + "."
        + _b64(_canonical(bundle))
    ).encode("ascii")
    return signing_input + b"." + _b64(signer.sign(signing_input)).encode("ascii")


def _no_dupes(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)


class BundleVerifier:
    """Verifies against a **pinned** public JWK (never fetched)."""

    def __init__(
        self,
        public_jwk: Mapping[str, str],
        *,
        issuer: str,
        max_age_s: int = MAX_AGE_S,
        now: Callable[[], int] | None = None,
    ) -> None:
        if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
            raise ValueError("bundle key must be an EC P-256 public JWK")
        x = int.from_bytes(_unb64(public_jwk["x"].encode()), "big")
        y = int.from_bytes(_unb64(public_jwk["y"].encode()), "big")
        self._key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        self._kid = thumbprint({k: public_jwk[k] for k in ("crv", "kty", "x", "y")})
        self._issuer, self._max_age = issuer, max_age_s
        self._now = now or (lambda: int(time.time()))

    def verify(self, token: bytes) -> Bundle:
        if len(token) > MAX_BUNDLE_BYTES:
            raise BundleError(BundleFailure.TOO_LARGE)
        parts = token.split(b".")
        if len(parts) != 3:
            raise BundleError(BundleFailure.MALFORMED)
        try:
            header = json.loads(_unb64(parts[0]), object_pairs_hook=_no_dupes)
            signature = _unb64(parts[2])
        except (ValueError, binascii.Error, UnicodeDecodeError, RecursionError):
            raise BundleError(BundleFailure.MALFORMED) from None
        if (
            not isinstance(header, dict)
            or set(header) != {"alg", "kid", "typ"}
            or header["alg"] != "ES256"
            or header["typ"] != BUNDLE_TYP
        ):
            raise BundleError(BundleFailure.BAD_HEADER)
        if header["kid"] != self._kid:
            raise BundleError(BundleFailure.WRONG_KEY)
        try:
            verify_es256(self._key, parts[0] + b"." + parts[1], signature)
        except SigningError:
            raise BundleError(BundleFailure.BAD_SIGNATURE) from None
        try:
            raw = json.loads(_unb64(parts[1]), object_pairs_hook=_no_dupes)
            if not isinstance(raw, dict):
                raise TypeError("payload must be an object")  # noqa: TRY301
            bundle = Bundle.model_validate_json(json.dumps(raw))
        except (
            ValueError,
            TypeError,
            binascii.Error,
            UnicodeDecodeError,
            RecursionError,
            ValidationError,
        ):
            raise BundleError(BundleFailure.BAD_PAYLOAD) from None
        if bundle.iss != self._issuer:
            raise BundleError(BundleFailure.WRONG_ISSUER)
        if bundle.exp - bundle.iat > self._max_age:
            raise BundleError(BundleFailure.TOO_LONG_LIVED)
        now = self._now()
        if bundle.iat > now + LEEWAY_S:
            raise BundleError(BundleFailure.NOT_YET_VALID)
        if now >= bundle.exp:
            raise BundleError(BundleFailure.EXPIRED)
        # No separate staleness check: exp - iat <= max_age, so "older than max_age" is "expired".
        return bundle


@dataclass(frozen=True)
class LoadedBundle:
    bundle: Bundle
    raw: bytes
    pdp: CedarPdp

    def grant(self, agent_id: str, now: int) -> AgentGrant | None:
        """The agent's grant, or ``None`` if absent or past its own ``expires_at``."""
        g = self.bundle.agents.get(agent_id)
        if g is None or (g.expires_at is not None and now >= g.expires_at):
            return None
        return g


class RefreshOutcome(StrEnum):
    ACCEPTED = "accepted"
    UNCHANGED = "unchanged"
    REJECTED_INVALID = "rejected_invalid"
    REJECTED_ROLLBACK = "rejected_rollback"
    REJECTED_EQUIVOCATION = "rejected_equivocation"
    UNAVAILABLE = "unavailable"


class BundleHolder:
    """The gateway's current bundle. ``current()`` is ``None`` (deny everything) when there is
    no bundle or it is older than ``max_age_s``; failed refreshes keep the last good one."""

    def __init__(
        self,
        verifier: BundleVerifier,
        source: BundleSource,
        *,
        max_age_s: int = MAX_AGE_S,
        now: Callable[[], int] | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._verifier, self._source, self._max_age = verifier, source, max_age_s
        self._now = now or (lambda: int(time.time()))
        self._current: LoadedBundle | None = None

    def refresh(self) -> RefreshOutcome:
        try:
            raw = self._source.fetch()
        except Exception:  # noqa: BLE001 - any source failure: keep the last good bundle
            return RefreshOutcome.UNAVAILABLE
        if raw is None:
            return RefreshOutcome.UNAVAILABLE
        with self._lock:
            cur = self._current
        if cur is not None and raw == cur.raw:
            return RefreshOutcome.UNCHANGED
        try:
            bundle = self._verifier.verify(raw)
        except BundleError:
            return RefreshOutcome.REJECTED_INVALID
        if cur is not None:
            if bundle.bundle_version < cur.bundle.bundle_version:
                return RefreshOutcome.REJECTED_ROLLBACK
            if bundle.bundle_version == cur.bundle.bundle_version:
                return RefreshOutcome.REJECTED_EQUIVOCATION
        try:
            pdp = CedarPdp(bundle.policies, bundle.agents)
        except PolicyConfigError:
            return RefreshOutcome.REJECTED_INVALID
        with self._lock:
            if self._current is not None and (
                self._current.bundle.bundle_version >= bundle.bundle_version
            ):
                return RefreshOutcome.REJECTED_ROLLBACK  # a concurrent refresh won
            self._current = LoadedBundle(bundle, raw, pdp)
        return RefreshOutcome.ACCEPTED

    def current(self) -> LoadedBundle | None:
        with self._lock:
            cur = self._current
        if cur is None:
            return None
        now = self._now()
        if now >= cur.bundle.exp or now - cur.bundle.iat > self._max_age:
            return None  # fail closed: everything is denied until a fresh bundle arrives
        return cur
