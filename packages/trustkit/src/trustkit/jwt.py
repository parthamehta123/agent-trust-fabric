"""JWT validation with a fixed, fail-closed check order.

Order of checks (cheapest and most dangerous first; each failure is terminal):

1. size limit                  -> TOO_LARGE
2. compact-JWS structure       -> MALFORMED
3. header: forbidden params    -> FORBIDDEN_HEADER   (jku, x5u, jwk, x5c, crit)
4. header: alg in allowlist    -> ALG_NOT_ALLOWED    (never "none", never HS*)
5. header: typ (if required)   -> WRONG_TYP
6. header: kid present, known  -> UNKNOWN_KID        (one rate-limited JWKS refresh)
7. key type matches alg family -> ALG_NOT_ALLOWED
8. signature                   -> BAD_SIGNATURE
9. claims: required present    -> MISSING_CLAIM
10. claim types strict         -> MALFORMED          (NumericDate must be int; no bool/str coercion)
11. iss exact match            -> WRONG_ISSUER
12. aud intersects expected    -> WRONG_AUDIENCE
13. exp / nbf / iat with skew  -> EXPIRED / NOT_YET_VALID / IAT_IN_FUTURE

Threat-model refs: TM-ING-01, TM-ING-02, TM-ING-03, TM-ING-06.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import threading
import time
import warnings
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final, Protocol

from joserfc import jwt as jose_jwt
from joserfc.errors import BadSignatureError, JoseError
from joserfc.jwk import ECKey, RSAKey

PublicKey = RSAKey | ECKey

ALLOWED_ALGORITHMS: Final = frozenset({"RS256", "PS256", "ES256"})
"""The platform-wide ceiling. A policy may narrow it but never widen it."""

FORBIDDEN_HEADER_PARAMS: Final = frozenset({"jku", "x5u", "jwk", "x5c", "crit"})
"""Header params that let a token pick its own verification key, or demand extension handling."""

CORE_REQUIRED_CLAIMS: Final = frozenset({"iss", "sub", "aud", "exp", "iat"})
MAX_LEEWAY_SECONDS: Final = 120
MIN_RSA_BITS: Final = 2048

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_PRIVATE_JWK_MEMBERS: Final = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_ALG_KEY_TYPE: Final[Mapping[str, type[RSAKey] | type[ECKey]]] = MappingProxyType(
    {"RS256": RSAKey, "PS256": RSAKey, "ES256": ECKey}
)
_ALG_EC_CURVE: Final[Mapping[str, str]] = MappingProxyType({"ES256": "P-256"})


class Reason(StrEnum):
    TOO_LARGE = "too_large"
    MALFORMED = "malformed"
    FORBIDDEN_HEADER = "forbidden_header"
    ALG_NOT_ALLOWED = "alg_not_allowed"
    WRONG_TYP = "wrong_typ"
    UNKNOWN_KID = "unknown_kid"
    BAD_SIGNATURE = "bad_signature"
    MISSING_CLAIM = "missing_claim"
    WRONG_ISSUER = "wrong_issuer"
    WRONG_AUDIENCE = "wrong_audience"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    IAT_IN_FUTURE = "iat_in_future"


class TokenValidationError(Exception):
    """Raised for every rejection. ``str(err)`` is safe to log: it never contains token material.

    ``detail`` is always a fixed string chosen by this module (claim *names* at most).
    """

    def __init__(self, reason: Reason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)


@dataclass(frozen=True, kw_only=True)
class ValidationPolicy:
    issuer: str
    audiences: frozenset[str]
    algorithms: frozenset[str] = ALLOWED_ALGORITHMS
    required_claims: frozenset[str] = CORE_REQUIRED_CLAIMS
    expected_typ: str | None = None
    """e.g. ``"at+jwt"`` (RFC 9068) or ``"oauth-id-jag+jwt"``; compared case-insensitively."""
    leeway_seconds: int = 60
    max_token_bytes: int = 16_384

    def __post_init__(self) -> None:
        """Reject unsafe policies at construction time, not at first request."""
        if not self.issuer.startswith("https://") or self.issuer != self.issuer.strip():
            raise ValueError("issuer must be an https URL without surrounding whitespace")
        if not isinstance(self.audiences, frozenset) or not self.audiences:
            raise ValueError("audiences must be a non-empty frozenset")
        if not isinstance(self.algorithms, frozenset) or not self.algorithms:
            raise ValueError("at least one algorithm is required")
        if not self.algorithms <= ALLOWED_ALGORITHMS:
            raise ValueError("algorithm outside the platform allowlist")
        if not self.required_claims >= CORE_REQUIRED_CLAIMS:
            raise ValueError("required_claims must include iss, sub, aud, exp, iat")
        if not 0 <= self.leeway_seconds <= MAX_LEEWAY_SECONDS:
            raise ValueError(f"leeway must be within 0..{MAX_LEEWAY_SECONDS}s")
        if self.max_token_bytes <= 0:
            raise ValueError("max_token_bytes must be positive")


class KeyResolver(Protocol):
    def resolve(self, kid: str) -> PublicKey | None:
        """Return the key for ``kid``, or ``None`` if unknown even after any permitted refresh."""
        ...


# ----------------------------------------------------------------------------- JWKS


def _import_public_jwk(jwk: Any) -> tuple[str, PublicKey] | None:
    """Import one JWKS entry as a signature-verification key, or ``None`` if unacceptable."""
    if not isinstance(jwk, dict):
        return None
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid:
        return None
    if _PRIVATE_JWK_MEMBERS & jwk.keys():
        return (
            None  # a JWKS publishing private/symmetric material is misconfigured: trust none of it
        )
    if jwk.get("use", "sig") != "sig":
        return None
    try:
        if jwk.get("kty") == "RSA":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # joserfc warns on weak keys; we reject them below
                rsa = RSAKey.import_key(jwk)
            if rsa.raw_value.key_size < MIN_RSA_BITS:
                return None
            return kid, rsa
        if jwk.get("kty") == "EC" and jwk.get("crv") in _ALG_EC_CURVE.values():
            return kid, ECKey.import_key(jwk)
    except (JoseError, ValueError, TypeError, KeyError):
        return None
    return None


def _parse_jwks(doc: Any) -> dict[str, PublicKey]:
    entries = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return {}
    imported = [k for k in map(_import_public_jwk, entries) if k is not None]
    counts = Counter(kid for kid, _ in imported)
    return {kid: key for kid, key in imported if counts[kid] == 1}  # duplicate kids: trust neither


@dataclass
class JwksKeyResolver:
    """Resolves keys from a JWKS document fetched by ``fetch``.

    ``fetch`` is injected (HTTP lives in an adapter) and must only ever be pointed at the
    issuer's configured ``jwks_uri``.

    Refresh rules (TM-ING-03):

    * Proactive: keys older than ``max_key_age_s`` trigger a refresh even when the kid is known,
      so a key the IdP has retired stops being trusted.
    * Unknown kid: at most one refresh per ``min_refresh_interval_s``, so an attacker spraying
      random kids can't turn us into a JWKS-fetch amplifier.
    * Failure: the last good key set is kept for availability, but never beyond
      ``max_staleness_s`` since the last *successful* fetch. After that, nothing resolves.
    """

    fetch: Callable[[], Mapping[str, Any]]
    min_refresh_interval_s: float = 60
    max_key_age_s: float = 3_600
    max_staleness_s: float = 86_400
    now: Callable[[], float] = time.monotonic
    _keys: dict[str, PublicKey] = field(default_factory=dict, init=False, repr=False)
    _last_attempt: float | None = field(default=None, init=False, repr=False)
    _last_success: float | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def resolve(self, kid: str) -> PublicKey | None:
        with self._lock:
            t = self.now()
            if self._last_success is None or t - self._last_success >= self.max_key_age_s:
                self._refresh_if_allowed(t)
            if kid not in self._keys:
                self._refresh_if_allowed(t)
            if self._last_success is None or t - self._last_success > self.max_staleness_s:
                self._keys = {}
            return self._keys.get(kid)

    def _refresh_if_allowed(self, t: float) -> None:
        if self._last_attempt is not None and t - self._last_attempt < self.min_refresh_interval_s:
            return
        self._last_attempt = t
        try:
            doc = self.fetch()
        except Exception:  # noqa: BLE001 - adapter failure of any kind == failed refresh; keep last good set
            return
        self._keys = _parse_jwks(doc)
        self._last_success = t


# ----------------------------------------------------------------------------- validation


@dataclass(frozen=True)
class VerifiedToken:
    header: Mapping[str, Any]
    claims: Mapping[str, Any]

    @property
    def subject(self) -> str:
        return str(self.claims["sub"])

    @property
    def issuer(self) -> str:
        return str(self.claims["iss"])

    @property
    def jti(self) -> str | None:
        v = self.claims.get("jti")
        return None if v is None else str(v)


def _b64url_json(segment: str) -> Any:
    if not segment or not _B64URL.fullmatch(segment):
        raise TokenValidationError(Reason.MALFORMED, "segment encoding")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        return json.loads(raw)
    except (binascii.Error, ValueError, RecursionError):
        raise TokenValidationError(Reason.MALFORMED, "segment encoding") from None


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


class TokenValidator:
    def __init__(
        self,
        policy: ValidationPolicy,
        keys: KeyResolver,
        *,
        now: Callable[[], int] | None = None,
    ) -> None:
        self._policy = policy
        self._keys = keys
        self._now = now or (lambda: int(time.time()))

    @property
    def policy(self) -> ValidationPolicy:
        return self._policy

    def validate(self, token: str) -> VerifiedToken:
        p = self._policy
        if len(token.encode("utf-8", errors="replace")) > p.max_token_bytes:
            raise TokenValidationError(Reason.TOO_LARGE)

        parts = token.split(".")
        if len(parts) != 3 or not _B64URL.fullmatch(parts[1]) or not _B64URL.fullmatch(parts[2]):
            raise TokenValidationError(Reason.MALFORMED, "not a compact JWS")
        header = _b64url_json(parts[0])
        if not isinstance(header, dict):
            raise TokenValidationError(Reason.MALFORMED, "header is not an object")

        if FORBIDDEN_HEADER_PARAMS & header.keys():
            raise TokenValidationError(Reason.FORBIDDEN_HEADER)

        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in p.algorithms:
            raise TokenValidationError(Reason.ALG_NOT_ALLOWED)

        if p.expected_typ is not None:
            typ = header.get("typ")
            if not isinstance(typ, str) or typ.lower() != p.expected_typ.lower():
                raise TokenValidationError(Reason.WRONG_TYP)

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenValidationError(Reason.UNKNOWN_KID, "kid missing")
        key = self._keys.resolve(kid)
        if key is None:
            raise TokenValidationError(Reason.UNKNOWN_KID)

        if not isinstance(key, _ALG_KEY_TYPE[alg]) or (
            alg in _ALG_EC_CURVE and key.as_dict().get("crv") != _ALG_EC_CURVE[alg]
        ):
            raise TokenValidationError(Reason.ALG_NOT_ALLOWED, "key type does not match alg")

        try:
            verified = jose_jwt.decode(token, key, algorithms=[alg])
        except BadSignatureError:
            raise TokenValidationError(Reason.BAD_SIGNATURE) from None
        except (JoseError, ValueError, TypeError):
            raise TokenValidationError(Reason.MALFORMED, "jws decode") from None

        claims = verified.claims
        if not isinstance(claims, dict):
            raise TokenValidationError(Reason.MALFORMED, "claims is not an object")
        self._check_claims(claims)
        return VerifiedToken(
            header=MappingProxyType(dict(header)), claims=MappingProxyType(dict(claims))
        )

    def _check_claims(self, c: dict[str, Any]) -> None:
        p = self._policy
        for name in sorted(p.required_claims):
            if name not in c:
                raise TokenValidationError(Reason.MISSING_CLAIM, name)

        for name in ("exp", "iat", "nbf"):
            if name in c and not _is_int(c[name]):
                raise TokenValidationError(Reason.MALFORMED, f"{name} must be an integer")
        for name in ("iss", "sub", "jti"):
            if name in c and not isinstance(c[name], str):
                raise TokenValidationError(Reason.MALFORMED, f"{name} must be a string")

        if c["iss"] != p.issuer:
            raise TokenValidationError(Reason.WRONG_ISSUER)

        aud = c["aud"]
        if isinstance(aud, str):
            auds = {aud}
        elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
            auds = set(aud)
        else:
            raise TokenValidationError(Reason.MALFORMED, "aud must be a string or string list")
        if not auds & p.audiences:
            raise TokenValidationError(Reason.WRONG_AUDIENCE)

        now, skew = self._now(), p.leeway_seconds
        if now > c["exp"] + skew:
            raise TokenValidationError(Reason.EXPIRED)
        if "nbf" in c and now + skew < c["nbf"]:
            raise TokenValidationError(Reason.NOT_YET_VALID)
        if c["iat"] > now + skew:
            raise TokenValidationError(Reason.IAT_IN_FUTURE)
