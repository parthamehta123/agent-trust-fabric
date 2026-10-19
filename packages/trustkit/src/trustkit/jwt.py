"""JWT validation with a fixed, fail-closed check order.

Order of checks (cheapest and most dangerous first; each failure is terminal):

1. size limit                  -> TOO_LARGE
2. compact-JWS structure       -> MALFORMED
3. header: forbidden params    -> FORBIDDEN_HEADER   (jku, x5u, jwk, x5c, crit)
4. header: alg in allowlist    -> ALG_NOT_ALLOWED    (never "none", never HS*)
5. header: typ (if required)   -> WRONG_TYP
6. header: kid present, known  -> UNKNOWN_KID        (one rate-limited JWKS refresh)
7. key type matches alg family -> ALG_NOT_ALLOWED
8. signature                   -> BAD_SIGNATURE      (rotated under same kid: one shared-budget
                                                      refresh + one re-verify, ADR-0027)
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
from typing import Any, Final, Protocol, runtime_checkable

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


class AccessTokenProfile(StrEnum):
    """How an IdP shapes its access tokens (ADR-0027 token-exchange review, finding #1; A-15).

    * ``rfc9068``: ``typ: at+jwt``, ``scope`` (space-separated string), ``client_id``.
    * ``okta``: Okta custom authorization servers: no ``typ`` header, ``scp`` (array), ``cid``,
      and for user tokens ``sub`` = the login with the stable user id in ``uid``. Normalised on
      validation to ``scope``/``client_id``/``sub = uid``, so every consumer sees one shape.
    """

    RFC9068 = "rfc9068"
    OKTA = "okta"


ACCESS_TOKEN_PROFILE_ENV: Final = "ATF_ACCESS_TOKEN_PROFILE"  # noqa: S105 - env var name


def access_token_profile_from_env(env: Mapping[str, str]) -> AccessTokenProfile:
    """``ATF_ACCESS_TOKEN_PROFILE`` (default ``rfc9068``). Anything else raises: a typo must be a
    cold-start failure, not a silent fallback."""
    return AccessTokenProfile(env.get(ACCESS_TOKEN_PROFILE_ENV, AccessTokenProfile.RFC9068.value))


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
    access_token_profile: AccessTokenProfile = AccessTokenProfile.RFC9068
    """``okta``: also accept an access token *without* ``typ`` where ``at+jwt`` is expected (any
    other ``typ`` is still refused), and normalise Okta's claims. See ``AccessTokenProfile``."""

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


@runtime_checkable
class RotationAwareKeyResolver(KeyResolver, Protocol):
    def resolve_rotated(self, kid: str, rejected: PublicKey) -> PublicKey | None:
        """After ``rejected`` failed to verify a signature: refresh within the shared budget and
        return a *different* key for ``kid`` if the IdP has rotated it, else ``None``."""
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
        # Private or symmetric material published: that key is compromised, so it is never
        # trusted. Only this entry is dropped: refusing the whole document would keep the
        # previous set, which still contains the key (ADR-0027 review #5).
        return None
    if jwk.get("use", "sig") != "sig":
        return None
    ops = jwk.get("key_ops")
    if ops is not None and (not isinstance(ops, list) or "verify" not in ops):
        return None  # RFC 7517 §4.3: a key not meant for verification isn't used for it (#6)
    if "alg" in jwk and jwk["alg"] not in ALLOWED_ALGORITHMS:
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


def _parse_jwks(doc: Any) -> dict[str, PublicKey] | None:
    """``None`` when ``doc`` isn't a JWK Set at all (RFC 7517 §5: ``keys`` is required): that is a
    failed fetch, not an IdP that revoked everything (ADR-0027 review #3)."""
    entries = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(entries, list):
        return None
    imported = [k for k in map(_import_public_jwk, entries) if k is not None]
    counts = Counter(kid for kid, _ in imported)
    return {kid: key for kid, key in imported if counts[kid] == 1}  # duplicate kids: trust neither


@dataclass
class JwksKeyResolver:
    """Resolves keys from a JWKS document fetched by ``fetch``.

    ``fetch`` is injected (HTTP lives in an adapter) and must only ever be pointed at the
    issuer's configured ``jwks_uri``.

    Refresh rules (TM-ING-03, ADR-0027):

    * Proactive: keys older than ``max_key_age_s`` (5 min) trigger a refresh even when the kid is
      known, so a key the IdP has revoked stops being trusted within that window.
    * Unknown kid, or a known kid whose key failed a signature (rotation under the same kid): at
      most one refresh per ``min_refresh_interval_s``, a single shared budget, so an attacker
      spraying random kids or forged signatures can't turn us into a JWKS-fetch amplifier.
    * Failure: the last good key set is kept for availability, but never beyond
      ``max_staleness_s`` since the last *successful* fetch. After that, nothing resolves. A
      response that isn't a JWK Set (no ``keys`` array) is a failure, not an empty set.

    Concurrency (ADR-0027 review #2): the fetch never runs under the lock, and at most one is in
    flight. Callers whose kid is already known keep using the current set meanwhile; callers that
    need the result (unknown kid, a rotated key, nothing loaded yet) wait for that one fetch.
    """

    fetch: Callable[[], Mapping[str, Any]]
    min_refresh_interval_s: float = 60
    max_key_age_s: float = 300
    max_staleness_s: float = 86_400
    max_wait_s: float = 10
    """Upper bound on waiting for another caller's fetch (the adapter has its own timeouts)."""
    now: Callable[[], float] = time.monotonic
    _keys: dict[str, PublicKey] = field(default_factory=dict, init=False, repr=False)
    _last_attempt: float | None = field(default=None, init=False, repr=False)
    _last_success: float | None = field(default=None, init=False, repr=False)
    _in_flight: threading.Event | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def resolve(self, kid: str) -> PublicKey | None:
        with self._lock:
            t = self.now()
            due = self._last_success is None or t - self._last_success >= self.max_key_age_s
            usable = kid in self._keys and self._fresh(t)
        if due or not usable:
            self._refresh(wait=not usable)
        return self._current(kid)

    def resolve_rotated(self, kid: str, rejected: PublicKey) -> PublicKey | None:
        self._refresh(wait=True)
        fresh = self._current(kid)
        if fresh is None or fresh.as_dict(private=False) == rejected.as_dict(private=False):
            return None
        return fresh

    def _fresh(self, t: float) -> bool:
        return self._last_success is not None and t - self._last_success <= self.max_staleness_s

    def _current(self, kid: str) -> PublicKey | None:
        with self._lock:
            if not self._fresh(self.now()):
                self._keys = {}
            return self._keys.get(kid)

    def _refresh(self, *, wait: bool) -> None:
        """Start a refresh if the shared budget allows and none is in flight; otherwise, when
        ``wait``, join the one in flight. Never fetches while holding the lock."""
        with self._lock:
            t = self.now()
            flight, owner = self._in_flight, False
            allowed = (
                self._last_attempt is None or t - self._last_attempt >= self.min_refresh_interval_s
            )
            if flight is None and allowed:
                flight = self._in_flight = threading.Event()
                self._last_attempt, owner = t, True
        if flight is None:
            return
        if not owner:
            if wait:
                flight.wait(self.max_wait_s)
            return
        keys: dict[str, PublicKey] | None = None
        try:
            keys = _parse_jwks(self.fetch())
        except Exception:  # noqa: BLE001, S110 - adapter failure of any kind == failed refresh
            pass
        finally:
            with self._lock:
                if keys is not None:
                    self._keys, self._last_success = keys, t
                self._in_flight = None
            flight.set()


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


def _media_type(typ: str) -> str:
    """RFC 7515 §4.1.9: ``typ`` is a media type whose ``application/`` prefix may be omitted, so
    ``at+jwt`` and ``application/at+jwt`` are the same (RFC 9068 §4; ADR-0027 review #4)."""
    t = typ.strip().lower()
    return t if "/" in t else f"application/{t}"


_AT_JWT: Final = "application/at+jwt"


def _normalise_okta(c: dict[str, Any]) -> dict[str, Any]:
    """Okta claim names -> the ones every consumer reads. An Okta and a standard claim that are
    both present must agree, or the token is ambiguous (``MALFORMED``)."""
    out = dict(c)
    pairs: list[tuple[str, str, Any]] = []
    if "scp" in c:
        scp = c["scp"]
        if not isinstance(scp, list) or not all(isinstance(x, str) and x for x in scp):
            raise TokenValidationError(Reason.MALFORMED, "scp must be a list of strings")
        pairs.append(("scp", "scope", " ".join(scp)))
    if "cid" in c:
        if not isinstance(c["cid"], str) or not c["cid"]:
            raise TokenValidationError(Reason.MALFORMED, "cid must be a string")
        pairs.append(("cid", "client_id", c["cid"]))
    if "uid" in c:  # a user's token: sub is their login, uid the stable id the ID token uses
        if not isinstance(c["uid"], str) or not c["uid"]:
            raise TokenValidationError(Reason.MALFORMED, "uid must be a string")
        out["sub"] = c["uid"]
    for okta_name, std_name, value in pairs:
        if std_name in c and (
            set(str(c[std_name]).split()) != set(value.split())
            if std_name == "scope"
            else c[std_name] != value
        ):
            raise TokenValidationError(Reason.MALFORMED, f"{okta_name} and {std_name} disagree")
        out[std_name] = value
    return out


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
            typless_okta = (
                typ is None
                and p.access_token_profile is AccessTokenProfile.OKTA
                and _media_type(p.expected_typ) == _AT_JWT
            )
            if not typless_okta and (
                not isinstance(typ, str) or _media_type(typ) != _media_type(p.expected_typ)
            ):
                raise TokenValidationError(Reason.WRONG_TYP)

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenValidationError(Reason.UNKNOWN_KID, "kid missing")
        key = self._keys.resolve(kid)
        if key is None:
            raise TokenValidationError(Reason.UNKNOWN_KID)

        try:
            verified = self._verify(token, key, alg)
        except BadSignatureError:
            # ADR-0027: the IdP may have rotated key material under the same kid. One refresh
            # (shared rate limit) and exactly one re-verify against a *different* key; never more.
            fresh = (
                self._keys.resolve_rotated(kid, key)
                if isinstance(self._keys, RotationAwareKeyResolver)
                else None
            )
            if fresh is None:
                raise TokenValidationError(Reason.BAD_SIGNATURE) from None
            try:
                verified = self._verify(token, fresh, alg)
            except BadSignatureError:
                raise TokenValidationError(Reason.BAD_SIGNATURE) from None

        claims = verified.claims
        if not isinstance(claims, dict):
            raise TokenValidationError(Reason.MALFORMED, "claims is not an object")
        if p.access_token_profile is AccessTokenProfile.OKTA:
            claims = _normalise_okta(claims)
        self._check_claims(claims)
        return VerifiedToken(
            header=MappingProxyType(dict(header)), claims=MappingProxyType(dict(claims))
        )

    @staticmethod
    def _verify(token: str, key: PublicKey, alg: str) -> Any:
        """Key/alg family check, then signature. ``BadSignatureError`` propagates."""
        if not isinstance(key, _ALG_KEY_TYPE[alg]) or (
            alg in _ALG_EC_CURVE and key.as_dict().get("crv") != _ALG_EC_CURVE[alg]
        ):
            raise TokenValidationError(Reason.ALG_NOT_ALLOWED, "key type does not match alg")
        if key.as_dict(private=False).get("alg", alg) != alg:
            # RFC 8725 §3.1: a key published for one algorithm is used with that one only. Enforced
            # here, not left to the JOSE library (ADR-0027 review #6).
            raise TokenValidationError(Reason.ALG_NOT_ALLOWED, "key is published for another alg")
        try:
            return jose_jwt.decode(token, key, algorithms=[alg])
        except BadSignatureError:
            raise
        except (JoseError, ValueError, TypeError):
            raise TokenValidationError(Reason.MALFORMED, "jws decode") from None

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
