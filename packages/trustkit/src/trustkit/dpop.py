"""DPoP (RFC 9449) proofs: sender-constrained workload tokens (ADR-0028 Phase 1).

Agents hold an **ephemeral P-256 key in process memory** (never KMS: one sign per request), bind
their workload token to it at the IdP (``cnf.jkt``), and send a fresh proof with every egress
call. Gateways verify the proof before anything else uses the token.

Proof checks, cheapest and most dangerous first, each terminal:

1. compact JWS, size limit                        -> MALFORMED
2. header: ``typ = dpop+jwt``, ``alg = ES256``,
   ``jwk`` a public P-256 key, nothing else odd   -> BAD_HEADER
3. signature with that ``jwk``                    -> BAD_SIGNATURE
4. ``htm`` / ``htu`` equal the request            -> WRONG_TARGET
5. ``ath`` = SHA-256(access token)                -> WRONG_TOKEN
6. ``iat`` within the window                      -> STALE
7. ``jti`` unseen in this instance                -> REPLAY
8. ``jwk`` thumbprint == token ``cnf.jkt``        -> KEY_MISMATCH
9. ``nonce`` issued by this plane, current epoch  -> USE_NONCE  (client retries with the new one)

Replay across instances is bounded by a **stateless nonce**:
``epoch || HMAC-SHA256(K, epoch || client_id)``, with 5-min epochs and the previous epoch still
accepted. No shared state: any instance with the plane's key validates any instance's nonce.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ec
from joserfc.jwk import thumbprint

from trustkit.signing import SigningError, der_to_jose_es256, es256_public_jwk, verify_es256

__all__ = [
    "DpopError",
    "DpopGuard",
    "DpopKey",
    "DpopMode",
    "DpopReason",
    "DpopVerifier",
    "NonceIssuer",
    "ReplayCache",
    "access_token_hash",
    "canonical_htu",
    "dpop_guard_from_env",
    "dpop_post",
]

MAX_PROOF_BYTES: Final = 4096
IAT_WINDOW_S: Final = 60
NONCE_EPOCH_S: Final = 300
_B64URL: Final = re.compile(r"^[A-Za-z0-9_-]+$")
_ALLOWED_HEADER: Final = frozenset({"typ", "alg", "jwk"})
_PUBLIC_JWK_MEMBERS: Final = frozenset({"kty", "crv", "x", "y"})


class DpopReason(StrEnum):
    MALFORMED = "dpop_malformed"
    BAD_HEADER = "dpop_bad_header"
    BAD_SIGNATURE = "dpop_bad_signature"
    WRONG_TARGET = "dpop_wrong_target"
    WRONG_TOKEN = "dpop_wrong_token"  # noqa: S105 - a reason code, not a secret
    STALE = "dpop_stale"
    REPLAY = "dpop_replay"
    KEY_MISMATCH = "dpop_key_mismatch"
    USE_NONCE = "use_dpop_nonce"
    MISSING = "dpop_missing"
    REQUIRED = "dpop_required"
    CACHE_FULL = "dpop_replay_cache_full"


class DpopError(Exception):
    """Log-safe: names the rule, never proof or token material. ``nonce`` is set for USE_NONCE."""

    def __init__(self, reason: DpopReason, *, nonce: str | None = None) -> None:
        super().__init__(reason.value)
        self.reason, self.nonce = reason, nonce


class DpopMode(StrEnum):
    OPTIONAL = "optional"
    """Unbound (bearer) workload tokens are still accepted (rollout); bound ones need a proof."""
    REQUIRED = "required"
    """Every workload token must be bound and proven."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(segment: str) -> bytes:
    if not _B64URL.fullmatch(segment):
        raise DpopError(DpopReason.MALFORMED)
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def access_token_hash(token: str) -> str:
    """RFC 9449 ``ath``: base64url(SHA-256(ASCII access token))."""
    return _b64(hashlib.sha256(token.encode("ascii")).digest())


def canonical_htu(url: str) -> str:
    """Scheme and host lowercased, default port dropped, no query or fragment (RFC 9449 §4.3)."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise DpopError(DpopReason.WRONG_TARGET)
    host = parts.hostname.lower()
    port = parts.port
    netloc = host if port in (None, 443) else f"{host}:{port}"
    return f"https://{netloc}{parts.path or '/'}"


# ----------------------------------------------------------------------------- agent side


class DpopKey:
    """Ephemeral P-256 key, generated in memory (ADR-0028). Never persisted, rotated on restart."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._key = private_key or ec.generate_private_key(ec.SECP256R1())
        self.public_jwk: Final = es256_public_jwk(self._key.public_key())
        self.jkt: Final = thumbprint(dict(self.public_jwk))

    def proof(
        self,
        method: str,
        url: str,
        *,
        access_token: str | None = None,
        nonce: str | None = None,
        now: Callable[[], int] = lambda: int(time.time()),
    ) -> str:
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": dict(self.public_jwk)}
        claims: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": canonical_htu(url),
            "iat": now(),
        }
        if access_token is not None:
            claims["ath"] = access_token_hash(access_token)
        if nonce is not None:
            claims["nonce"] = nonce
        signing_input = (
            f"{_b64(json.dumps(header, separators=(',', ':')).encode())}."
            f"{_b64(json.dumps(claims, separators=(',', ':')).encode())}"
        ).encode("ascii")
        from cryptography.hazmat.primitives import hashes

        der = self._key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        signature = der_to_jose_es256(der)
        verify_es256(self._key.public_key(), signing_input, signature)
        return f"{signing_input.decode('ascii')}.{_b64(signature)}"


# ----------------------------------------------------------------------------- server side


class NonceIssuer:
    """Stateless nonces: ``epoch || HMAC(K, epoch || client_id)``. Current and previous epoch
    are valid, so a nonce lives 5-10 min and every instance sharing ``K`` agrees."""

    def __init__(
        self,
        key: bytes,
        *,
        epoch_s: int = NONCE_EPOCH_S,
        now: Callable[[], float] = time.time,
    ) -> None:
        if len(key) < 32:
            raise ValueError("nonce key must be at least 32 bytes")
        self._key, self._epoch_s, self._now = key, epoch_s, now

    def _mac(self, epoch: int, client_id: str) -> str:
        msg = f"{epoch}|{client_id}".encode()
        return _b64(hmac.new(self._key, msg, hashlib.sha256).digest())

    def issue(self, client_id: str) -> str:
        epoch = int(self._now()) // self._epoch_s
        return f"{epoch}.{self._mac(epoch, client_id)}"

    def valid(self, nonce: str, client_id: str) -> bool:
        epoch_s, _, mac = nonce.partition(".")
        if not epoch_s.isdigit() or not mac:
            return False
        epoch, current = int(epoch_s), int(self._now()) // self._epoch_s
        if epoch not in (current, current - 1):
            return False
        return hmac.compare_digest(mac, self._mac(epoch, client_id))


class ReplayCache:
    """Per-instance ``jti`` cache. Bounded: when full of unexpired entries it refuses new proofs
    (fail closed) rather than evicting, which would reopen replay."""

    def __init__(
        self,
        *,
        ttl_s: float = 2 * IAT_WINDOW_S,
        max_entries: int = 200_000,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl, self._max, self._now = ttl_s, max_entries, now
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, jti: str) -> None:
        """Record ``jti``; raises REPLAY if seen within the TTL, CACHE_FULL if saturated."""
        with self._lock:
            t = self._now()
            if len(self._seen) >= self._max:
                self._seen = {k: exp for k, exp in self._seen.items() if exp > t}
                if len(self._seen) >= self._max:
                    raise DpopError(DpopReason.CACHE_FULL)
            exp = self._seen.get(jti)
            if exp is not None and exp > t:
                raise DpopError(DpopReason.REPLAY)
            self._seen[jti] = t + self._ttl


@dataclass(frozen=True)
class VerifiedProof:
    jkt: str
    jti: str


class DpopVerifier:
    def __init__(
        self,
        *,
        nonces: NonceIssuer,
        replay: ReplayCache | None = None,
        now: Callable[[], int] = lambda: int(time.time()),
        iat_window_s: int = IAT_WINDOW_S,
    ) -> None:
        self._nonces, self._replay = nonces, replay or ReplayCache()
        self._now, self._window = now, iat_window_s

    def verify(
        self,
        proof: str,
        *,
        method: str,
        url: str,
        access_token: str,
        expected_jkt: str,
        client_id: str,
    ) -> VerifiedProof:
        """Raise ``DpopError`` unless ``proof`` proves possession of ``expected_jkt`` for exactly
        this request and token. A USE_NONCE error carries a fresh nonce for the client."""
        if len(proof) > MAX_PROOF_BYTES:
            raise DpopError(DpopReason.MALFORMED)
        parts = proof.split(".")
        if len(parts) != 3:
            raise DpopError(DpopReason.MALFORMED)
        try:
            header = json.loads(_unb64(parts[0]))
            claims = json.loads(_unb64(parts[1]))
            signature = _unb64(parts[2])
        except (ValueError, RecursionError):
            raise DpopError(DpopReason.MALFORMED) from None
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise DpopError(DpopReason.MALFORMED)

        jwk = header.get("jwk")
        if (
            set(header) != _ALLOWED_HEADER
            or header.get("typ") != "dpop+jwt"
            or header.get("alg") != "ES256"
            or not isinstance(jwk, dict)
            or set(jwk) != _PUBLIC_JWK_MEMBERS
            or jwk.get("kty") != "EC"
            or jwk.get("crv") != "P-256"
        ):
            raise DpopError(DpopReason.BAD_HEADER)
        try:
            x = int.from_bytes(_unb64(str(jwk["x"])), "big")
            y = int.from_bytes(_unb64(str(jwk["y"])), "big")
            public = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        except (DpopError, ValueError):
            raise DpopError(DpopReason.BAD_HEADER) from None
        try:
            verify_es256(public, f"{parts[0]}.{parts[1]}".encode("ascii"), signature)
        except SigningError:
            raise DpopError(DpopReason.BAD_SIGNATURE) from None

        if claims.get("htm") != method.upper() or claims.get("htu") != canonical_htu(url):
            raise DpopError(DpopReason.WRONG_TARGET)
        ath = claims.get("ath")
        if not isinstance(ath, str) or not hmac.compare_digest(
            ath, access_token_hash(access_token)
        ):
            raise DpopError(DpopReason.WRONG_TOKEN)
        iat, jti = claims.get("iat"), claims.get("jti")
        if (
            not isinstance(iat, int)
            or isinstance(iat, bool)
            or abs(self._now() - iat) > self._window
        ):
            raise DpopError(DpopReason.STALE)
        if not isinstance(jti, str) or not 8 <= len(jti) <= 128:
            raise DpopError(DpopReason.MALFORMED)

        jkt = thumbprint({k: str(jwk[k]) for k in ("kty", "crv", "x", "y")})
        if not hmac.compare_digest(jkt, expected_jkt):
            raise DpopError(DpopReason.KEY_MISMATCH)
        nonce = claims.get("nonce")
        if not isinstance(nonce, str) or not self._nonces.valid(nonce, client_id):
            raise DpopError(DpopReason.USE_NONCE, nonce=self._nonces.issue(client_id))
        # Recorded last: a proof refused for any reason above can be corrected and resent.
        self._replay.add(jti)
        return VerifiedProof(jkt=jkt, jti=jti)


def random_nonce_key() -> bytes:
    """For tests and the local stack only; real deployments load the plane's key from Secrets
    Manager (ADR-0028)."""
    return secrets.token_bytes(32)


def bound_jkt(claims: Mapping[str, Any]) -> str | None:
    """The token's ``cnf.jkt``, or None if unbound. Malformed ``cnf`` is treated as bound to
    nothing (and so can never be proven), never as unbound."""
    cnf = claims.get("cnf")
    if cnf is None:
        return None
    if isinstance(cnf, dict) and isinstance(cnf.get("jkt"), str) and cnf["jkt"]:
        return str(cnf["jkt"])
    return "\x00invalid"


# ----------------------------------------------------------------------------- gateway guard


@dataclass(frozen=True)
class WorkloadAuth:
    token: str
    """The workload access token, for the binder (which validates it again, as before)."""
    bound: bool
    """True when the token is DPoP-bound and a proof was verified."""


def authenticate_workload(
    headers: Mapping[str, str],
    *,
    method: str,
    url: str,
    validate: Callable[[str], Any],
    verifier: DpopVerifier,
    mode: DpopMode,
) -> WorkloadAuth:
    """Gateway entry check (ADR-0028), before the binder.

    * ``Authorization: DPoP <token>`` + ``DPoP: <proof>``: the token must be bound (``cnf.jkt``)
      and the proof must verify for this request.
    * ``Authorization: Bearer <token>``: only an *unbound* token, and only in OPTIONAL mode.
      A bound token presented as Bearer is refused: stripping the proof never downgrades it.

    ``validate`` is the gateway's workload ``TokenValidator.validate``; it raises on an invalid
    token. Raises ``DpopError`` for DPoP failures, ``ValueError`` for missing credentials.
    """
    auth = headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if not token or scheme not in ("Bearer", "DPoP"):
        raise ValueError("missing credentials")
    verified = validate(token)
    claims = verified.claims
    jkt = bound_jkt(claims)
    if scheme == "Bearer":
        if jkt is not None:
            raise DpopError(DpopReason.MISSING)
        if mode is DpopMode.REQUIRED:
            raise DpopError(DpopReason.REQUIRED)
        return WorkloadAuth(token=token, bound=False)
    if jkt is None:
        raise DpopError(DpopReason.REQUIRED)  # "DPoP" scheme with an unbound token
    proof = headers.get("dpop")
    if not proof:
        raise DpopError(DpopReason.MISSING)
    verifier.verify(
        proof,
        method=method,
        url=url,
        access_token=token,
        expected_jkt=jkt,
        client_id=str(claims.get("client_id") or claims.get("sub")),
    )
    return WorkloadAuth(token=token, bound=True)


def challenge_headers(err: DpopError) -> dict[str, str]:
    """RFC 9449 §7.1 response headers for a refused request."""
    error = "use_dpop_nonce" if err.reason is DpopReason.USE_NONCE else "invalid_dpop_proof"
    out = {"WWW-Authenticate": f'DPoP error="{error}", algs="ES256"'}
    if err.nonce:
        out["DPoP-Nonce"] = err.nonce
    return out


class DpopGuard:
    """One per gateway (ADR-0028): verifies the request, then hands the binder the same headers
    it always had (``Authorization: Bearer <workload>``, no ``DPoP``), so binders don't change.

    ``public_url`` is the base URL agents call (behind a load balancer the request's own URL
    differs); ``htu`` is checked against ``public_url + path``."""

    def __init__(
        self,
        *,
        public_url: str,
        mode: DpopMode,
        verifier: DpopVerifier,
        validate: Callable[[str], Any],
        on_unbound: Callable[[str], None] = lambda client_id: None,
    ) -> None:
        canonical_htu(public_url)  # fail at cold start, not per request
        self._base = public_url.rstrip("/")
        self._mode, self._verifier, self._validate = mode, verifier, validate
        self._on_unbound = on_unbound

    def check(self, headers: Mapping[str, str], method: str, path: str) -> dict[str, str]:
        auth = authenticate_workload(
            headers,
            method=method,
            url=f"{self._base}{path}",
            validate=self._validate,
            verifier=self._verifier,
            mode=self._mode,
        )
        if not auth.bound:
            claims = self._validate(auth.token).claims
            self._on_unbound(str(claims.get("client_id") or claims.get("sub")))
        out = {k: v for k, v in headers.items() if k not in ("authorization", "dpop")}
        out["authorization"] = f"Bearer {auth.token}"
        return out


def dpop_guard_from_env(
    env: Mapping[str, str],
    *,
    validate: Callable[[str], Any],
    fetch_secret: Callable[[str], bytes] | None = None,
    on_unbound: Callable[[str], None] = lambda client_id: None,
) -> DpopGuard | None:
    """``ATF_DPOP_MODE``: ``off`` (default, no guard), ``optional`` or ``required``.
    ``ATF_PUBLIC_URL``: the base URL agents call. Nonce key: ``ATF_DPOP_NONCE_KEY_PATH`` (a file
    of >= 32 raw bytes, local) or ``ATF_DPOP_NONCE_KEY_SECRET_ARN`` (Secrets Manager, AWS);
    exactly one. Anything invalid raises: a misconfigured guard is a cold-start failure."""
    import pathlib

    raw_mode = env.get("ATF_DPOP_MODE", "off")
    if raw_mode == "off":
        return None
    mode = DpopMode(raw_mode)
    path, arn = env.get("ATF_DPOP_NONCE_KEY_PATH"), env.get("ATF_DPOP_NONCE_KEY_SECRET_ARN")
    if bool(path) == bool(arn):
        raise ValueError("set ATF_DPOP_NONCE_KEY_PATH or ATF_DPOP_NONCE_KEY_SECRET_ARN, not both")
    if path:
        key = pathlib.Path(path).read_bytes()
    else:
        if fetch_secret is None:
            raise ValueError("a secret ARN needs a secret fetcher")
        key = fetch_secret(str(arn))
    return DpopGuard(
        public_url=env["ATF_PUBLIC_URL"],
        mode=mode,
        verifier=DpopVerifier(nonces=NonceIssuer(key)),
        validate=validate,
        on_unbound=on_unbound,
    )


def guard_error_status(err: DpopError) -> int:
    """503 when the replay cache is saturated (fail closed, retry later); 401 otherwise."""
    return 503 if err.reason is DpopReason.CACHE_FULL else 401


# ----------------------------------------------------------------------------- agent sender

RawPost = Callable[
    [str, Mapping[str, Any], Mapping[str, str]], "tuple[int, Any, Mapping[str, str]]"
]
"""``(url, json_payload, headers) -> (status, json_body_or_None, lowercased response headers)``."""


def dpop_post(
    key: DpopKey,
    raw_post: RawPost,
    *,
    now: Callable[[], int] = lambda: int(time.time()),
) -> Callable[[str, Mapping[str, Any], Mapping[str, str]], tuple[int, Any]]:
    """Wrap an agent's HTTP POST so every egress call proves possession (ADR-0028).

    Callers keep sending ``Authorization: Bearer <workload>``; the wrapper rewrites it to
    ``DPoP <workload>`` with a fresh proof bound to this method, URL and token, remembers each
    origin's ``DPoP-Nonce``, and retries **once** when challenged with ``use_dpop_nonce``."""
    nonces: dict[str, str] = {}
    lock = threading.Lock()

    def post(url: str, payload: Mapping[str, Any], headers: Mapping[str, str]) -> tuple[int, Any]:
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        if not auth.startswith("Bearer "):
            status, body, _ = raw_post(url, payload, headers)
            return status, body
        token = auth.removeprefix("Bearer ")
        parts = urlsplit(canonical_htu(url))
        origin = f"{parts.scheme}://{parts.netloc}"  # nonces belong to the gateway, not a path
        base = {k: v for k, v in headers.items() if k.lower() not in ("authorization", "dpop")}
        status, body = 0, None
        for _ in range(2):
            with lock:
                nonce = nonces.get(origin)
            sent = {
                **base,
                "Authorization": f"DPoP {token}",
                "DPoP": key.proof("POST", url, access_token=token, nonce=nonce, now=now),
            }
            status, body, rh = raw_post(url, payload, sent)
            fresh = rh.get("dpop-nonce")
            if fresh:
                with lock:
                    nonces[origin] = fresh
            challenged = status == 401 and "use_dpop_nonce" in rh.get("www-authenticate", "")
            if not (challenged and fresh):
                return status, body
        return status, body

    return post
