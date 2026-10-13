"""Ingress T1 -> ID-JAG -> T2 exchange. The **single** exchange point (ADR-0002).

Flow (ADR-0009, ADR-0011)::

    BoundIdentity + ingress profile
      -> signer for profile.ingress_clients[bound.client_id]
      -> RFC 8693 token exchange at idp.token_endpoint           -> ID-JAG (validated)
      -> RFC 7523 JWT-bearer at idp.resource_token_endpoint      -> T2     (validated)
      -> cache

HTTP is behind the ``TokenEndpoint`` protocol (adapter: ``trustkit-http``). Keys are behind
``KeySigner`` (adapters: in-memory, ``trustkit-aws`` KMS) and ``KeyResolver`` (JWKS).

Threat-model refs: TM-EXC-02, TM-EXC-03, TM-EXC-07, TM-EXC-08, TM-ING-06.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Protocol

from trustkit.binding import ActorBinding, BoundIdentity, expected_act
from trustkit.breaker import BreakerRegistry
from trustkit.cache import TokenCache, cache_key
from trustkit.jwt import (
    CORE_REQUIRED_CLAIMS,
    KeyResolver,
    TokenValidationError,
    TokenValidator,
    ValidationPolicy,
    VerifiedToken,
)
from trustkit.profiles import Flow, GatewayProfile
from trustkit.signing import KeySigner, SigningError, build_client_assertion

GRANT_TOKEN_EXCHANGE: Final = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - protocol URN
GRANT_JWT_BEARER: Final = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_TYPE_ID_JAG: Final = "urn:ietf:params:oauth:token-type:id-jag"  # noqa: S105 - protocol URN
TOKEN_TYPE_ACCESS_TOKEN: Final = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 - URN
TOKEN_TYPE_ID_TOKEN: Final = "urn:ietf:params:oauth:token-type:id_token"  # noqa: S105 - protocol URN
CLIENT_ASSERTION_TYPE: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ID_JAG_TYP: Final = "oauth-id-jag+jwt"
ACCESS_TOKEN_TYP: Final = "at+jwt"  # noqa: S105 - JOSE typ value

KNOWN_OAUTH_ERRORS: Final = frozenset(
    {
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
        "invalid_target",
        "temporarily_unavailable",
        "server_error",
    }
)
"""Only these IdP ``error`` codes are surfaced; anything else (and every description) is dropped."""


# ----------------------------------------------------------------------------- transport


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: Mapping[str, Any]
    """Parsed JSON object, or ``{}`` if the response was not acceptable JSON."""


class TransportError(Exception):
    """No HTTP response was received (connect error, timeout). The only retryable failure."""


class TokenEndpoint(Protocol):
    def post_form(self, url: str, form: Mapping[str, str]) -> HttpResult: ...


# ----------------------------------------------------------------------------- results


class ExchangeReason(StrEnum):
    PROFILE_NOT_INGRESS = "profile_not_ingress"
    PROFILE_NOT_EGRESS = "profile_not_egress"
    AGENT_NOT_CONFIGURED = "agent_not_configured"
    DELEGATED_INVALID = "delegated_invalid"
    PROFILE_DISABLED = "profile_disabled"
    CLIENT_NOT_CONFIGURED = "client_not_configured"
    SIGNING_FAILED = "signing_failed"
    IDP_UNAVAILABLE = "idp_unavailable"
    CIRCUIT_OPEN = "circuit_open"
    IDP_ERROR = "idp_error"
    MALFORMED_RESPONSE = "malformed_response"
    ID_JAG_INVALID = "id_jag_invalid"
    T2_INVALID = "t2_invalid"
    T2_SCOPE_ESCALATION = "t2_scope_escalation"


class ExchangeError(Exception):
    """Log-safe. ``idp_error`` is set only for codes in ``KNOWN_OAUTH_ERRORS``."""

    def __init__(
        self, reason: ExchangeReason, *, step: str | None = None, idp_error: str | None = None
    ) -> None:
        self.reason, self.step, self.idp_error = reason, step, idp_error
        parts = [reason.value] + [p for p in (step, idp_error) if p]
        super().__init__(" / ".join(parts))


@dataclass(frozen=True)
class ExchangeResult:
    token: str = field(repr=False)
    """T2. Never logged (TM-ING-06)."""
    claims: VerifiedToken
    cached: bool


SignerFactory = Callable[[str], KeySigner]
"""Profile key reference (KMS ARN or ``local:<name>``) -> signer. Implementations should memoise."""

KeyResolverFactory = Callable[[str], KeyResolver]
"""JWKS URI -> resolver. Implementations should memoise (one resolver per URI)."""


_DELEGATED_TOKEN_CLAIMS: Final = CORE_REQUIRED_CLAIMS | {"client_id", "jti"}
_MAX_ATTEMPTS: Final = 2  # one retry, transport errors only (ADR-0011)


class IdJagExchanger:
    def __init__(
        self,
        *,
        http: TokenEndpoint,
        signers: SignerFactory,
        jwks: KeyResolverFactory,
        cache: TokenCache[ExchangeResult] | None = None,
        breakers: BreakerRegistry | None = None,
        now: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        """``breakers``: per-endpoint circuit breakers (ADR-0014 §4); ``None`` disables them."""
        self._breakers = breakers
        self._http = http
        self._signers = signers
        self._jwks = jwks
        self._cache: TokenCache[ExchangeResult] = (
            cache if cache is not None else TokenCache(now=now)
        )
        self._now = now
        self._validators: dict[tuple[str, str, str, str], TokenValidator] = {}

    def exchange(self, bound: BoundIdentity, profile: GatewayProfile) -> ExchangeResult:
        # Gating happens before the cache so a kill switch or config change wins immediately.
        if profile.flow is not Flow.INGRESS:
            raise ExchangeError(ExchangeReason.PROFILE_NOT_INGRESS)
        if not profile.enabled:
            raise ExchangeError(ExchangeReason.PROFILE_DISABLED)
        key_ref = (profile.ingress_clients or {}).get(bound.client_id)
        if key_ref is None:
            raise ExchangeError(ExchangeReason.CLIENT_NOT_CONFIGURED)

        key = cache_key(
            at_jti=bound.access_token.jti,
            idt_jti=bound.id_token.jti,
            subject=bound.subject,
            audience=profile.target.audience,
            profile_id=profile.profile_id,
        )
        if key is not None and (hit := self._cache.get(key)) is not None:
            return dataclasses.replace(hit, cached=True)

        try:
            signer = self._signers(key_ref)
        except SigningError:
            raise ExchangeError(ExchangeReason.SIGNING_FAILED) from None

        idp = profile.idp
        step = "token_exchange"
        body = self._call(
            step,
            idp.token_endpoint,
            signer,
            bound.client_id,
            {
                "grant_type": GRANT_TOKEN_EXCHANGE,
                "requested_token_type": TOKEN_TYPE_ID_JAG,
                "subject_token": bound.raw_id_token,
                "subject_token_type": TOKEN_TYPE_ID_TOKEN,
                "audience": idp.resource_issuer,
                "scope": " ".join(sorted(profile.target.scopes)),
            },
        )
        if body.get("issued_token_type") != TOKEN_TYPE_ID_JAG or not _token_type_is(body, "n_a"):
            raise ExchangeError(ExchangeReason.MALFORMED_RESPONSE, step=step)
        id_jag = _token_field(body, step)
        jag = self._validate(
            id_jag,
            ExchangeReason.ID_JAG_INVALID,
            step,
            issuer=idp.issuer,
            audience=idp.resource_issuer,
            typ=ID_JAG_TYP,
            jwks_uri=idp.jwks_uri,
        )
        _require_same_principal(jag, bound, ExchangeReason.ID_JAG_INVALID, step)

        step = "jwt_bearer"
        body = self._call(
            step,
            idp.resource_token_endpoint,
            signer,
            bound.client_id,
            {"grant_type": GRANT_JWT_BEARER, "assertion": id_jag},
        )
        if not _token_type_is(body, "bearer"):
            raise ExchangeError(ExchangeReason.MALFORMED_RESPONSE, step=step)
        t2 = _token_field(body, step)
        t2_claims = self._validate(
            t2,
            ExchangeReason.T2_INVALID,
            step,
            issuer=idp.resource_issuer,
            audience=profile.target.audience,
            typ=ACCESS_TOKEN_TYP,
            jwks_uri=idp.resource_jwks_uri,
        )
        _require_same_principal(t2_claims, bound, ExchangeReason.T2_INVALID, step)
        granted = t2_claims.claims.get("scope")
        if not isinstance(granted, str) or not set(granted.split()) <= profile.target.scopes:
            raise ExchangeError(ExchangeReason.T2_SCOPE_ESCALATION, step=step)

        result = ExchangeResult(token=t2, claims=t2_claims, cached=False)
        if key is not None:
            self._cache.put(key, result, exp=int(t2_claims.claims["exp"]))
        return result

    def exchange_delegated(self, binding: ActorBinding, profile: GatewayProfile) -> ExchangeResult:
        """ADR-0016 §5-§6: T2 (subject) + workload token (actor) -> tool token with ``act``.

        Client auth is the tool gateway's own client (``profile.client``). Requested scope is
        ``target.scopes ∩ binding.allowed_scopes``. The result is validated (iss, aud, typ, sub,
        act.sub, no nested act, client_id, scope subset) before it is cached or returned.
        """
        if profile.flow is not Flow.EGRESS:
            raise ExchangeError(ExchangeReason.PROFILE_NOT_EGRESS)
        if not profile.enabled:
            raise ExchangeError(ExchangeReason.PROFILE_DISABLED)
        requested = profile.target.scopes & binding.allowed_scopes
        if profile.client is None or not requested:
            raise ExchangeError(ExchangeReason.AGENT_NOT_CONFIGURED)

        # The requested scopes are part of the key: when a policy bundle narrows an agent's
        # grant, a token minted under the broader grant must never be served from cache.
        key = cache_key(
            at_jti=binding.subject_token.jti,
            idt_jti=binding.workload.jti,
            subject=binding.subject,
            audience=profile.target.audience,
            profile_id=(
                f"{profile.profile_id}#delegated#{binding.agent_client_id}"
                f"#{' '.join(sorted(requested))}"
            ),
        )
        if key is not None and (hit := self._cache.get(key)) is not None:
            return dataclasses.replace(hit, cached=True)

        try:
            signer = self._signers(profile.client.signing_key)
        except SigningError:
            raise ExchangeError(ExchangeReason.SIGNING_FAILED) from None

        idp, step = profile.idp, "delegation"
        body = self._call(
            step,
            idp.resource_token_endpoint,
            signer,
            profile.client.client_id,
            {
                "grant_type": GRANT_TOKEN_EXCHANGE,
                "requested_token_type": TOKEN_TYPE_ACCESS_TOKEN,
                "subject_token": binding.raw_subject,
                "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
                "actor_token": binding.raw_workload,
                "actor_token_type": TOKEN_TYPE_ACCESS_TOKEN,
                "audience": idp.resource_issuer,
                "resource": profile.target.audience,
                "scope": " ".join(sorted(requested)),
            },
        )
        if body.get("issued_token_type") != TOKEN_TYPE_ACCESS_TOKEN or not _token_type_is(
            body, "bearer"
        ):
            raise ExchangeError(ExchangeReason.MALFORMED_RESPONSE, step=step)
        token = _token_field(body, step)
        verified = self._validate(
            token,
            ExchangeReason.DELEGATED_INVALID,
            step,
            issuer=idp.resource_issuer,
            audience=profile.target.audience,
            typ=ACCESS_TOKEN_TYP,
            jwks_uri=idp.resource_jwks_uri,
        )
        c = verified.claims
        if (
            c.get("sub") != binding.subject
            or c.get("client_id") != profile.client.client_id
            # Exactly the expected chain: this agent, nesting the prior actors (ADR-0024 §2).
            or c.get("act") != expected_act(binding)
        ):
            raise ExchangeError(ExchangeReason.DELEGATED_INVALID, step=step)
        granted = c.get("scope")
        if not isinstance(granted, str) or not set(granted.split()) <= requested:
            raise ExchangeError(ExchangeReason.T2_SCOPE_ESCALATION, step=step)

        result = ExchangeResult(token=token, claims=verified, cached=False)
        if key is not None:
            self._cache.put(key, result, exp=int(c["exp"]))
        return result

    # -- helpers ----------------------------------------------------------------------------------

    def _call(
        self, step: str, url: str, signer: KeySigner, client_id: str, form: Mapping[str, str]
    ) -> Mapping[str, Any]:
        breaker = self._breakers.get(url) if self._breakers is not None else None
        if breaker is not None and not breaker.allow():
            raise ExchangeError(ExchangeReason.CIRCUIT_OPEN, step=step)
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            # A fresh assertion per attempt: the IdP may have consumed the previous jti.
            try:
                assertion = build_client_assertion(
                    signer, client_id=client_id, token_endpoint=url, now=self._now
                )
            except (SigningError, ValueError):
                # Our key failed, not the IdP: free the probe slot, say nothing about IdP health.
                if breaker is not None:
                    breaker.release_probe()
                raise ExchangeError(ExchangeReason.SIGNING_FAILED, step=step) from None
            try:
                res = self._http.post_form(
                    url,
                    {
                        **form,
                        "client_assertion_type": CLIENT_ASSERTION_TYPE,
                        "client_assertion": assertion,
                    },
                )
            except TransportError:
                if attempt == _MAX_ATTEMPTS:
                    if breaker is not None:
                        breaker.record_failure()
                    raise ExchangeError(ExchangeReason.IDP_UNAVAILABLE, step=step) from None
                continue
            if breaker is not None:
                # Only dependency failures count; a 4xx policy answer proves the IdP is healthy.
                if res.status >= 500 or res.status == 429:
                    breaker.record_failure()
                else:
                    breaker.record_success()
            if res.status != 200:
                code = res.body.get("error")
                known = code if isinstance(code, str) and code in KNOWN_OAUTH_ERRORS else None
                raise ExchangeError(ExchangeReason.IDP_ERROR, step=step, idp_error=known)
            return res.body
        raise AssertionError("unreachable")  # pragma: no cover

    def _validate(
        self,
        token: str,
        reason: ExchangeReason,
        step: str,
        *,
        issuer: str,
        audience: str,
        typ: str,
        jwks_uri: str,
    ) -> VerifiedToken:
        cache_key_ = (issuer, audience, typ, jwks_uri)
        validator = self._validators.get(cache_key_)
        if validator is None:
            validator = TokenValidator(
                ValidationPolicy(
                    issuer=issuer,
                    audiences=frozenset({audience}),
                    expected_typ=typ,
                    required_claims=_DELEGATED_TOKEN_CLAIMS,
                ),
                self._jwks(jwks_uri),
                now=self._now,
            )
            self._validators[cache_key_] = validator
        try:
            return validator.validate(token)
        except TokenValidationError:
            raise ExchangeError(reason, step=step) from None


def _token_type_is(body: Mapping[str, Any], expected: str) -> bool:
    tt = body.get("token_type")
    return isinstance(tt, str) and tt.lower() == expected


def _token_field(body: Mapping[str, Any], step: str) -> str:
    token = body.get("access_token")
    if not isinstance(token, str) or not token:
        raise ExchangeError(ExchangeReason.MALFORMED_RESPONSE, step=step)
    return token


def _require_same_principal(
    tok: VerifiedToken, bound: BoundIdentity, reason: ExchangeReason, step: str
) -> None:
    """Mix-up defence: the IdP must have issued for *this* user via *this* client."""
    if tok.claims.get("sub") != bound.subject or tok.claims.get("client_id") != bound.client_id:
        raise ExchangeError(reason, step=step)
