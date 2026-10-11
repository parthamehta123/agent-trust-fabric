"""Resource-server side: how an agent runtime authorizes an incoming T2 (ADR-0014 §1, TM-RT-01).

The runtime trusts **only** T2's claims. It never trusts ``x-atf-*`` headers, the caller's
original token, or anything else the gateway or interceptor might add (TM-RT-02).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from trustkit.jwt import (
    CORE_REQUIRED_CLAIMS,
    KeyResolver,
    Reason,
    TokenValidationError,
    TokenValidator,
    ValidationPolicy,
)

_BEARER: Final = re.compile(r"^[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9._~+/=-]+)$")
_SCOPE_TOKEN: Final = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")  # RFC 6749 §3.3 scope-token


class AuthzFailure(StrEnum):
    MISSING_TOKEN = "missing_token"  # noqa: S105 - enum label, not a credential
    INVALID_TOKEN = "invalid_token"  # noqa: S105 - enum label, not a credential
    INSUFFICIENT_SCOPE = "insufficient_scope"


class ResourceAuthzError(Exception):
    """Log-safe. ``status`` is 401 for token problems, 403 for insufficient scope.

    ``www_authenticate`` is the RFC 6750 §3 challenge value to return.
    """

    def __init__(
        self,
        failure: AuthzFailure,
        token_reason: Reason | None = None,
        *,
        required_scope: str | None = None,
    ) -> None:
        self.failure, self.token_reason, self.required_scope = failure, token_reason, required_scope
        self.status = 403 if failure is AuthzFailure.INSUFFICIENT_SCOPE else 401
        super().__init__(
            failure.value if token_reason is None else f"{failure.value} ({token_reason.value})"
        )

    @property
    def www_authenticate(self) -> str:
        if self.failure is AuthzFailure.MISSING_TOKEN:
            return "Bearer"  # RFC 6750 §3.1: no error code when no credentials were sent
        if self.failure is AuthzFailure.INVALID_TOKEN:
            return 'Bearer error="invalid_token"'
        scope = self.required_scope or ""
        if not _SCOPE_TOKEN.fullmatch(scope):  # never let a value break the header grammar
            return 'Bearer error="insufficient_scope"'
        return f'Bearer error="insufficient_scope", scope="{scope}"'


@dataclass(frozen=True)
class Principal:
    subject: str
    client_id: str
    scopes: frozenset[str]
    token_jti: str | None


class ResourceAuthorizer:
    """Validates ``Authorization: Bearer <T2>`` for one resource (agent).

    Checks: RFC 9068 ``typ: at+jwt``; ``iss`` = ``issuer``; ``aud`` contains ``audience``;
    signature; time claims; required ``client_id``, ``jti`` and ``scope``; and
    ``required_scope`` ∈ scope.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        keys: KeyResolver,
        now: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        self._validator = TokenValidator(
            ValidationPolicy(
                issuer=issuer,
                audiences=frozenset({audience}),
                expected_typ="at+jwt",
                required_claims=CORE_REQUIRED_CLAIMS | {"client_id", "jti", "scope"},
            ),
            keys,
            now=now,
        )

    def authorize(self, authorization_header: str | None, *, required_scope: str) -> Principal:
        if not authorization_header:
            raise ResourceAuthzError(AuthzFailure.MISSING_TOKEN)
        m = _BEARER.fullmatch(authorization_header)
        if m is None:
            raise ResourceAuthzError(AuthzFailure.INVALID_TOKEN)
        try:
            token = self._validator.validate(m.group(1))
        except TokenValidationError as e:
            raise ResourceAuthzError(AuthzFailure.INVALID_TOKEN, e.reason) from None
        scope, client_id = token.claims.get("scope"), token.claims.get("client_id")
        if not isinstance(scope, str) or not isinstance(client_id, str) or not client_id:
            raise ResourceAuthzError(AuthzFailure.INVALID_TOKEN, Reason.MALFORMED)
        scopes = frozenset(scope.split())
        if required_scope not in scopes:
            raise ResourceAuthzError(AuthzFailure.INSUFFICIENT_SCOPE, required_scope=required_scope)
        return Principal(
            subject=token.subject, client_id=client_id, scopes=scopes, token_jti=token.jti
        )
