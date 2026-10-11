"""Bind the caller's access token to their ID token before any exchange (ADR-0006, TM-ING-08).

The ID token is the ID-JAG ``subject_token``; the access token is what authorized the call.
Without binding, a caller could pair their own valid access token with somebody else's
(or a stale) ID token and have the interceptor mint delegated tokens as that user.

Rules, all of which must hold:

1. Access token valid under the ingress access-token policy.     -> ACCESS_TOKEN_INVALID
2. ID token valid under the ID-token policy (aud = front ends).  -> ID_TOKEN_INVALID
3. AT client: ``client_id`` (RFC 9068) and/or ``cid`` (Okta); if both, equal. -> CLIENT_MISMATCH
4. IDT client: ``aud`` if single-valued; if multi-valued, ``azp`` is required
   and must be in ``aud`` (OIDC Core §2).                        -> CLIENT_MISMATCH
5. AT client == IDT client.                                      -> CLIENT_MISMATCH
6. That client is in the profile's allowed front-end clients.    -> CLIENT_NOT_ALLOWED
7. ``AT.sub == IDT.sub``.                                        -> SUBJECT_MISMATCH
8. IDT ``auth_time`` present, an integer, not in the future.  -> ID_TOKEN_INVALID
9. ``now - IDT.auth_time <= max_auth_age_s`` (login age, not   -> AUTHENTICATION_TOO_OLD
   token age: Okta re-issues ID tokens on silent refresh).      (ADR-0009)
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from trustkit.jwt import Reason, TokenValidationError, TokenValidator, VerifiedToken


class BindingReason(StrEnum):
    ACCESS_TOKEN_INVALID = "access_token_invalid"  # noqa: S105 - enum label, not a credential
    ID_TOKEN_INVALID = "id_token_invalid"  # noqa: S105 - enum label, not a credential
    CLIENT_MISMATCH = "client_mismatch"
    CLIENT_NOT_ALLOWED = "client_not_allowed"
    SUBJECT_MISMATCH = "subject_mismatch"
    AUTHENTICATION_TOO_OLD = "authentication_too_old"


class BindingError(Exception):
    """Log-safe: carries reasons, never token material or claim values."""

    def __init__(self, reason: BindingReason, token_reason: Reason | None = None) -> None:
        self.reason = reason
        self.token_reason = token_reason
        msg = reason.value if token_reason is None else f"{reason.value} ({token_reason.value})"
        super().__init__(msg)


@dataclass(frozen=True)
class BoundIdentity:
    subject: str
    client_id: str
    """The front-end client both tokens were issued to. On ingress it requests the ID-JAG
    (ADR-0009)."""
    access_token: VerifiedToken
    id_token: VerifiedToken
    raw_id_token: str = field(repr=False)
    """Needed as the ``subject_token`` of the exchange. Excluded from ``repr`` so that logging
    a ``BoundIdentity`` can never leak a live credential (TM-ING-06)."""


def bind(
    access_token: str,
    id_token: str,
    *,
    access_token_validator: TokenValidator,
    id_token_validator: TokenValidator,
    allowed_clients: frozenset[str],
    max_auth_age_s: int,
    now: Callable[[], int] | None = None,
) -> BoundIdentity:
    try:
        at = access_token_validator.validate(access_token)
    except TokenValidationError as e:
        raise BindingError(BindingReason.ACCESS_TOKEN_INVALID, e.reason) from None
    try:
        idt = id_token_validator.validate(id_token)
    except TokenValidationError as e:
        raise BindingError(BindingReason.ID_TOKEN_INVALID, e.reason) from None

    client = _access_token_client(at)
    if client is None or client != _id_token_client(idt):
        raise BindingError(BindingReason.CLIENT_MISMATCH)
    if client not in allowed_clients:
        raise BindingError(BindingReason.CLIENT_NOT_ALLOWED)
    if at.subject != idt.subject:
        raise BindingError(BindingReason.SUBJECT_MISMATCH)

    t = (now or (lambda: int(time.time())))()
    auth_time = idt.claims.get("auth_time")
    if auth_time is None:
        raise BindingError(BindingReason.ID_TOKEN_INVALID, Reason.MISSING_CLAIM)
    if not isinstance(auth_time, int) or isinstance(auth_time, bool):
        raise BindingError(BindingReason.ID_TOKEN_INVALID, Reason.MALFORMED)
    if auth_time > t + id_token_validator.policy.leeway_seconds:
        raise BindingError(BindingReason.ID_TOKEN_INVALID, Reason.IAT_IN_FUTURE)
    if t - auth_time > max_auth_age_s:
        raise BindingError(BindingReason.AUTHENTICATION_TOO_OLD)

    return BoundIdentity(
        subject=at.subject, client_id=client, access_token=at, id_token=idt, raw_id_token=id_token
    )


def _access_token_client(at: VerifiedToken) -> str | None:
    """RFC 9068 ``client_id`` and/or Okta ``cid``. Both present but different -> ambiguous."""
    values = {at.claims[k] for k in ("client_id", "cid") if k in at.claims}
    if len(values) != 1:
        return None
    (value,) = values
    return value if isinstance(value, str) and value else None


def _id_token_client(idt: VerifiedToken) -> str | None:
    """OIDC Core §2: a single ``aud`` names the client; with several, ``azp`` must (and be in
    ``aud``). If ``azp`` is present it must agree with the client in every case."""
    aud = idt.claims["aud"]
    auds = [aud] if isinstance(aud, str) else list(aud)
    azp = idt.claims.get("azp")
    if azp is not None and (not isinstance(azp, str) or azp not in auds):
        return None
    if len(auds) == 1:
        return str(auds[0])
    return azp
