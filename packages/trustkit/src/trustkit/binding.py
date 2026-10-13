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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from trustkit.jwt import (
    Reason,
    TokenValidationError,
    TokenValidator,
    VerifiedToken,
)


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


# ----------------------------------------------------------------------------- egress (ADR-0016)


class ActorBindingReason(StrEnum):
    WORKLOAD_INVALID = "workload_invalid"
    AGENT_NOT_ALLOWED = "agent_not_allowed"
    SUBJECT_INVALID = "subject_invalid"
    DELEGATION_CHAIN = "delegation_chain"


class ActorBindingError(Exception):
    """Log-safe: reasons only."""

    def __init__(self, reason: ActorBindingReason, token_reason: Reason | None = None) -> None:
        self.reason, self.token_reason = reason, token_reason
        msg = reason.value if token_reason is None else f"{reason.value} ({token_reason.value})"
        super().__init__(msg)


@dataclass(frozen=True)
class AgentPolicy:
    t2_validator: TokenValidator
    """Validates T2 for *this* agent: its resource AS issuer, its audience, ``typ: at+jwt``."""
    allowed_scopes: frozenset[str]


@dataclass(frozen=True)
class ActorBinding:
    agent_client_id: str
    subject: str
    allowed_scopes: frozenset[str]
    workload: VerifiedToken
    subject_token: VerifiedToken
    raw_workload: str = field(repr=False)
    raw_subject: str = field(repr=False)
    prior_actors: tuple[str, ...] = ()
    """Agents earlier in the delegation chain, oldest first (ADR-0024). Empty = user -> agent."""


def bind_actor(
    workload_token: str,
    subject_token: str,
    *,
    workload_validator: TokenValidator,
    agents: Mapping[str, AgentPolicy],
    max_prior_actors: int = 0,
) -> ActorBinding:
    """Bind the agent's workload token (actor) to the user-delegated T2 (subject).

    1. Workload token valid, ``sub == client_id``.                   -> WORKLOAD_INVALID
    2. ``client_id`` listed in ``agents``.                           -> AGENT_NOT_ALLOWED
    3. T2 valid under *that agent's* policy (so T2.aud is this agent) -> SUBJECT_INVALID
       This is the confused-deputy guard: agent A can't spend agent B's T2.
    4. T2's ``act`` chain is well formed and has at most ``max_prior_actors`` actors
       (ADR-0024: 0 = no chains, 1 = user -> A -> this agent), with no loops.
                                                                    -> DELEGATION_CHAIN
    """
    try:
        workload = workload_validator.validate(workload_token)
    except TokenValidationError as e:
        raise ActorBindingError(ActorBindingReason.WORKLOAD_INVALID, e.reason) from None
    agent = workload.claims.get("client_id")
    if not isinstance(agent, str) or workload.claims.get("sub") != agent:
        raise ActorBindingError(ActorBindingReason.WORKLOAD_INVALID, Reason.MALFORMED)
    policy = agents.get(agent)
    if policy is None:
        raise ActorBindingError(ActorBindingReason.AGENT_NOT_ALLOWED)
    try:
        subject = policy.t2_validator.validate(subject_token)
    except TokenValidationError as e:
        raise ActorBindingError(ActorBindingReason.SUBJECT_INVALID, e.reason) from None
    try:
        prior = parse_act_chain(subject.claims.get("act"))
    except ValueError:
        raise ActorBindingError(ActorBindingReason.DELEGATION_CHAIN) from None
    if len(prior) > max_prior_actors or agent in prior or len(set(prior)) != len(prior):
        # Too long, or a loop (an agent acting "for" itself further up the chain).
        raise ActorBindingError(ActorBindingReason.DELEGATION_CHAIN)
    return ActorBinding(
        agent_client_id=agent,
        subject=subject.subject,
        allowed_scopes=policy.allowed_scopes,
        workload=workload,
        subject_token=subject,
        raw_workload=workload_token,
        raw_subject=subject_token,
        prior_actors=prior,
    )


MAX_CHAIN_DEPTH = 8
"""Parser bound only (stack safety); the policy cap is ``max_prior_actors``."""


def parse_act_chain(act: object) -> tuple[str, ...]:
    """RFC 8693 §4.1 ``act`` -> actors oldest first. ``None`` -> ``()``.

    Each level must be exactly ``{"sub": str}`` or ``{"sub": str, "act": {...}}``; any other
    member, a non-string or empty ``sub``, or nesting beyond ``MAX_CHAIN_DEPTH`` raises
    ``ValueError`` (never partially trusted)."""
    newest_first: list[str] = []
    node = act
    while node is not None:
        if len(newest_first) >= MAX_CHAIN_DEPTH:
            raise ValueError("act chain too deep")
        if not isinstance(node, dict) or "sub" not in node or not set(node) <= {"sub", "act"}:
            raise ValueError("malformed act")
        sub = node["sub"]
        if not isinstance(sub, str) or not sub:
            raise ValueError("malformed act subject")
        newest_first.append(sub)
        if "act" in node:
            node = node["act"]
            if node is None:  # an explicit null is ambiguous: never accept it
                raise ValueError("null nested act")
        else:
            node = None
    return tuple(reversed(newest_first))


def expected_act(binding: ActorBinding) -> dict[str, object]:
    """The ``act`` a delegated token minted for ``binding`` must carry: the current agent,
    nesting the prior actors (newest outermost)."""
    act: dict[str, object] = {"sub": binding.agent_client_id}
    inner: dict[str, object] = act
    for prior in reversed(binding.prior_actors):
        nxt: dict[str, object] = {"sub": prior}
        inner["act"] = nxt
        inner = nxt
    return act
