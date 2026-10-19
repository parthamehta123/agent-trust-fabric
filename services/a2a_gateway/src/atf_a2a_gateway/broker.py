"""A2A broker (ADR-0024 §1): agent A -> agent B on behalf of a user.

``send`` order: target grant + card + T2 binding exist -> Cedar ``delegate`` A -> B -> requested
scopes (target scopes ∩ user's T2 scopes, must include ``agent.invoke``) -> request scan ->
delegated exchange at B's AS (subject = A's T2, actor = A) -> forward to B's runtime (SSRF-pinned)
-> response scan -> A2A message. Every failure is a typed, detail-free ``A2AError``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from trustkit.audit import AuditEvent, AuditSink, Decision
from trustkit.binding import ActorBinding
from trustkit.exchange import ExchangeError, ExchangeResult
from trustkit.profiles import (
    GatewayProfile,
    ProfileConfigError,
    ScannerFailureMode,
    UnknownGatewayError,
    load_profiles,
)
from trustkit.scanning import ContentScanner, Direction, Verdict, scan_with_policy
from trustkit_policy.bundle import LoadedBundle
from trustkit_policy.grants import AgentGrant
from trustkit_policy.idps import TrustedIdps
from trustkit_policy.runtime import delegate_decision, user_scopes, visible_card


class A2AFailure(StrEnum):
    POLICY_UNAVAILABLE = "policy_unavailable"  # 503
    UNKNOWN_AGENT = "unknown_agent"  # 404: absent, no card, or not visible to the caller
    DELEGATION_DENIED = "delegation_denied"  # 403
    NOT_ENTITLED = "not_entitled"  # 403: user's scopes don't allow invoking the target
    BLOCKED = "blocked"  # 403: request scan
    EXCHANGE_FAILED = "exchange_failed"  # 502
    TARGET_FAILED = "target_failed"  # 502
    RESPONSE_BLOCKED = "response_blocked"  # 502
    INVALID = "invalid"  # 400
    AUDIT_UNAVAILABLE = "audit_unavailable"  # 503: nothing minted or forwarded


class A2AError(Exception):
    def __init__(self, failure: A2AFailure) -> None:
        self.failure = failure
        super().__init__(failure.value)


class Exchanger(Protocol):
    def exchange_delegated(
        self, binding: ActorBinding, profile: GatewayProfile
    ) -> ExchangeResult: ...


class Upstream(Protocol):
    def post_json(
        self, url: str, payload: Mapping[str, Any], *, headers: Mapping[str, str]
    ) -> tuple[int, dict[str, Any] | None]: ...


@dataclass(frozen=True)
class BrokerConfig:
    gateway_base_url: str
    """Public base URL of this gateway; cards advertise ``{base}/agents/{id}/a2a``."""
    egress_base: Mapping[str, Any]
    """Egress profile document base (org IdP, this gateway's client, ``egress_inbound``). Per
    target, ``idp.resource_*``, ``target`` and ``server_id`` come from the target's grant."""
    target_scopes: frozenset[str]
    """Scopes requested for the target agent's API (intersected with the user's T2 scopes)."""
    trusted_idps: TrustedIdps
    """A target's T2 issuer becomes a token endpoint here: only on a trusted IdP (ADR-0027 #1)."""
    max_message_chars: int = 16_000


class A2ABroker:
    def __init__(
        self,
        *,
        policy: Callable[[], LoadedBundle | None],
        exchanger: Exchanger,
        upstream: Upstream,
        scanner: ContentScanner,
        audit: AuditSink,
        config: BrokerConfig,
        now: Callable[[], int],
    ) -> None:
        self._policy, self._exchanger, self._upstream = policy, exchanger, upstream
        self._scanner, self._audit, self._cfg, self._now = scanner, audit, config, now

    def send(self, binding: ActorBinding, target: str, text: str) -> str:
        """Deliver ``text`` from the bound agent to ``target`` for the bound user; returns the
        target's reply text. Raises ``A2AError``."""
        policy_ids: tuple[str, ...] = ()
        try:
            reply, policy_ids = self._send(binding, target, text)
        except A2AError as e:
            self._emit(binding, target, Decision.DENY, e.failure.value, policy_ids)
            raise
        self._emit(binding, target, Decision.ALLOW, "ok", policy_ids)
        return reply

    def _send(self, binding: ActorBinding, target: str, text: str) -> tuple[str, tuple[str, ...]]:
        if not text or len(text) > self._cfg.max_message_chars:
            raise A2AError(A2AFailure.INVALID)
        loaded = self._policy()
        if loaded is None:
            raise A2AError(A2AFailure.POLICY_UNAVAILABLE)
        caller = binding.agent_client_id
        if target == caller:
            raise A2AError(A2AFailure.DELEGATION_DENIED)
        grant = loaded.grant(target, self._now())
        if grant is None or grant.card is None or grant.ingress is None:
            raise A2AError(A2AFailure.UNKNOWN_AGENT)
        scopes = user_scopes(binding.subject_token)
        decision = delegate_decision(
            loaded, from_agent=caller, to_agent=target, user=binding.subject, user_scopes=scopes
        )
        if not decision.allowed:
            raise A2AError(A2AFailure.DELEGATION_DENIED)
        requested = self._cfg.target_scopes & scopes
        if "agent.invoke" not in requested:
            raise A2AError(A2AFailure.NOT_ENTITLED)
        if self._scan(text, Direction.REQUEST)[0] is not Verdict.ALLOW:
            raise A2AError(A2AFailure.BLOCKED)  # before any token is minted
        try:  # audit failure -> deny: record the delegation before minting anything
            self._audit.emit(
                self._event(binding, target, Decision.ALLOW, "delegating", decision.policy_ids)
            )
        except Exception:  # noqa: BLE001
            raise A2AError(A2AFailure.AUDIT_UNAVAILABLE) from None

        try:
            profile = self._profile_for(grant)
            result = self._exchanger.exchange_delegated(
                dataclasses.replace(binding, allowed_scopes=requested), profile
            )
        except (ExchangeError, ProfileConfigError, UnknownGatewayError, KeyError, ValueError):
            raise A2AError(A2AFailure.EXCHANGE_FAILED) from None

        try:
            status, body = self._upstream.post_json(
                grant.card.endpoint,
                {"prompt": text},
                headers={"Authorization": f"Bearer {result.token}"},
            )
        except Exception:  # noqa: BLE001 - SSRF refusal, transport: never surface details
            raise A2AError(A2AFailure.TARGET_FAILED) from None
        output = body.get("output") if status == 200 and isinstance(body, dict) else None
        if not isinstance(output, str):
            raise A2AError(A2AFailure.TARGET_FAILED)
        verdict, redacted = self._scan(output, Direction.RESPONSE)
        if verdict is Verdict.BLOCK:
            raise A2AError(A2AFailure.RESPONSE_BLOCKED)
        reply = redacted if verdict is Verdict.REDACT and redacted is not None else output
        return reply, decision.policy_ids

    def card(self, viewer: str, target: str) -> dict[str, Any]:
        """The target's Agent Card as ``viewer`` may see it. Raises ``A2AError(UNKNOWN_AGENT)``
        when it doesn't exist *or* isn't visible (no disclosure oracle)."""
        loaded = self._policy()
        if loaded is None:
            raise A2AError(A2AFailure.POLICY_UNAVAILABLE)
        card = visible_card(
            loaded,
            viewer=viewer,
            agent_id=target,
            gateway_url=f"{self._cfg.gateway_base_url}/agents/{target}/a2a",
            now=self._now(),
        )
        if card is None:
            raise A2AError(A2AFailure.UNKNOWN_AGENT)
        return card

    def _profile_for(self, grant: AgentGrant) -> GatewayProfile:
        """Egress profile for the target agent's AS, validated by the strict profile schema.
        Token endpoint: ``{issuer}/v1/token`` (custom-AS convention)."""
        ingress = grant.ingress
        if ingress is None:
            raise ValueError("target has no T2 binding")
        if not self._cfg.trusted_idps.allows(ingress.t2_issuer, ingress.t2_jwks_uri):
            raise ValueError("target's T2 issuer is not a trusted IdP")
        base = dict(self._cfg.egress_base)
        doc = {
            **base,
            "idp": {
                **base["idp"],
                "resource_issuer": ingress.t2_issuer,
                "resource_token_endpoint": f"{ingress.t2_issuer}/v1/token",
                "resource_jwks_uri": ingress.t2_jwks_uri,
            },
            "target": {
                "audience": ingress.t2_audience,
                "scopes": sorted(self._cfg.target_scopes),
            },
            "server_id": "a2a-target",
        }
        registry = load_profiles(json.dumps({"version": 1, "profiles": [doc]}))
        return registry.lookup(str(doc["gateway_id"]))

    def _scan(self, text: str, direction: Direction) -> tuple[Verdict, str | None]:
        out = scan_with_policy(
            self._scanner,
            text,
            direction=direction,
            failure_mode=ScannerFailureMode.CLOSED,  # A2A content is never fail-open
            timeout_s=0.8,
        )
        return out.result.verdict, out.result.redacted_text

    def _emit(
        self,
        binding: ActorBinding,
        target: str,
        decision: Decision,
        reason: str,
        policy_ids: tuple[str, ...],
    ) -> None:
        # Outcome events are best-effort; the allow was already audited before minting.
        with contextlib.suppress(Exception):
            self._audit.emit(self._event(binding, target, decision, reason, policy_ids))

    @staticmethod
    def _event(
        binding: ActorBinding,
        target: str,
        decision: Decision,
        reason: str,
        policy_ids: tuple[str, ...],
    ) -> AuditEvent:
        return AuditEvent(
            event_type="a2a.send",
            request_id=str(uuid.uuid4()),
            decision=decision,
            reason=f"{reason}:{target}"[:256],
            subject=binding.subject,
            client_id=binding.agent_client_id,
            policy_ids=policy_ids,
            actor_chain=binding.prior_actors,
        )
