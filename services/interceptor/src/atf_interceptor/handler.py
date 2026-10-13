"""The interceptor Lambda handler: the single ingress exchange point (ADR-0002, ADR-0012, ADR-0013).

REQUEST (ingress profile):
  context GATEWAY_ARN -> profile (never caller input) -> enabled? -> headers present?
  -> Authorization: Bearer <AT> + X-Subject-Token: <ID token> -> bind (ADR-0006/0009)
  -> exchange -> T2 (ADR-0011) -> scan request (ADR-0004)
  -> forward with Authorization: Bearer <T2> + every reserved x-atf-* header overwritten.
  Caller headers are never forwarded by us.

REQUEST (egress profile): deny until Phase 3 implements the egress flow (fail closed).

RESPONSE (any profile): monotonic (ADR-0013). Scan if the profile says so; then pass, redact or
deny. Never upgrade.

The handler **never raises** (ADR-0012 §3, TM-INT-01). Every failure becomes an explicit deny
output, and every decision emits exactly one audit event.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

from atf_interceptor.events import (
    EventError,
    InterceptorEvent,
    Phase,
    Shape,
    deny,
    forward_request,
    gateway_id_from_context,
    parse_event,
    pass_response,
    replace_response_text,
    request_id_from_context,
)
from trustkit import policy
from trustkit.audit import AuditEvent, AuditSink, Decision, jti_hash
from trustkit.binding import (
    ActorBinding,
    ActorBindingError,
    BindingError,
    BoundIdentity,
    bind,
    bind_actor,
)
from trustkit.exchange import ExchangeError, ExchangeReason, ExchangeResult, KeyResolverFactory
from trustkit.jwt import TokenValidator, ValidationPolicy
from trustkit.profiles import (
    Flow,
    GatewayProfile,
    ProfileConfigError,
    ProfileRegistry,
    UnknownGatewayError,
)
from trustkit.scanning import (
    ContentScanner,
    Direction,
    ScanOutcome,
    Verdict,
    failure_outcome,
    scan_with_policy,
)
from trustkit_policy.bundle import LoadedBundle
from trustkit_policy.runtime import actor_policies_from_bundle, tool_decision, user_scopes

RESERVED_HEADERS: Final = tuple(sorted(policy.RESERVED_HEADERS))
"""Always set on every forwarded request (ADR-0012 §4). Advisory only: runtimes trust T2 claims."""

SUBJECT_TOKEN_HEADER: Final = "x-subject-token"  # noqa: S105 - header name
LAMBDA_SAFETY_MARGIN_S: Final = 0.5
_BEARER: Final = re.compile(r"^[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9._~+/=-]+)$")
_EXCHANGE_DEPENDENCY_FAILURES: Final = frozenset(
    {
        ExchangeReason.IDP_UNAVAILABLE,
        ExchangeReason.CIRCUIT_OPEN,
        ExchangeReason.SIGNING_FAILED,
        ExchangeReason.MALFORMED_RESPONSE,
    }
)


class Exchanger(Protocol):
    def exchange(self, bound: BoundIdentity, profile: GatewayProfile) -> ExchangeResult: ...

    def exchange_delegated(
        self, binding: ActorBinding, profile: GatewayProfile
    ) -> ExchangeResult: ...


@dataclass(frozen=True, kw_only=True)
class InterceptorDeps:
    profiles: Callable[[], ProfileRegistry]
    """Returns the current registry; raising ``ProfileConfigError`` means deny everything."""
    exchanger: Exchanger
    jwks: KeyResolverFactory
    scanner: ContentScanner
    audit: AuditSink
    now: Callable[[], int]
    monotonic: Callable[[], float]
    deadline_s: float = 4.0
    """Internal budget. Kept below the Lambda timeout so slow dependencies become explicit
    denies."""
    policy: Callable[[], LoadedBundle | None] = lambda: None
    """Current verified policy bundle (ADR-0022). ``None`` = no fresh bundle: egress denies."""


Handler = Callable[[Mapping[str, Any], Any], dict[str, Any]]


class _Deny(Exception):  # noqa: N818 - control flow, not an error condition
    def __init__(self, status: int, reason: str, event_type: str | None = None) -> None:
        self.status, self.reason, self.event_type = status, reason, event_type
        super().__init__(reason)


@dataclass
class _Call:
    """Per-invocation state: audit fields accumulate as the decision progresses."""

    deps: InterceptorDeps
    context: Any
    request_id: str
    started: float
    budget_s: float
    fields: dict[str, Any]
    extra_events: list[AuditEvent]

    def check_deadline(self) -> None:
        if self.deps.monotonic() - self.started > self.budget_s:
            raise _Deny(503, "deadline_exceeded")

    def remaining_s(self) -> float:
        return max(0.0, self.budget_s - (self.deps.monotonic() - self.started))


def make_handler(deps: InterceptorDeps) -> Handler:
    validators: dict[tuple[str, ...], tuple[TokenValidator, TokenValidator]] = {}

    def binding_validators(profile: GatewayProfile) -> tuple[TokenValidator, TokenValidator]:
        it, clients = profile.ingress_token, profile.ingress_clients
        if it is None or clients is None:  # schema guarantees this; never rely on assert (-O)
            raise _Deny(503, "profile_invalid")
        key = (
            profile.profile_id,
            it.issuer,
            it.jwks_uri,
            *sorted(it.audiences),
            profile.idp.issuer,
            profile.idp.jwks_uri,
            *sorted(clients),
        )
        if key not in validators:
            at_v = TokenValidator(
                ValidationPolicy(issuer=it.issuer, audiences=it.audiences),
                deps.jwks(it.jwks_uri),
                now=deps.now,
            )
            idt_v = TokenValidator(
                ValidationPolicy(issuer=profile.idp.issuer, audiences=frozenset(clients)),
                deps.jwks(profile.idp.jwks_uri),
                now=deps.now,
            )
            validators[key] = (at_v, idt_v)
        return validators[key]

    workload_cache: dict[tuple[str, ...], TokenValidator] = {}

    def workload_validator(profile: GatewayProfile) -> TokenValidator:
        ei = profile.egress_inbound
        if ei is None:  # schema guarantees this; never rely on assert (-O)
            raise _Deny(503, "profile_invalid")
        key = (profile.profile_id, ei.issuer, ei.jwks_uri, *sorted(ei.audiences))
        if key not in workload_cache:
            workload_cache[key] = TokenValidator(
                ValidationPolicy(issuer=ei.issuer, audiences=ei.audiences, expected_typ="at+jwt"),
                deps.jwks(ei.jwks_uri),
                now=deps.now,
            )
        return workload_cache[key]

    def handler(event: Mapping[str, Any], context: Any) -> dict[str, Any]:
        request_id = request_id_from_context(context)
        shape = Shape.MCP if isinstance(event, Mapping) and "mcp" in event else Shape.HTTP
        call = _Call(
            deps=deps,
            context=context,
            request_id=request_id,
            started=deps.monotonic(),
            budget_s=_budget(deps, context),
            fields={},
            extra_events=[],
        )
        jsonrpc_id: Any = None
        try:
            ev = _parse(event)
            shape, jsonrpc_id = ev.shape, ev.jsonrpc_id
            output, decision, reason, event_type = _decide(
                call, ev, binding_validators, workload_validator
            )
        except _Deny as d:
            output = deny(shape, status=d.status, request_id=request_id, jsonrpc_id=jsonrpc_id)
            decision, reason = Decision.DENY, d.reason
            event_type = d.event_type or _event_type(event)
        except Exception:  # noqa: BLE001 - TM-INT-01: never let the gateway see an exception
            output = deny(shape, status=503, request_id=request_id, jsonrpc_id=jsonrpc_id)
            decision, reason, event_type = Decision.DENY, "internal_error", "interceptor.error"

        try:
            for extra in call.extra_events:
                deps.audit.emit(extra)
            deps.audit.emit(
                AuditEvent(
                    event_type=event_type,
                    request_id=request_id,
                    decision=decision,
                    reason=reason,
                    latency_ms=int((deps.monotonic() - call.started) * 1000),
                    **call.fields,
                )
            )
        except Exception:  # noqa: BLE001 - TM-ING-07: no audit, no access
            if decision is not Decision.DENY:
                return deny(shape, status=503, request_id=request_id, jsonrpc_id=jsonrpc_id)
        return output

    return handler


def _budget(deps: InterceptorDeps, context: Any) -> float:
    remaining = getattr(context, "get_remaining_time_in_millis", None)
    budget = deps.deadline_s
    if callable(remaining):
        # A broken context just means "use our own budget".
        with contextlib.suppress(Exception):
            budget = min(budget, remaining() / 1000 - LAMBDA_SAFETY_MARGIN_S)
    return budget


def _event_type(event: Any) -> str:
    try:
        phase = parse_event(event).phase
    except Exception:  # noqa: BLE001
        return "interceptor.request"
    return "interceptor.response" if phase is Phase.RESPONSE else "interceptor.request"


def _parse(event: Any) -> InterceptorEvent:
    try:
        return parse_event(event)
    except EventError:
        raise _Deny(400, "event_malformed") from None


def _decide(
    call: _Call,
    ev: InterceptorEvent,
    binding_validators: Callable[[GatewayProfile], tuple[TokenValidator, TokenValidator]],
    workload_validator: Callable[[GatewayProfile], TokenValidator],
) -> tuple[dict[str, Any], Decision, str, str]:
    deps = call.deps
    gateway_id = gateway_id_from_context(call.context)
    if gateway_id is None:
        raise _Deny(403, "gateway_unknown")
    call.fields["gateway_id"] = gateway_id
    try:
        profile = deps.profiles().lookup(gateway_id)
    except ProfileConfigError:
        raise _Deny(503, "config_invalid", "config.invalid") from None
    except UnknownGatewayError:
        raise _Deny(403, "gateway_unknown") from None
    call.fields["profile_id"] = profile.profile_id
    if not profile.enabled:
        raise _Deny(403, "profile_disabled")

    if ev.phase is Phase.RESPONSE:
        return _decide_response(call, ev, profile)
    if profile.flow is Flow.EGRESS:
        return _decide_egress_request(call, ev, profile, workload_validator)
    return _decide_ingress_request(call, ev, profile, binding_validators)


def _decide_ingress_request(
    call: _Call,
    ev: InterceptorEvent,
    profile: GatewayProfile,
    binding_validators: Callable[[GatewayProfile], tuple[TokenValidator, TokenValidator]],
) -> tuple[dict[str, Any], Decision, str, str]:
    deps = call.deps
    if ev.headers is None:
        raise _Deny(503, "headers_not_passed")  # passRequestHeaders=false: misconfiguration
    m = _BEARER.fullmatch(ev.headers.get("authorization") or "")
    id_token = ev.headers.get(SUBJECT_TOKEN_HEADER)
    if m is None or not id_token:
        raise _Deny(401, "missing_credentials")

    at_v, idt_v = binding_validators(profile)
    if profile.ingress_clients is None or profile.max_auth_age_s is None:
        raise _Deny(503, "profile_invalid")
    try:
        bound = bind(
            m.group(1),
            id_token,
            access_token_validator=at_v,
            id_token_validator=idt_v,
            allowed_clients=frozenset(profile.ingress_clients),
            max_auth_age_s=profile.max_auth_age_s,
            now=deps.now,
        )
    except BindingError as e:
        raise _Deny(401, f"binding:{e.reason.value}") from None
    call.fields.update(
        subject=bound.subject,
        client_id=bound.client_id,
        at_jti_sha256=jti_hash(bound.access_token.jti),
        idt_jti_sha256=jti_hash(bound.id_token.jti),
    )
    call.check_deadline()

    try:
        result = deps.exchanger.exchange(bound, profile)
    except ExchangeError as e:
        status = 503 if e.reason in _EXCHANGE_DEPENDENCY_FAILURES else 403
        raise _Deny(status, f"exchange:{e.reason.value}") from None
    call.fields.update(
        target_audience=profile.target.audience,
        t2_jti_sha256=jti_hash(result.claims.jti),
        t2_cached=result.cached,
    )
    call.check_deadline()
    return _scan_and_forward(call, ev, profile, result.token)


def _decide_egress_request(
    call: _Call,
    ev: InterceptorEvent,
    profile: GatewayProfile,
    workload_validator: Callable[[GatewayProfile], TokenValidator],
) -> tuple[dict[str, Any], Decision, str, str]:
    """ADR-0016, ADR-0022: workload token (actor) + T2 (subject), authorized by the signed
    policy bundle and Cedar, -> delegated tool token with ``act``."""
    deps = call.deps
    if ev.headers is None:
        raise _Deny(503, "headers_not_passed")
    m = _BEARER.fullmatch(ev.headers.get("authorization") or "")
    subject_token = ev.headers.get(SUBJECT_TOKEN_HEADER)
    if m is None or not subject_token:
        raise _Deny(401, "missing_credentials")

    loaded = deps.policy()
    server_id = profile.server_id
    if loaded is None or server_id is None:
        raise _Deny(503, "policy_unavailable")  # no fresh bundle: fail closed (ADR-0022 §6)
    target_scopes = profile.target.scopes
    agents = actor_policies_from_bundle(
        loaded,
        deps.jwks,
        scopes_for=lambda g: g.tools.get(server_id, frozenset()) & target_scopes,
        now=deps.now,
    )
    try:
        binding = bind_actor(
            m.group(1),
            subject_token,
            workload_validator=workload_validator(profile),
            agents=agents,
            max_prior_actors=1,  # ADR-0024: user -> A -> B, never deeper
        )
    except ActorBindingError as e:
        raise _Deny(401, f"actor_binding:{e.reason.value}") from None
    call.fields.update(
        subject=binding.subject,
        client_id=binding.agent_client_id,
        at_jti_sha256=jti_hash(binding.subject_token.jti),
        actor_jti_sha256=jti_hash(binding.workload.jti),
        actor_chain=binding.prior_actors,
    )
    decision = tool_decision(
        loaded,
        agent_id=binding.agent_client_id,
        user=binding.subject,
        user_scopes=user_scopes(binding.subject_token),
        server_id=server_id,
        delegation="token",
        requested=binding.allowed_scopes,
        chain=binding.prior_actors,
    )
    call.fields["policy_ids"] = decision.policy_ids
    if not decision.allowed:
        raise _Deny(403, "policy_denied")
    call.check_deadline()

    try:
        result = deps.exchanger.exchange_delegated(binding, profile)
    except ExchangeError as e:
        status = 503 if e.reason in _EXCHANGE_DEPENDENCY_FAILURES else 403
        raise _Deny(status, f"exchange:{e.reason.value}") from None
    call.fields.update(
        target_audience=profile.target.audience,
        t2_jti_sha256=jti_hash(result.claims.jti),
        t2_cached=result.cached,
    )
    call.check_deadline()
    return _scan_and_forward(call, ev, profile, result.token)


def _scan_and_forward(
    call: _Call, ev: InterceptorEvent, profile: GatewayProfile, token: str
) -> tuple[dict[str, Any], Decision, str, str]:
    """Scan the request, then forward with ``token`` and every reserved header overwritten."""
    verdict = "none"
    if ev.request_text:
        outcome = _scan(call, profile, ev.request_text, Direction.REQUEST)
        # Rewriting a user's request is out of scope: anything but ALLOW on a request is a block.
        if outcome.result.verdict is not Verdict.ALLOW:
            raise _Deny(403, "scan_blocked")
        verdict = "unscanned" if outcome.failed_open else "allow"

    headers = {
        "Authorization": f"Bearer {token}",
        "x-atf-request-id": call.request_id,
        "x-atf-decision": "allow",
        "x-atf-scan-verdict": verdict,
    }
    return forward_request(ev, headers=headers), Decision.ALLOW, "ok", "interceptor.request"


def _decide_response(
    call: _Call, ev: InterceptorEvent, profile: GatewayProfile
) -> tuple[dict[str, Any], Decision, str, str]:
    """ADR-0013: may only pass, redact or deny. Never upgrades."""
    if not profile.response_body_scan:
        return pass_response(ev), Decision.ALLOW, "scan_disabled_by_profile", "interceptor.response"
    if ev.response_text is None:
        if ev.shape is Shape.HTTP:
            # Body excluded (payload filter) on a profile that requires scanning.
            outcome = _scan_failure(call, profile, "response_body_missing")
            if outcome.result.verdict is not Verdict.ALLOW:
                raise _Deny(403, "scan_blocked", "interceptor.response")
        return pass_response(ev), Decision.ALLOW, "ok", "interceptor.response"

    outcome = _scan(call, profile, ev.response_text, Direction.RESPONSE)
    verdict = outcome.result.verdict
    if verdict is Verdict.BLOCK:
        raise _Deny(403, "scan_blocked", "interceptor.response")
    if verdict is Verdict.REDACT:
        redacted = outcome.result.redacted_text
        if redacted is None:  # scan_with_policy guarantees this; never rely on assert (-O)
            raise _Deny(403, "redaction_failed", "interceptor.response")
        try:
            output = replace_response_text(ev, redacted)
        except EventError:
            raise _Deny(403, "redaction_failed", "interceptor.response") from None
        return output, Decision.REDACT, "pii_redacted", "interceptor.response"
    return pass_response(ev), Decision.ALLOW, "ok", "interceptor.response"


def _scan(call: _Call, profile: GatewayProfile, text: str, direction: Direction) -> ScanOutcome:
    timeout_s = min(profile.scanner_timeout_ms / 1000, call.remaining_s())
    outcome = scan_with_policy(
        call.deps.scanner,
        text,
        direction=direction,
        failure_mode=profile.scanner_failure_mode,
        timeout_s=timeout_s,
    )
    _record_scan(call, outcome)
    return outcome


def _scan_failure(call: _Call, profile: GatewayProfile, failure: str) -> ScanOutcome:
    outcome = failure_outcome(profile.scanner_failure_mode, failure)
    _record_scan(call, outcome)
    return outcome


def _record_scan(call: _Call, outcome: ScanOutcome) -> None:
    call.fields["scan_verdict"] = outcome.result.verdict.value
    call.fields["scan_categories"] = tuple(sorted(outcome.result.categories))
    if outcome.failed_open:
        call.fields["scanner_failed_open"] = True
        call.extra_events.append(
            AuditEvent(
                event_type="scanner.fail_open",
                request_id=call.request_id,
                decision=Decision.ALLOW,
                reason=outcome.failure or "unknown",
                gateway_id=call.fields.get("gateway_id"),
                profile_id=call.fields.get("profile_id"),
                scanner_failed_open=True,
            )
        )
