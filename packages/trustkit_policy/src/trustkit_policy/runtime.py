"""Gateway-side glue for bundles (ADR-0022 §6, ADR-0023): settings, lazy single-flight refresh,
``bind_actor`` policies from grants, Cedar tool decisions, fail-mode combination."""

from __future__ import annotations

import contextlib
import json
import pathlib
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

from trustkit.audit import AuditEvent, AuditSink, Decision
from trustkit.binding import AgentPolicy
from trustkit.exchange import KeyResolverFactory
from trustkit.jwt import TokenValidator, ValidationPolicy, VerifiedToken
from trustkit.profiles import ScannerFailureMode
from trustkit_policy.bundle import BundleHolder, BundleVerifier, LoadedBundle, RefreshOutcome
from trustkit_policy.grants import AgentGrant
from trustkit_policy.pdp import DecisionRequest, PolicyDecision, Resource
from trustkit_policy.schema import Action, ResourceType
from trustkit_policy.sources import BundleSource, FileBundleSource

MAX_AGE_CEILING_S: Final = 600
DEFAULT_REFRESH_S: Final = 60


@dataclass(frozen=True)
class BundleSettings:
    issuer: str
    public_jwk: Mapping[str, str]
    max_age_s: int
    refresh_s: int

    @staticmethod
    def from_env(env: Mapping[str, str]) -> BundleSettings:
        """``ATF_BUNDLE_ISSUER``, ``ATF_BUNDLE_PUBLIC_JWK_PATH`` (pinned key file),
        ``ATF_BUNDLE_MAX_AGE_S`` (default and ceiling 600), ``ATF_BUNDLE_REFRESH_S`` (default
        60, must be < max age). Anything invalid raises ``ValueError`` (cold-start failure)."""
        issuer = env["ATF_BUNDLE_ISSUER"]
        jwk = read_jwk(pathlib.Path(env["ATF_BUNDLE_PUBLIC_JWK_PATH"]))
        max_age = int(env.get("ATF_BUNDLE_MAX_AGE_S", str(MAX_AGE_CEILING_S)))
        refresh = int(env.get("ATF_BUNDLE_REFRESH_S", str(DEFAULT_REFRESH_S)))
        if not 0 < max_age <= MAX_AGE_CEILING_S:
            raise ValueError("bundle max age must be within 1..600 s")
        if not 0 < refresh < max_age:
            raise ValueError("bundle refresh must be positive and shorter than the max age")
        return BundleSettings(issuer, jwk, max_age, refresh)


class BundleGuard:
    """Lazy single-flight refresh: at most one caller refreshes when due; others use the
    current bundle. Staleness is judged on the bundle's own ``iat`` by the holder."""

    def __init__(
        self,
        holder: BundleHolder,
        *,
        refresh_s: int,
        monotonic: Callable[[], float],
        on_outcome: Callable[[RefreshOutcome], None] = lambda _: None,
    ) -> None:
        self._holder, self._refresh_s, self._mono = holder, refresh_s, monotonic
        self._on_outcome = on_outcome
        self._lock = threading.Lock()
        self._last: float | None = None

    def current(self) -> LoadedBundle | None:
        due = self._last is None or self._mono() - self._last >= self._refresh_s
        if due and self._lock.acquire(blocking=False):  # single flight; nobody waits
            try:
                if self._last is None or self._mono() - self._last >= self._refresh_s:
                    outcome = self._holder.refresh()
                    self._last = self._mono()
                    with contextlib.suppress(Exception):  # alerting must never break requests
                        self._on_outcome(outcome)
            finally:
                self._lock.release()
        return self._holder.current()


def actor_policies_from_bundle(
    loaded: LoadedBundle,
    jwks: KeyResolverFactory,
    *,
    scopes_for: Callable[[AgentGrant], frozenset[str]],
    now: Callable[[], int],
) -> dict[str, AgentPolicy]:
    """``{client_id: AgentPolicy}`` for ``bind_actor``: only unexpired grants that have a T2
    binding and a non-empty ``scopes_for(grant)``."""
    t = now()
    out: dict[str, AgentPolicy] = {}
    for agent_id in loaded.bundle.agents:
        grant = loaded.grant(agent_id, t)
        if grant is None or grant.ingress is None:
            continue
        scopes = scopes_for(grant)
        if not scopes:
            continue
        b = grant.ingress
        out[agent_id] = AgentPolicy(
            TokenValidator(
                ValidationPolicy(
                    issuer=b.t2_issuer, audiences=frozenset({b.t2_audience}), expected_typ="at+jwt"
                ),
                jwks(b.t2_jwks_uri),
                now=now,
            ),
            frozenset(scopes),
        )
    return out


def user_scopes(subject_token: VerifiedToken) -> frozenset[str]:
    """The user's delegated entitlements: T2 ``scope`` (space-separated); malformed -> empty."""
    scope = subject_token.claims.get("scope")
    return frozenset(scope.split()) if isinstance(scope, str) else frozenset()


def tool_decision(
    loaded: LoadedBundle,
    *,
    agent_id: str,
    user: str,
    user_scopes: frozenset[str],
    server_id: str,
    delegation: str,
    requested: frozenset[str],
) -> PolicyDecision:
    """Cedar ``invoke_tool``. An empty ``requested`` set is always deny (never ask for nothing)."""
    if not requested:
        return PolicyDecision(allowed=False)
    return loaded.pdp.decide(
        DecisionRequest(
            agent_id=agent_id,
            action=Action.INVOKE_TOOL,
            resource=Resource(ResourceType.MCP_SERVER, server_id, {"delegation": delegation}),
            context={
                "user": user,
                "user_scopes": sorted(user_scopes),
                "scopes": sorted(requested),
            },
        )
    )


def effective_fail_mode(
    profile_mode: ScannerFailureMode, grant_mode: ScannerFailureMode
) -> ScannerFailureMode:
    """Most restrictive wins: open only if both are open."""
    if profile_mode is ScannerFailureMode.OPEN and grant_mode is ScannerFailureMode.OPEN:
        return ScannerFailureMode.OPEN
    return ScannerFailureMode.CLOSED


def read_jwk(path: pathlib.Path) -> Mapping[str, str]:
    """The pinned bundle verification key: a *public* EC JWK (a private key is a config error)."""
    doc = json.loads(path.read_text())
    if not isinstance(doc, dict) or "d" in doc:
        raise ValueError("bundle verification key must be a public JWK")
    return {str(k): str(v) for k, v in doc.items()}


S3Factory = Callable[[str, str], BundleSource]
"""``(bucket, key) -> BundleSource`` (``trustkit_aws.s3_bundles``), injected so this package
stays free of AWS SDK dependencies."""


def policy_from_env(
    env: Mapping[str, str],
    *,
    s3_factory: S3Factory | None = None,
    audit: AuditSink | None = None,
    monotonic: Callable[[], float] | None = None,
) -> Callable[[], LoadedBundle | None]:
    """One wiring for every gateway: settings + source + holder + guard.

    Source: ``ATF_BUNDLE_PATH`` (local, read-only mount) **or** ``ATF_BUNDLE_S3_BUCKET`` +
    ``ATF_BUNDLE_S3_KEY``; both or neither is a cold-start failure. Every refresh outcome except
    ``unchanged`` is audited as ``bundle.refresh`` (rollback and equivocation are alertable)."""
    settings = BundleSettings.from_env(env)
    path, bucket, key = (
        env.get("ATF_BUNDLE_PATH"),
        env.get("ATF_BUNDLE_S3_BUCKET"),
        env.get("ATF_BUNDLE_S3_KEY"),
    )
    source: BundleSource
    if path and not bucket and not key:
        source = FileBundleSource(pathlib.Path(path))
    elif bucket and key and not path and s3_factory is not None:
        source = s3_factory(bucket, key)
    else:
        raise ValueError("bundle source: set ATF_BUNDLE_PATH or ATF_BUNDLE_S3_BUCKET+KEY")
    verifier = BundleVerifier(
        settings.public_jwk, issuer=settings.issuer, max_age_s=settings.max_age_s
    )
    holder = BundleHolder(verifier, source, max_age_s=settings.max_age_s)

    def on_outcome(outcome: RefreshOutcome) -> None:
        if audit is None or outcome is RefreshOutcome.UNCHANGED:
            return
        audit.emit(
            AuditEvent(
                event_type="bundle.refresh",
                request_id=str(uuid.uuid4()),
                decision=Decision.ALLOW if outcome is RefreshOutcome.ACCEPTED else Decision.DENY,
                reason=outcome.value,
            )
        )

    guard = BundleGuard(
        holder,
        refresh_s=settings.refresh_s,
        monotonic=monotonic or time.monotonic,
        on_outcome=on_outcome,
    )
    return guard.current
