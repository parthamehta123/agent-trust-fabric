"""Bundle publisher (ADR-0022 §7): the only holder of the bundle-signing key.

Reads approved, unexpired records; generates permits; appends the platform guardrails; refuses
to publish anything that fails schema validation; signs; writes through a ``BundleSink``.
Publishes on change and at least every ``heartbeat_s`` seconds.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import threading
from collections.abc import Callable
from typing import Final

from atf_agent_registry.records import (
    AgentVersion,
    RegistryStore,
    State,
    StoreUnavailableError,
    canonical_spec_json,
)
from trustkit.signing import KeySigner, SigningError
from trustkit_policy.bundle import MAX_AGE_S, Bundle, sign_bundle
from trustkit_policy.grants import AgentGrant, generate_permits
from trustkit_policy.pdp import CedarPdp, PolicyConfigError
from trustkit_policy.sources import BundleSink

HEARTBEAT_S: Final = 300


class PublishError(Exception):
    """Nothing was published (invalid policies, store or sink failure). Message is log-safe."""


def to_grant(v: AgentVersion) -> AgentGrant:
    """Map an approved record to the grant gateways enforce (every security field carried)."""
    spec = json.loads(canonical_spec_json(v.spec))
    for presentation_only in ("display_name", "description"):
        spec.pop(presentation_only)
    spec["agent_id"], spec["record_version"] = v.agent_id, v.version
    if v.expires_at is not None:
        spec["expires_at"] = int(v.expires_at.timestamp())
    return AgentGrant.model_validate_json(json.dumps(spec))


class BundlePublisher:
    def __init__(
        self,
        store: RegistryStore,
        signer: KeySigner,
        sink: BundleSink,
        *,
        guardrails: str,
        issuer: str,
        max_age_s: int = MAX_AGE_S,
        heartbeat_s: int = HEARTBEAT_S,
        now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC),
    ) -> None:
        self._store, self._signer, self._sink = store, signer, sink
        self._guardrails, self._issuer = guardrails, issuer
        self._max_age, self._heartbeat, self._now = max_age_s, heartbeat_s, now
        self._last_digest: str | None = None
        self._last_at: dt.datetime | None = None

    def _effective(self) -> dict[str, AgentGrant]:
        now = self._now()
        grants: dict[str, AgentGrant] = {}
        for agent_id in self._store.agent_ids():
            approved = [v for v in self._store.versions(agent_id) if v.state is State.APPROVED]
            if not approved:
                continue
            v = approved[-1]
            if v.expires_at is not None and now >= v.expires_at:
                continue
            grants[agent_id] = to_grant(v)
        return grants

    def _content(self) -> tuple[dict[str, AgentGrant], str, str]:
        grants = self._effective()
        policies = generate_permits(grants) + "\n" + self._guardrails
        try:
            CedarPdp(policies, grants)  # refuse to publish what gateways would refuse to load
        except PolicyConfigError:
            raise PublishError("policies fail schema validation") from None
        digest = hashlib.sha256(
            json.dumps(
                {k: json.loads(g.model_dump_json()) for k, g in sorted(grants.items())},
                sort_keys=True,
                default=sorted,
            ).encode()
            + policies.encode()
        ).hexdigest()
        return grants, policies, digest

    def build(self) -> Bundle:
        """Unsigned bundle with a fresh version. ``PublishError`` if policies don't validate."""
        try:
            grants, policies, _ = self._content()
            version = self._store.next_bundle_version()
        except StoreUnavailableError:
            raise PublishError("registry store unavailable") from None
        iat = int(self._now().timestamp())
        return Bundle(
            iss=self._issuer,
            bundle_version=version,
            iat=iat,
            exp=iat + self._max_age,
            agents=grants,
            policies=policies,
        )

    def publish(self) -> int:
        """Build, sign, write. Returns the published version."""
        bundle = self.build()
        try:
            token = sign_bundle(bundle, self._signer)
            self._sink.publish(token)
        except (SigningError, OSError, Exception) as e:  # noqa: BLE001 - nothing published
            raise PublishError(f"publish failed: {type(e).__name__}") from None
        return bundle.bundle_version

    def tick(self) -> int | None:
        """Publish if the effective content changed or the heartbeat is due; else ``None``."""
        try:
            _, _, digest = self._content()
        except (PublishError, StoreUnavailableError):
            return None
        now = self._now()
        due = self._last_at is None or (now - self._last_at).total_seconds() >= self._heartbeat
        if digest == self._last_digest and not due:
            return None
        try:
            version = self.publish()
        except PublishError:
            return None  # retried on the next tick
        self._last_digest, self._last_at = digest, now
        return version

    def run_forever(self, stop: threading.Event, poll_s: float = 5.0) -> None:
        while not stop.is_set():
            self.tick()
            stop.wait(poll_s)
