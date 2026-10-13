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
from collections.abc import Callable, Mapping
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


def build_publisher(env: Mapping[str, str]) -> BundlePublisher:
    """Env wiring (ADR-0022 §7). Anything invalid raises (cold-start failure).

    ``ATF_REGISTRY_TABLE``, ``ATF_BUNDLE_SIGNING_KEY`` (``arn:aws:kms:...`` or, with
    ``ATF_ENV=local``, ``local:<name>`` under ``ATF_LOCAL_KEYS_DIR``), ``ATF_BUNDLE_ISSUER``,
    ``ATF_GUARDRAILS_PATH``, ``ATF_BUNDLE_DIR`` **or** ``ATF_BUNDLE_S3_BUCKET`` + ``_KEY``,
    ``ATF_BUNDLE_MAX_AGE_S`` (<= 600), ``ATF_BUNDLE_HEARTBEAT_S`` (<= half the max age)."""
    import pathlib

    import boto3

    from atf_agent_registry.store_dynamo import DynamoRegistryStore, ensure_local_table
    from trustkit_aws.s3_bundles import S3BundleSink
    from trustkit_aws.signers import make_signer_factory
    from trustkit_policy.runtime import MAX_AGE_CEILING_S
    from trustkit_policy.sources import FileBundleSink

    table, issuer = env["ATF_REGISTRY_TABLE"], env["ATF_BUNDLE_ISSUER"]
    region = env.get("AWS_REGION", "us-east-1")
    guardrails = pathlib.Path(env["ATF_GUARDRAILS_PATH"]).read_text()
    max_age = int(env.get("ATF_BUNDLE_MAX_AGE_S", str(MAX_AGE_CEILING_S)))
    heartbeat = int(env.get("ATF_BUNDLE_HEARTBEAT_S", str(HEARTBEAT_S)))
    if not 0 < max_age <= MAX_AGE_CEILING_S:
        raise ValueError("bundle max age must be within 1..600 s")
    if not 0 < heartbeat * 2 <= max_age:
        raise ValueError("heartbeat must be at most half the max age (gateways must not go stale)")
    signer = make_signer_factory(env)(env["ATF_BUNDLE_SIGNING_KEY"])

    directory, bucket, key = (
        env.get("ATF_BUNDLE_DIR"),
        env.get("ATF_BUNDLE_S3_BUCKET"),
        env.get("ATF_BUNDLE_S3_KEY"),
    )
    sink: BundleSink
    if directory and not bucket and not key:
        sink = FileBundleSink(pathlib.Path(directory))
    elif bucket and key and not directory:
        sink = S3BundleSink(boto3.client("s3", region_name=region), bucket=bucket, key=key)
    else:
        raise ValueError("bundle sink: set ATF_BUNDLE_DIR or ATF_BUNDLE_S3_BUCKET+KEY")

    ddb = boto3.client("dynamodb", region_name=region)
    if env.get("ATF_ENV") == "local":
        ensure_local_table(ddb, table)
    return BundlePublisher(
        DynamoRegistryStore(ddb, table),
        signer,
        sink,
        guardrails=guardrails,
        issuer=issuer,
        max_age_s=max_age,
        heartbeat_s=heartbeat,
    )


def main() -> int:  # pragma: no cover - process entrypoint; build_publisher is tested
    import os
    import signal

    publisher = build_publisher(dict(os.environ))
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    publisher.run_forever(stop, poll_s=float(os.environ.get("ATF_PUBLISH_POLL_S", "5")))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
