"""Lambda entrypoint: cold-start wiring for the interceptor (ADR-0015 §5-§6).

Environment:

* ``ATF_ENV``: deployment environment. ``local`` enables ``local:`` signing keys.
* ``ATF_PROFILES_PATH``: gateway profiles JSON (Phase 6: SSM-backed source).
* ``ATF_CA_BUNDLE``: optional. Restricts outbound TLS trust (local stack only).
* ``ATF_LOCAL_KEYS_DIR``: directory of ``<name>.pem`` for ``local:<name>`` refs. Honoured only
  when ``ATF_ENV=local``.
* ``AWS_REGION``: for KMS signers.

``build_handler(env)`` never raises. If wiring fails, it returns a handler that denies every
request (503) and emits ``config.invalid``. The module-level ``handler`` is what the Lambda
runtime calls.
"""

from __future__ import annotations

import contextlib
import os
import pathlib
import re
import sys
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any, Final

from atf_interceptor.events import Shape, deny, request_id_from_context
from atf_interceptor.handler import Handler, InterceptorDeps, make_handler
from trustkit.audit import AuditEvent, AuditSink, Decision, JsonLinesSink
from trustkit.breaker import BreakerRegistry, CircuitState
from trustkit.exchange import IdJagExchanger
from trustkit.jwt import JwksKeyResolver, KeyResolver
from trustkit.profiles import load_profiles
from trustkit.scanning import LocalRulesScanner
from trustkit.signing import InMemoryEs256Signer, KeySigner, SigningError
from trustkit_http.endpoint import HttpxTokenEndpoint

_LOCAL_NAME: Final = re.compile(r"^[a-z0-9-]{1,64}$")
_KMS_ARN: Final = re.compile(r"^arn:aws:kms:([a-z0-9-]+):\d{12}:key/[0-9a-f-]{36}$")

SignerFactory = Callable[[str], KeySigner]


def make_signer_factory(env: Mapping[str, str]) -> SignerFactory:
    """``arn:aws:kms:...`` -> KMS signer. ``local:<name>`` -> in-memory signer (local only).

    Signers are memoised per reference. Unknown or disallowed references raise ``SigningError``.
    """
    cache: dict[str, KeySigner] = {}
    lock = threading.Lock()
    local_allowed = env.get("ATF_ENV") == "local"
    keys_dir = env.get("ATF_LOCAL_KEYS_DIR")

    def build(ref: str) -> KeySigner:
        if (m := _KMS_ARN.fullmatch(ref)) is not None:
            import boto3  # lazy: keeps cold start lean when only local keys are used

            from trustkit_aws.kms import KmsEs256Signer

            return KmsEs256Signer(boto3.client("kms", region_name=m.group(1)), ref)
        if ref.startswith("local:"):
            if not local_allowed:
                raise SigningError("local signing keys are disabled outside ATF_ENV=local")
            name = ref.removeprefix("local:")
            if not _LOCAL_NAME.fullmatch(name) or not keys_dir:
                raise SigningError("invalid local key reference")
            try:
                pem = (pathlib.Path(keys_dir) / f"{name}.pem").read_bytes()
            except (OSError, ValueError):
                raise SigningError("local signing key unavailable") from None
            signer = InMemoryEs256Signer(pem)
            _ = signer.key_id  # load + validate now: fail at first use, not mid-request
            return signer
        raise SigningError("unsupported key reference")

    def factory(ref: str) -> KeySigner:
        with lock:
            if ref not in cache:
                cache[ref] = build(ref)
            return cache[ref]

    return factory


def _deny_all(sink: AuditSink) -> Handler:
    """Cold start failed: deny everything, say so in audit, never raise (ADR-0015 §6)."""

    def handler(event: Mapping[str, Any], context: Any) -> dict[str, Any]:
        request_id = request_id_from_context(context)
        with contextlib.suppress(Exception):
            sink.emit(
                AuditEvent(
                    event_type="config.invalid",
                    request_id=request_id,
                    decision=Decision.DENY,
                    reason="cold_start_failed",
                )
            )
        shape = Shape.MCP if isinstance(event, Mapping) and "mcp" in event else Shape.HTTP
        return deny(shape, status=503, request_id=request_id)

    return handler


def build_handler(env: Mapping[str, str]) -> Handler:
    sink = JsonLinesSink(sys.stdout)
    try:
        registry = load_profiles(pathlib.Path(env["ATF_PROFILES_PATH"]).read_bytes())
        http = HttpxTokenEndpoint(ca_bundle_path=env.get("ATF_CA_BUNDLE"))
        resolvers: dict[str, KeyResolver] = {}

        def jwks(uri: str) -> KeyResolver:
            if uri not in resolvers:
                resolvers[uri] = JwksKeyResolver(fetch=lambda: http.get_json(uri))
            return resolvers[uri]

        def on_transition(name: str, old: CircuitState, new: CircuitState) -> None:
            sink.emit(
                AuditEvent(
                    event_type="breaker.transition",
                    request_id="breaker",
                    decision=Decision.DENY if new is CircuitState.OPEN else Decision.ALLOW,
                    reason=f"{old.value}->{new.value}",
                )
            )

        exchanger = IdJagExchanger(
            http=http,
            signers=make_signer_factory(env),
            jwks=jwks,
            breakers=BreakerRegistry(on_transition=on_transition),
        )
        deps = InterceptorDeps(
            profiles=lambda: registry,
            exchanger=exchanger,
            jwks=jwks,
            scanner=LocalRulesScanner(),  # production scanner adapter: Phase 3
            audit=sink,
            now=lambda: int(time.time()),
            monotonic=time.monotonic,
        )
        return make_handler(deps)
    except Exception:  # noqa: BLE001 - any wiring failure -> deny-all handler (fail closed)
        return _deny_all(sink)


_handler: Handler | None = None
_handler_lock = threading.Lock()


def handler(event: Mapping[str, Any], context: Any) -> dict[str, Any]:
    """Lambda entrypoint. Wiring happens once, on the first (cold-start) invocation."""
    global _handler
    with _handler_lock:
        if _handler is None:
            _handler = build_handler(os.environ)
    return _handler(event, context)
