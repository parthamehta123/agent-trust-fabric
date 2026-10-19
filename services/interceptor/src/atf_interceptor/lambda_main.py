"""Lambda entrypoint: cold-start wiring for the interceptor (ADR-0015 §5-§6).

Environment:

* ``ATF_ENV``: deployment environment. ``local`` enables ``local:`` signing keys.
* ``ATF_PROFILES_PATH`` or ``ATF_PROFILES_JSON``: gateway profiles (ADR-0026 §13).
* ``ATF_GATEWAY_ID_PARAMETER``: optional SSM parameter holding this Lambda's gateway id
  (ADR-0026 §22). The gateway is created with this Lambda's ARN, so its AWS-assigned id can't be
  inline. When set, the profiles document must hold exactly one profile; the fetched id becomes
  its ``gateway_id`` and is still matched exactly against ``GATEWAY_ARN`` (ADR-0012 §2).
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
import json
import os
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
from trustkit.config import ca_bundle, load_document
from trustkit.exchange import IdJagExchanger
from trustkit.jwt import JwksKeyResolver, KeyResolver, access_token_profile_from_env
from trustkit.profiles import load_profiles
from trustkit.scanning import LocalRulesScanner
from trustkit.signing import KeySigner
from trustkit_aws.s3_bundles import s3_source_factory
from trustkit_aws.signers import make_signer_factory
from trustkit_http.endpoint import HttpxTokenEndpoint
from trustkit_policy.idps import TrustedIdps
from trustkit_policy.runtime import policy_from_env

__all__ = ["bind_gateway_id", "build_handler", "handler", "make_signer_factory"]


SignerFactory = Callable[[str], KeySigner]
ParameterFetch = Callable[[str], str]
"""SSM parameter name -> value (``build_handler`` injects boto3 by default)."""

_GATEWAY_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")


def _ssm_fetch(region: str) -> ParameterFetch:
    def fetch(name: str) -> str:
        import boto3

        value = boto3.client("ssm", region_name=region).get_parameter(Name=name)["Parameter"][
            "Value"
        ]
        return str(value)

    return fetch


def bind_gateway_id(raw: bytes, gateway_id: str) -> bytes:
    """Bind the fetched id into the single profile. Anything unexpected raises (deny-all)."""
    if not _GATEWAY_ID.fullmatch(gateway_id):
        raise ValueError("gateway id parameter is not a gateway id")
    doc = json.loads(raw)
    profiles = doc.get("profiles") if isinstance(doc, dict) else None
    if not isinstance(profiles, list) or len(profiles) != 1 or not isinstance(profiles[0], dict):
        raise ValueError("a parameter-bound gateway id needs exactly one profile")
    profiles[0]["gateway_id"] = gateway_id
    return json.dumps(doc).encode()


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


def build_handler(
    env: Mapping[str, str], *, fetch_parameter: ParameterFetch | None = None
) -> Handler:
    sink = JsonLinesSink(sys.stdout)
    try:
        raw_profiles = load_document(env, "ATF_PROFILES")
        param = env.get("ATF_GATEWAY_ID_PARAMETER")
        if param is not None:
            fetch = fetch_parameter or _ssm_fetch(env.get("AWS_REGION", "us-east-1"))
            raw_profiles = bind_gateway_id(raw_profiles, fetch(param).strip())
        registry = load_profiles(raw_profiles)
        http = HttpxTokenEndpoint(ca_bundle_path=ca_bundle(env))
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
            access_token_profile=access_token_profile_from_env(env),
        )
        # Egress needs the signed policy bundle (ADR-0022). Ingress-only deployments don't set
        # it; without it every egress request is denied (fail closed), never allowed.
        policy = (
            policy_from_env(
                env,
                s3_factory=s3_source_factory(env.get("AWS_REGION", "us-east-1")),
                audit=sink,
            )
            if "ATF_BUNDLE_ISSUER" in env
            else (lambda: None)
        )
        trusted_idps = TrustedIdps.from_env(env) if "ATF_BUNDLE_ISSUER" in env else None
        deps = InterceptorDeps(
            profiles=lambda: registry,
            exchanger=exchanger,
            jwks=jwks,
            scanner=LocalRulesScanner(),  # production scanner adapter: Phase 3
            audit=sink,
            now=lambda: int(time.time()),
            monotonic=time.monotonic,
            policy=policy,
            trusted_idps=trusted_idps,
            access_token_profile=access_token_profile_from_env(env),
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
