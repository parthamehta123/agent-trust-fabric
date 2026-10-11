"""AgentCore Gateway emulator for HTTP (runtime) targets. TEST INFRASTRUCTURE ONLY (ADR-0014 §3).

Reproduces the *documented* behaviour (ADR-0012 sources) and nothing more:

1. **Inbound JWT authorizer.** ``Authorization: Bearer`` is validated (signature via JWKS,
   ``iss``, ``aud``, ``exp``) before anything else. On failure: 401, interceptor not invoked.
   Independent of ``trustkit`` (joserfc directly), like the mock IdP.
2. **Routing.** ``/{target}/invocations`` -> target. Unknown target: 404.
3. **REQUEST interception.**
   - Event: ``{"interceptorInputVersion": "1.0", "http": {"gatewayRequest": {path, httpMethod,
     headers?, body(base64)}}}``. Headers are included only if ``pass_request_headers``.
   - Client context: ``GATEWAY_ARN``, ``GATEWAY_ACCOUNT_ID``, ``REQUEST_ID`` and optional
     ``SOURCE_IP``.
   - ``transformedGatewayResponse`` short-circuits: returned to the caller, target not called,
     RESPONSE interceptor not run (HTTP-target rule).
4. **Header propagation to the target.**
   - ``Authorization`` comes only from the interceptor output (it is a restricted header).
   - Other headers must be in the target's ``allowed_request_headers``. Client values pass
     through **unless the interceptor sets the same header**, in which case the interceptor wins.
     This is the pessimistic reading of A-5: omission does not remove a client header.
5. **RESPONSE interception (buffered).**
   - Event ``gatewayRequest: null`` + ``gatewayResponse`` {statusCode, headers: null,
     body(base64), contentType}.
   - Output fields override when non-null; ``{"http": {}}`` means pass through.
6. **Interceptor error or malformed output.** Real behaviour is unknown (A-6). The emulator fails
   closed with 502 and records it (see ``emulator-divergences.md``).
"""

from __future__ import annotations

import base64
import binascii
import copy
import re
import time
import uuid
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Final

from joserfc import jwt as jose_jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from trustkit.policy import check_target_allowlist

_ARN: Final = re.compile(
    r"^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:(\d{12}):gateway/[A-Za-z0-9][A-Za-z0-9_-]*$"
)
_PATH: Final = re.compile(r"^/([A-Za-z0-9_-]+)/invocations$")
_BEARER: Final = re.compile(r"^Bearer ([A-Za-z0-9._~+/=-]+)$")

Interceptor = Callable[[Mapping[str, Any], Any], Mapping[str, Any]]


@dataclass(frozen=True)
class TargetResponse:
    status: int
    body: bytes
    content_type: str = "application/json"
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HttpTarget:
    name: str
    invoke: Callable[[Mapping[str, str], bytes], TargetResponse]
    allowed_request_headers: frozenset[str]
    """Validated with ``trustkit.policy.check_target_allowlist`` at emulator construction."""


@dataclass(frozen=True)
class InboundJwt:
    issuer: str
    audiences: frozenset[str]
    jwks: Callable[[], Mapping[str, Any]]


@dataclass(frozen=True)
class GatewayResponse:
    status: int
    body: bytes
    content_type: str = "application/json"


@dataclass(frozen=True)
class RecordedCall:
    """What the emulator observed, for assertions."""

    interceptor_events: list[Mapping[str, Any]]
    target_headers: Mapping[str, str] | None
    target_called: bool


class _InterceptorFailedError(Exception):
    """Interceptor raised or returned malformed output (real behaviour unknown: A-6)."""


@dataclass
class GatewayEmulator:
    gateway_arn: str
    inbound: InboundJwt
    targets: Mapping[str, HttpTarget]
    interceptor: Interceptor | None = None
    interception_points: frozenset[str] = frozenset({"REQUEST", "RESPONSE"})
    pass_request_headers: bool = True
    now: Callable[[], int] = lambda: int(time.time())
    calls: deque[RecordedCall] = field(default_factory=lambda: deque(maxlen=256), repr=False)

    def __post_init__(self) -> None:
        """Validate every target's allowlist (ADR-0014 §5) and the ARN shape."""
        m = _ARN.fullmatch(self.gateway_arn)
        if m is None:
            raise ValueError("invalid gateway arn")
        self._account_id = m.group(1)
        for target in self.targets.values():
            check_target_allowlist(target.allowed_request_headers)

    def invoke(
        self,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        *,
        source_ip: str | None = None,
    ) -> GatewayResponse:
        events: list[Mapping[str, Any]] = []
        record: dict[str, Any] = {"target_headers": None, "target_called": False}
        try:
            return self._invoke(path, headers, body, source_ip, events, record)
        finally:
            self.calls.append(
                RecordedCall(events, record["target_headers"], record["target_called"])
            )

    # ---------------------------------------------------------------------------------- flow

    def _invoke(
        self,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        source_ip: str | None,
        events: list[Mapping[str, Any]],
        record: dict[str, Any],
    ) -> GatewayResponse:
        if not self._inbound_ok(headers):
            return GatewayResponse(401, b'{"message": "Unauthorized"}')
        m = _PATH.fullmatch(path)
        target = self.targets.get(m.group(1)) if m else None
        if target is None:
            return GatewayResponse(404, b'{"message": "Not Found"}')

        custom = {
            "GATEWAY_ARN": self.gateway_arn,
            "GATEWAY_ACCOUNT_ID": self._account_id,
            "REQUEST_ID": uuid.uuid4().hex,
        }
        if source_ip is not None:
            custom["SOURCE_IP"] = source_ip
        context = SimpleNamespace(
            client_context=SimpleNamespace(custom=custom),
            aws_request_id=custom["REQUEST_ID"],
            get_remaining_time_in_millis=lambda: 30_000,
        )

        intercept_request = self.interceptor is not None and "REQUEST" in self.interception_points
        transformed: Mapping[str, Any] = {}
        if intercept_request:
            gateway_request: dict[str, Any] = {
                "path": path,
                "httpMethod": "POST",
                "body": base64.b64encode(body).decode(),
            }
            if self.pass_request_headers:
                gateway_request["headers"] = dict(headers)
            event = {"interceptorInputVersion": "1.0", "http": {"gatewayRequest": gateway_request}}
            try:
                out = self._intercept(event, context, events)
                short_circuit = out.get("transformedGatewayResponse")
                if short_circuit is not None:
                    # HTTP-target rule: no target call, no RESPONSE interception.
                    return self._apply_override(short_circuit, None)
                transformed = _mapping_or_fail(out.get("transformedGatewayRequest") or {})
            except _InterceptorFailedError:
                return GatewayResponse(502, b'{"message": "Bad Gateway"}')

        try:
            target_headers = self._propagate(headers, transformed, target)
            raw_body = transformed.get("body")
            target_body = _b64_or_fail(raw_body) if raw_body is not None else body
        except _InterceptorFailedError:
            return GatewayResponse(502, b'{"message": "Bad Gateway"}')
        record["target_headers"], record["target_called"] = target_headers, True
        result = target.invoke(target_headers, target_body)
        response = GatewayResponse(result.status, result.body, result.content_type)

        if self.interceptor is not None and "RESPONSE" in self.interception_points:
            event = {
                "interceptorInputVersion": "1.0",
                "http": {
                    "gatewayRequest": None,
                    "gatewayResponse": {
                        "statusCode": result.status,
                        "headers": None,
                        "body": base64.b64encode(result.body).decode(),
                        "contentType": result.content_type,
                    },
                },
            }
            try:
                out = self._intercept(event, context, events)
                override = out.get("transformedGatewayResponse")
                if override is not None:
                    response = self._apply_override(override, response)
            except _InterceptorFailedError:
                return GatewayResponse(502, b'{"message": "Bad Gateway"}')
        return response

    # ---------------------------------------------------------------------------------- pieces

    def _inbound_ok(self, headers: Mapping[str, str]) -> bool:
        values = [v for k, v in headers.items() if k.lower() == "authorization"]
        if len(values) != 1:
            return False
        m = _BEARER.fullmatch(values[0])
        if m is None:
            return False
        try:
            keys = KeySet.import_key_set(dict(self.inbound.jwks()))  # type: ignore[arg-type]
            claims = jose_jwt.decode(m.group(1), keys, algorithms=["RS256", "ES256"]).claims
        except (JoseError, ValueError, TypeError, KeyError):
            return False
        aud = claims.get("aud")
        auds = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) else set()
        exp = claims.get("exp")
        return (
            claims.get("iss") == self.inbound.issuer
            and bool(auds & self.inbound.audiences)
            and isinstance(exp, int)
            and self.now() <= exp
        )

    def _intercept(
        self, event: Mapping[str, Any], context: Any, events: list[Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        events.append(copy.deepcopy(event))
        assert self.interceptor is not None  # noqa: S101 - test infrastructure
        try:
            out = self.interceptor(event, context)
        except Exception as e:
            raise _InterceptorFailedError from e
        if not isinstance(out, Mapping) or out.get("interceptorOutputVersion") != "1.0":
            raise _InterceptorFailedError
        return _mapping_or_fail(out.get("http"))

    @staticmethod
    def _propagate(
        client: Mapping[str, str], transformed: Mapping[str, Any], target: HttpTarget
    ) -> dict[str, str]:
        allowed = {h.lower() for h in target.allowed_request_headers}
        merged: dict[str, tuple[str, str]] = {}
        for k, v in client.items():
            if k.lower() in allowed:  # client value survives unless the interceptor overrides
                merged[k.lower()] = (k, v)
        icpt = transformed.get("headers") or {}
        if not isinstance(icpt, Mapping):
            raise _InterceptorFailedError
        for k, v in icpt.items():
            if k.lower() == "authorization" or k.lower() in allowed:
                merged[k.lower()] = (k, v)
        return dict(merged.values())

    @staticmethod
    def _apply_override(override: Any, original: GatewayResponse | None) -> GatewayResponse:
        o = _mapping_or_fail(override)
        status = o.get("statusCode")
        if status is None and original is None:
            raise _InterceptorFailedError
        body_b64 = o.get("body")
        return GatewayResponse(
            status=int(status) if status is not None else original.status,  # type: ignore[union-attr]
            body=_b64_or_fail(body_b64)
            if body_b64 is not None
            else (original.body if original else b""),
            content_type=o.get("contentType")
            or (original.content_type if original else "application/json"),
        )


def _mapping_or_fail(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _InterceptorFailedError
    return value


def _b64_or_fail(value: Any) -> bytes:
    if not isinstance(value, str):
        raise _InterceptorFailedError
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise _InterceptorFailedError from None
