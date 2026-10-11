"""AgentCore Gateway interceptor event adapters (ADR-0012 §1).

Two payload shapes, normalised into one model:

* ``mcp``: JSON-RPC body as a parsed object; also includes ``rawGatewayRequest``.
* ``http``: AgentCore Runtime, passthrough and inference targets; bodies are **base64** strings;
  HTTP RESPONSE events carry ``gatewayRequest: null``.

Parsing is strict. Anything unexpected raises ``EventError``, and the handler turns that into a
deny:

* wrong version
* both or neither shape keys
* wrong field types
* undecodable base64

Output builders never echo caller headers back. They emit exactly what the handler decided.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

INTERCEPTOR_VERSION: Final = "1.0"
_GATEWAY_ARN: Final = re.compile(
    r"^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:\d{12}:gateway/([A-Za-z0-9][A-Za-z0-9_-]{0,99})$"
)
_SAFE_REQUEST_ID: Final = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class Shape(StrEnum):
    MCP = "mcp"
    HTTP = "http"


class Phase(StrEnum):
    REQUEST = "request"
    RESPONSE = "response"


class EventError(Exception):
    """Malformed or unexpected interceptor event. Log-safe."""


@dataclass(frozen=True)
class Headers:
    """Case-insensitive, read-only view of request headers."""

    _items: Mapping[str, str] = field(repr=False)

    def get(self, name: str) -> str | None:
        return self._items.get(name.lower())

    @classmethod
    def parse(cls, raw: Any) -> Headers | None:
        if raw is None:
            return None
        if not isinstance(raw, Mapping):
            raise EventError("headers must be an object")
        items: dict[str, str] = {}
        for k, v in raw.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise EventError("header names and values must be strings")
            if k.lower() in items:
                raise EventError("duplicate header (case-insensitive)")
            items[k.lower()] = v
        return cls(items)


@dataclass(frozen=True)
class InterceptorEvent:
    shape: Shape
    phase: Phase
    headers: Headers | None
    """``None`` when the interceptor is configured with ``passRequestHeaders: false``."""
    request_body: Any = field(repr=False)
    """Original request body, echoed back unchanged (dict for mcp, base64 str for http, or
    None)."""
    request_text: str | None = field(repr=False)
    """Request body as text, for scanning (mcp: canonical JSON; http: decoded UTF-8)."""
    jsonrpc_id: Any = None
    """MCP request id, echoed in JSON-RPC error responses."""
    response_status: int | None = None
    response_body: Any = field(default=None, repr=False)
    response_text: str | None = field(default=None, repr=False)


def _mapping(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EventError(f"{what} must be an object")
    return value


def _status(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 100 <= value <= 599:
        raise EventError("statusCode must be an HTTP status")
    return value


def _b64_text(value: Any, what: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EventError(f"{what} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        raise EventError(f"{what} is not valid base64") from None


def _json_text(value: Any, what: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise EventError(f"{what} must be a JSON object")
    return json.dumps(value, sort_keys=True)


def parse_event(event: Mapping[str, Any]) -> InterceptorEvent:
    top = _mapping(event, "event")
    if top.get("interceptorInputVersion") != INTERCEPTOR_VERSION:
        raise EventError("unsupported interceptorInputVersion")
    present = [s for s in Shape if s.value in top]
    if len(present) != 1:
        raise EventError("event must contain exactly one of mcp/http")
    shape = present[0]
    body = _mapping(top[shape.value], shape.value)

    raw_response = body.get("gatewayResponse")
    phase = Phase.RESPONSE if raw_response is not None else Phase.REQUEST

    raw_request = body.get("gatewayRequest")
    if raw_request is None and not (phase is Phase.RESPONSE and shape is Shape.HTTP):
        raise EventError("gatewayRequest missing")
    request = _mapping(raw_request, "gatewayRequest") if raw_request is not None else {}

    headers = Headers.parse(request.get("headers"))
    request_body = request.get("body")
    if shape is Shape.MCP:
        request_text = _json_text(request_body, "request body")
        jsonrpc_id = request_body.get("id") if isinstance(request_body, Mapping) else None
    else:
        request_text = _b64_text(request_body, "request body")
        jsonrpc_id = None

    status: int | None = None
    response_body: Any = None
    response_text: str | None = None
    if phase is Phase.RESPONSE:
        response = _mapping(raw_response, "gatewayResponse")
        status = _status(response.get("statusCode"))
        response_body = response.get("body")
        response_text = (
            _json_text(response_body, "response body")
            if shape is Shape.MCP
            else _b64_text(response_body, "response body")
        )

    return InterceptorEvent(
        shape=shape,
        phase=phase,
        headers=headers,
        request_body=request_body,
        request_text=request_text,
        jsonrpc_id=jsonrpc_id,
        response_status=status,
        response_body=response_body,
        response_text=response_text,
    )


def _custom(context: Any) -> Mapping[str, Any]:
    custom = getattr(getattr(context, "client_context", None), "custom", None)
    return custom if isinstance(custom, Mapping) else {}


def gateway_id_from_context(context: Any) -> str | None:
    """``GATEWAY_ARN`` from the Lambda client context -> gateway id, or None.

    Expected ARN form: ``arn:aws:bedrock-agentcore:<region>:<account>:gateway/<id>``; anything
    else gives None. Never reads the event body or headers (TM-ING-04).
    """
    arn = _custom(context).get("GATEWAY_ARN")
    if not isinstance(arn, str):
        return None
    m = _GATEWAY_ARN.fullmatch(arn)
    return m.group(1) if m else None


def request_id_from_context(context: Any) -> str:
    """``REQUEST_ID`` from client context, else Lambda ``aws_request_id``, else ``unknown``."""
    for candidate in (_custom(context).get("REQUEST_ID"), getattr(context, "aws_request_id", None)):
        if isinstance(candidate, str) and _SAFE_REQUEST_ID.fullmatch(candidate):
            return candidate
    return "unknown"


def _out(shape: Shape, payload: dict[str, Any]) -> dict[str, Any]:
    return {"interceptorOutputVersion": INTERCEPTOR_VERSION, shape.value: payload}


def forward_request(ev: InterceptorEvent, *, headers: Mapping[str, str]) -> dict[str, Any]:
    """REQUEST output: call the target with exactly ``headers`` and the original body."""
    return _out(
        ev.shape,
        {"transformedGatewayRequest": {"headers": dict(headers), "body": ev.request_body}},
    )


def deny(shape: Shape, *, status: int, request_id: str, jsonrpc_id: Any = None) -> dict[str, Any]:
    """Short-circuit output with a generic error body that carries only ``request_id``."""
    if shape is Shape.MCP:
        body: Any = {
            "jsonrpc": "2.0",
            "id": jsonrpc_id,
            "error": {
                "code": -32000,
                "message": "request denied",
                "data": {"request_id": request_id},
            },
        }
        return _out(shape, {"transformedGatewayResponse": {"statusCode": status, "body": body}})
    payload = json.dumps({"error": "request_denied", "request_id": request_id}).encode()
    return _out(
        shape,
        {
            "transformedGatewayResponse": {
                "statusCode": status,
                "contentType": "application/json",
                "body": base64.b64encode(payload).decode(),
            }
        },
    )


def pass_response(ev: InterceptorEvent) -> dict[str, Any]:
    """RESPONSE output: return the target's response unchanged."""
    if ev.shape is Shape.HTTP:
        return _out(ev.shape, {})
    return _out(
        ev.shape,
        {
            "transformedGatewayResponse": {
                "statusCode": ev.response_status,
                "body": ev.response_body,
            }
        },
    )


def replace_response_text(ev: InterceptorEvent, text: str) -> dict[str, Any]:
    """RESPONSE output: same status, body replaced by ``text`` (redaction).

    MCP: the JSON object parsed from ``text``. HTTP: base64 of ``text``.
    """
    if ev.shape is Shape.MCP:
        try:
            body: Any = json.loads(text)
        except ValueError:
            raise EventError("redacted MCP body is not JSON") from None
    else:
        body = base64.b64encode(text.encode("utf-8")).decode()
    return _out(
        ev.shape, {"transformedGatewayResponse": {"statusCode": ev.response_status, "body": body}}
    )
