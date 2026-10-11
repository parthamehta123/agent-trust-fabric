"""Reference agent runtime: the `/invocations` endpoint an AgentCore Runtime exposes.

Security contract (ADR-0014 §1, TM-RT-01/02):

* Every invocation is authorized from ``Authorization: Bearer <T2>`` via ``ResourceAuthorizer``
  with the ``agent.invoke`` scope. Nothing else confers identity or permission.
* ``x-atf-*`` headers are advisory. The runtime reads ``x-atf-request-id`` only for log
  correlation, and never for authorization.
* Errors are generic (RFC 6750 challenge on 401/403). Bodies never echo tokens or claims.
* The request body must be a JSON object of at most ``max_body_bytes``. Anything else gives 400/413.

The "agent" itself is an injected callable, so the trust boundary can be tested without a model.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from trustkit.resource import AuthzFailure, Principal, ResourceAuthorizer, ResourceAuthzError

DEFAULT_REQUIRED_SCOPE: Final = "agent.invoke"
DEFAULT_MAX_BODY_BYTES: Final = 262_144

Agent = Callable[[Principal, Mapping[str, Any]], Mapping[str, Any]]
"""(authorized principal, request JSON) -> response JSON."""


@dataclass(frozen=True)
class InvocationResult:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass
class AgentRuntime:
    authorizer: ResourceAuthorizer
    agent: Agent
    required_scope: str = DEFAULT_REQUIRED_SCOPE
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    principals_seen: list[Principal] = field(default_factory=list, repr=False)
    """Test observability: the principal of every *authorized* invocation."""

    def invoke(self, headers: Mapping[str, str], body: bytes) -> InvocationResult:
        auth_values = [v for k, v in headers.items() if k.lower() == "authorization"]
        if len(auth_values) > 1:  # ambiguous credentials (case-variant duplicates): never pick one
            return _deny(ResourceAuthzError(AuthzFailure.INVALID_TOKEN))
        try:
            principal = self.authorizer.authorize(
                auth_values[0] if auth_values else None, required_scope=self.required_scope
            )
        except ResourceAuthzError as e:
            return _deny(e)

        # Body handling only after authorization: no parser oracle for unauthenticated callers.
        if len(body) > self.max_body_bytes:
            return _json(413, {"error": "payload_too_large"})
        try:
            request = json.loads(body)
        except (ValueError, RecursionError):
            request = None
        if not isinstance(request, dict):
            return _json(400, {"error": "bad_request"})

        self.principals_seen.append(principal)
        try:
            output = self.agent(principal, request)
        except Exception:  # noqa: BLE001 - agent failures never leak details to the caller
            return _json(500, {"error": "internal_error"})
        return _json(200, dict(output))


def _deny(e: ResourceAuthzError) -> InvocationResult:
    error = "forbidden" if e.status == 403 else "unauthorized"
    return _json(e.status, {"error": error}, {"WWW-Authenticate": e.www_authenticate})


def _json(
    status: int, body: Mapping[str, Any], extra_headers: Mapping[str, str] | None = None
) -> InvocationResult:
    headers = {"Content-Type": "application/json", **(extra_headers or {})}
    return InvocationResult(status, headers, json.dumps(body).encode())
