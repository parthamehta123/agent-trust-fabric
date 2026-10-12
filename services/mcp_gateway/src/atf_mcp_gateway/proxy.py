"""MCP data plane: tools/list and tools/call for bound agents (ADR-0017 §1, §3, §5-§7).

The caller is already bound (workload token + T2, ``bind_actor``) by the HTTP shell. Here:

* ``tools/list``: tools of **callable** servers only (approved and digest-matching), named
  ``<server_id>__<tool>``.
* ``tools/call``: the prefix must name a callable server and the tool must be in its pinned
  snapshot. A credential is obtained per the server's delegation mode, the call goes through the
  SSRF-pinned client, and the result is scanned before it is returned.
* Anything else gets JSON-RPC ``-32601``. Every denial is a generic JSON-RPC error. Nothing about
  servers, URLs or credentials leaks to the agent.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Final, Protocol

from atf_mcp_gateway.servers import Delegation, ServerRecord, ServerStore
from trustkit.binding import ActorBinding
from trustkit.profiles import ScannerFailureMode
from trustkit.scanning import ContentScanner, Direction, Verdict, scan_with_policy

NAMESPACE_SEP: Final = "__"
INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL = -32600, -32601, -32602, -32603


class _RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        self.code, self.message = code, message
        super().__init__(message)


class Credentials(Protocol):
    def delegated_token(self, binding: ActorBinding, record: ServerRecord) -> str:
        """RFC 8693 exchange for ``record.audience`` (ADR-0016). Raises on failure."""
        ...

    def server_secret(self, record: ServerRecord) -> str:
        """Resolve ``record.secret_arn``. Raises on failure."""
        ...


class Upstream(Protocol):
    def post_json(
        self, url: str, payload: Mapping[str, Any], *, headers: Mapping[str, str]
    ) -> tuple[int, dict[str, Any] | None]: ...


class McpProxy:
    def __init__(
        self,
        *,
        store: ServerStore,
        upstream: Upstream,
        credentials: Credentials,
        scanner: ContentScanner,
        failure_mode: ScannerFailureMode = ScannerFailureMode.CLOSED,
        scan_timeout_s: float = 0.8,
    ) -> None:
        self._store, self._upstream, self._creds = store, upstream, credentials
        self._scanner, self._mode, self._timeout = scanner, failure_mode, scan_timeout_s

    def handle(self, binding: ActorBinding, request: Mapping[str, Any]) -> dict[str, Any]:
        """One JSON-RPC request in, one JSON-RPC response out. Never raises."""
        rid = _request_id(request)
        try:
            return {"jsonrpc": "2.0", "id": rid, "result": self._dispatch(binding, request)}
        except _RpcError as e:
            return _error(rid, e.code, e.message)
        except Exception:  # noqa: BLE001 - never surface internals to the agent
            return _error(rid, INTERNAL, "internal error")

    def _dispatch(self, binding: ActorBinding, request: Any) -> dict[str, Any]:
        if not isinstance(request, Mapping) or not isinstance(request.get("method"), str):
            raise _RpcError(INVALID_REQUEST, "invalid request")
        method = request["method"]
        if method == "tools/list":
            return {"tools": self._list(binding)}
        if method == "tools/call":
            return self._call(binding, request.get("params"))
        raise _RpcError(METHOD_NOT_FOUND, "method not found")

    def _list(self, binding: ActorBinding) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for record in sorted(self._store.list(), key=lambda r: r.server_id):
            if (
                not record.callable
                or record.current is None
                or not (binding.allowed_scopes & record.scopes)
            ):
                continue
            out.extend(
                {
                    "name": f"{record.server_id}{NAMESPACE_SEP}{t['name']}",
                    "description": t["description"],
                    "inputSchema": t["inputSchema"],
                }
                for t in record.current.tools
            )
        return out

    def _call(self, binding: ActorBinding, params: Any) -> dict[str, Any]:
        if not isinstance(params, Mapping) or not isinstance(params.get("name"), str):
            raise _RpcError(INVALID_PARAMS, "invalid params")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, Mapping):
            raise _RpcError(INVALID_PARAMS, "invalid params")
        server_id, sep, tool = params["name"].partition(NAMESPACE_SEP)
        record = self._store.get(server_id) if sep and server_id and tool else None
        # One error for every "can't route" case, so agents can't enumerate servers or states.
        if (
            record is None
            or NAMESPACE_SEP in tool
            or not record.callable
            or record.current is None
            or tool not in record.current.names()
            or not (binding.allowed_scopes & record.scopes)
        ):
            raise _RpcError(INVALID_PARAMS, "unknown tool")

        try:
            credential = (
                self._creds.delegated_token(binding, record)
                if record.delegation is Delegation.TOKEN
                else self._creds.server_secret(record)
            )
            status, body = self._upstream.post_json(
                record.url,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": dict(arguments)},
                },
                headers={"Authorization": f"Bearer {credential}"},
            )
        except Exception:  # noqa: BLE001 - credential or transport failure
            raise _RpcError(INTERNAL, "tool unavailable") from None
        result = body.get("result") if status == 200 and body is not None else None
        if not isinstance(result, Mapping):
            raise _RpcError(INTERNAL, "tool unavailable")

        outcome = scan_with_policy(
            self._scanner,
            json.dumps(result, sort_keys=True),
            direction=Direction.RESPONSE,
            failure_mode=self._mode,
            timeout_s=self._timeout,
        )
        verdict = outcome.result.verdict
        if verdict is Verdict.BLOCK:
            raise _RpcError(INTERNAL, "tool result blocked")
        if verdict is Verdict.REDACT and outcome.result.redacted_text is not None:
            redacted = json.loads(outcome.result.redacted_text)
            if not isinstance(redacted, dict):
                raise _RpcError(INTERNAL, "tool result blocked")
            return redacted
        return dict(result)


def _request_id(request: Any) -> Any:
    if isinstance(request, Mapping):
        rid = request.get("id")
        if rid is None or (isinstance(rid, (str, int)) and not isinstance(rid, bool)):
            return rid
    return None


def _error(rid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}
