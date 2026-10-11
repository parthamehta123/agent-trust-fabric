"""Hardened httpx adapter for ``trustkit.exchange.TokenEndpoint`` and JWKS fetching (ADR-0011).

* HTTPS URLs only. TLS verification is always on; there is deliberately no parameter to disable it.
* Redirects are never followed. A 3xx from a token or JWKS endpoint is returned as-is (non-200,
  so it becomes a deny).
* Connect and total timeouts.
* Response bodies above ``max_response_bytes`` are discarded unread (``body == {}``).
* JSON is parsed only for ``application/json`` responses whose top level is an object.
* No retries here. Retry policy belongs to the exchanger.
* Connect errors and timeouts raise ``TransportError``. Everything else yields an ``HttpResult``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Final

import httpx

from trustkit.exchange import HttpResult, TransportError

DEFAULT_CONNECT_TIMEOUT_S: Final = 2.0
DEFAULT_TOTAL_TIMEOUT_S: Final = 5.0
DEFAULT_MAX_RESPONSE_BYTES: Final = 65_536


class HttpxTokenEndpoint:
    def __init__(
        self,
        *,
        connect_timeout_s: float = DEFAULT_CONNECT_TIMEOUT_S,
        total_timeout_s: float = DEFAULT_TOTAL_TIMEOUT_S,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """``transport`` exists for tests (``httpx.MockTransport``) only."""
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._max = max_response_bytes
        self._client = httpx.Client(
            timeout=httpx.Timeout(total_timeout_s, connect=connect_timeout_s),
            follow_redirects=False,
            verify=True,
            transport=transport,
            headers={"accept": "application/json"},
        )

    def post_form(self, url: str, form: Mapping[str, str]) -> HttpResult:
        _require_https(url)
        try:
            with self._client.stream("POST", url, data=dict(form)) as resp:
                body = self._read_json_object(resp)
                return HttpResult(resp.status_code, body if body is not None else {})
        except httpx.HTTPError:
            # Dropped cause on purpose: httpx messages can include request details (TM-ING-06).
            raise TransportError("token endpoint unreachable") from None

    def get_json(self, url: str) -> Mapping[str, Any]:
        """For ``JwksKeyResolver.fetch``. Raises ``TransportError`` unless 200 + JSON object."""
        _require_https(url)
        try:
            with self._client.stream("GET", url) as resp:
                body = self._read_json_object(resp)
                status = resp.status_code
        except httpx.HTTPError:
            raise TransportError("endpoint unreachable") from None
        if status != 200 or body is None:
            raise TransportError("unusable response")
        return body

    def close(self) -> None:
        self._client.close()

    def _read_json_object(self, resp: httpx.Response) -> dict[str, Any] | None:
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return None
        declared = resp.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self._max:
            return None
        buf = bytearray()
        for chunk in resp.iter_bytes():
            buf += chunk
            if len(buf) > self._max:
                return None
        try:
            parsed = json.loads(buf)
        except (ValueError, RecursionError):
            return None
        return parsed if isinstance(parsed, dict) else None


def _require_https(url: str) -> None:
    if not url.startswith("https://"):
        raise ValueError("endpoint must be an https URL")
