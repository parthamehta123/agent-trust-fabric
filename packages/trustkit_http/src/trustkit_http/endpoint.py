"""Hardened httpx adapter for ``trustkit.exchange.TokenEndpoint`` and JWKS fetching (ADR-0011).

* HTTPS URLs only. TLS verification is always on; there is deliberately no parameter to disable it.
* Redirects are never followed. A 3xx from a token or JWKS endpoint is returned as-is (non-200,
  so it becomes a deny).
* Connect and total timeouts.
* Response bodies above ``max_response_bytes`` are discarded unread (``body == {}``).
* JSON is parsed only for ``application/json`` responses whose top level is an object (a JWKS may
  also be ``application/jwk-set+json``, RFC 7517 §8.5).
* No retries here. Retry policy belongs to the exchanger.
* Connect errors and timeouts raise ``TransportError``. Everything else yields an ``HttpResult``.
"""

from __future__ import annotations

import json
import ssl
from collections.abc import Mapping
from typing import Any, Final

import httpx

from trustkit.exchange import HttpResult, TransportError

DEFAULT_CONNECT_TIMEOUT_S: Final = 2.0
DEFAULT_TOTAL_TIMEOUT_S: Final = 5.0
DEFAULT_MAX_RESPONSE_BYTES: Final = 65_536
JSON: Final = frozenset({"application/json"})
JWKS_TYPES: Final = frozenset({"application/json", "application/jwk-set+json"})


def tls_context(ca_bundle_path: str | None) -> ssl.SSLContext | bool:
    """Verification is always on. With a bundle, *only* that bundle is trusted (ADR-0015 §4)."""
    if ca_bundle_path is None:
        return True
    try:
        # create_default_context(cafile=...) skips the system store: trust is narrowed, not widened.
        return ssl.create_default_context(cafile=ca_bundle_path)
    except (OSError, ssl.SSLError, ValueError):
        raise ValueError("ca bundle unusable") from None


class HttpxTokenEndpoint:
    def __init__(
        self,
        *,
        connect_timeout_s: float = DEFAULT_CONNECT_TIMEOUT_S,
        total_timeout_s: float = DEFAULT_TOTAL_TIMEOUT_S,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        ca_bundle_path: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """``ca_bundle_path`` *narrows* trust to one CA bundle (ADR-0015 §4); it can never disable
        verification. ``transport`` exists for tests (``httpx.MockTransport``) only."""
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._max = max_response_bytes
        self._client = httpx.Client(
            timeout=httpx.Timeout(total_timeout_s, connect=connect_timeout_s),
            follow_redirects=False,
            verify=tls_context(ca_bundle_path),
            transport=transport,
            headers={"accept": "application/json"},
        )

    def post_form(
        self, url: str, form: Mapping[str, str], *, headers: Mapping[str, str] | None = None
    ) -> HttpResult:
        """``headers`` is for ``DPoP`` only (ADR-0028); nothing else is sent to a token endpoint."""
        _require_https(url)
        extra = {k: v for k, v in (headers or {}).items() if k.lower() == "dpop"}
        try:
            with self._client.stream("POST", url, data=dict(form), headers=extra) as resp:
                body = self._read_json_object(resp)
                nonce = resp.headers.get("dpop-nonce")
                return HttpResult(
                    resp.status_code, body if body is not None else {}, dpop_nonce=nonce
                )
        except httpx.HTTPError:
            # Dropped cause on purpose: httpx messages can include request details (TM-ING-06).
            raise TransportError("token endpoint unreachable") from None

    def get_json(self, url: str) -> Mapping[str, Any]:
        """For ``JwksKeyResolver.fetch``. Raises ``TransportError`` unless 200 + JSON object."""
        _require_https(url)
        try:
            with self._client.stream(
                "GET", url, headers={"accept": ", ".join(sorted(JWKS_TYPES))}
            ) as resp:
                body = self._read_json_object(resp, JWKS_TYPES)
                status = resp.status_code
        except httpx.HTTPError:
            raise TransportError("endpoint unreachable") from None
        if status != 200 or body is None:
            raise TransportError("unusable response")
        return body

    def close(self) -> None:
        self._client.close()

    def _read_json_object(
        self, resp: httpx.Response, accept: frozenset[str] = JSON
    ) -> dict[str, Any] | None:
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype not in accept:
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
