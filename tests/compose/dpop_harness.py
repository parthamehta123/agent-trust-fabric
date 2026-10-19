"""Test harness acting as DPoP-capable agents against the running stack (ADR-0028).

The data-plane gateways run in ``required`` mode, and both agents' IdP clients require DPoP, so
the harness behaves exactly like the agents:

* ``mint_bound``: client credentials with DPoP and the IdP's nonce challenge.
* ``DpopTransport``: an ``Authorization: Bearer <token>`` request to a data-plane gateway whose
  token is bound to a key the harness holds is sent as ``DPoP <token>`` with a fresh proof (and
  the gateway's nonce dance). Anything else, such as garbage or unbound tokens that tests send on
  purpose, goes out exactly as written.

The host reaches services on published ports (``localhost:<port>``), but proofs and assertions
must name the URLs the services *believe* they serve (``https://<service>:8443``).
"""

from __future__ import annotations

import base64
import json
import ssl
import threading
import time
from typing import Any, Final

import httpx

from trustkit.dpop import DpopKey
from trustkit.signing import InMemoryEs256Signer, build_client_assertion

ASSERTION: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
IDP_HOST, IDP_CONFIGURED = "https://localhost:9443", "https://mock-idp:8443"
DPOP_CLIENTS: Final = frozenset({"0oa-agent-alpha", "0oa-agent-beta"})
"""Agents whose IdP clients require DPoP (devstack topology)."""
GATEWAYS: Final = {
    "localhost:8444": "https://mcp-gateway:8443",
    "localhost:8445": "https://inference-gateway:8443",
    "localhost:8446": "https://a2a-gateway:8443",
}
"""Published host:port -> the gateway's ATF_PUBLIC_URL (what ``htu`` must name)."""

_KEYS: dict[str, DpopKey] = {}
_BY_JKT: dict[str, DpopKey] = {}
_LOCK = threading.Lock()


def harness_key(client_id: str) -> DpopKey:
    """One in-memory key per agent for the whole session, like a running agent process."""
    with _LOCK:
        if client_id not in _KEYS:
            key = DpopKey()
            _KEYS[client_id], _BY_JKT[key.jkt] = key, key
        return _KEYS[client_id]


def _keys_dir() -> Any:
    from tests.compose.test_mcp_e2e import KEYS

    return KEYS


def mint_bound(
    http: httpx.Client,
    as_path: str,
    client_id: str,
    key_name: str,
    form: dict[str, str],
    dpop: DpopKey | None = None,
) -> tuple[str, int]:
    """Client credentials with DPoP, Okta-style: the first proof is challenged for a nonce and the
    retry (fresh assertion, fresh proof) gets a bound token. Returns ``(token, attempts)``."""
    key = dpop or harness_key(client_id)
    signer = InMemoryEs256Signer((_keys_dir() / f"{key_name}.pem").read_bytes())
    endpoint = f"{IDP_CONFIGURED}{as_path}"
    nonce: str | None = None
    for attempt in (1, 2):
        assertion = build_client_assertion(
            signer, client_id=client_id, token_endpoint=endpoint, now=lambda: int(time.time())
        )
        r = http.post(
            f"{IDP_HOST}{as_path}",
            data={**form, "client_assertion_type": ASSERTION, "client_assertion": assertion},
            headers={"DPoP": key.proof("POST", endpoint, nonce=nonce)},
        )
        if r.status_code == 400 and r.json().get("error") == "use_dpop_nonce":
            nonce = r.headers["dpop-nonce"]
            continue
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["token_type"] == "DPoP"
        return str(body["access_token"]), attempt
    raise AssertionError("IdP kept challenging")


def bound_workload_token(
    http: httpx.Client, client_id: str, key_name: str, dpop: DpopKey, scope: str = "tools.invoke"
) -> tuple[str, int]:
    form = {"grant_type": "client_credentials", "scope": scope}
    return mint_bound(http, "/oauth2/workload/v1/token", client_id, key_name, form, dpop)


def _jkt(token: str) -> str | None:
    try:
        seg = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
        cnf = claims.get("cnf")
        return str(cnf["jkt"]) if isinstance(cnf, dict) and "jkt" in cnf else None
    except (IndexError, ValueError, TypeError):
        return None


class DpopTransport(httpx.BaseTransport):
    """Turns harness-bound ``Bearer`` calls to data-plane gateways into DPoP calls."""

    def __init__(self, inner: httpx.BaseTransport) -> None:
        self._inner = inner
        self._nonces: dict[str, str] = {}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        public = GATEWAYS.get(f"{request.url.host}:{request.url.port}")
        auth = request.headers.get("authorization", "")
        key = (
            _BY_JKT.get(_jkt(auth.removeprefix("Bearer ")) or "")
            if auth.startswith("Bearer ")
            else None
        )
        if public is None or key is None:
            return self._inner.handle_request(request)
        token = auth.removeprefix("Bearer ")
        body = request.read()
        url = f"{public}{request.url.path}"
        response = self._send(request, body, key, token, url, self._nonces.get(public))
        challenged = response.status_code == 401 and "use_dpop_nonce" in response.headers.get(
            "www-authenticate", ""
        )
        if challenged:
            response.read()
            self._nonces[public] = response.headers["dpop-nonce"]
            response.close()
            response = self._send(request, body, key, token, url, self._nonces[public])
        elif "dpop-nonce" in response.headers:
            self._nonces[public] = response.headers["dpop-nonce"]
        return response

    def _send(
        self,
        request: httpx.Request,
        body: bytes,
        key: DpopKey,
        token: str,
        url: str,
        nonce: str | None,
    ) -> httpx.Response:
        headers = httpx.Headers(request.headers)
        headers["authorization"] = f"DPoP {token}"
        headers["dpop"] = key.proof(request.method, url, access_token=token, nonce=nonce)
        return self._inner.handle_request(
            httpx.Request(request.method, request.url, headers=headers, content=body)
        )

    def close(self) -> None:
        self._inner.close()


def harness_client(ca: Any, timeout: float = 15) -> httpx.Client:
    """The stack's CA only, plus DPoP for harness-bound agent tokens."""
    ctx = ssl.create_default_context(cafile=str(ca))
    return httpx.Client(transport=DpopTransport(httpx.HTTPTransport(verify=ctx)), timeout=timeout)


def dpop_request(
    http: httpx.Client,
    method: str,
    *,
    host_url: str,
    public_url: str,
    token: str,
    key: DpopKey,
    nonce: str | None = None,
    **kw: Any,
) -> httpx.Response:
    """One explicit request: ``Authorization: DPoP`` plus a proof for ``public_url``."""
    headers = {
        **kw.pop("headers", {}),
        "Authorization": f"DPoP {token}",
        "DPoP": key.proof(method, public_url, access_token=token, nonce=nonce),
    }
    return http.request(method, host_url, headers=headers, **kw)


def dpop_call(http: httpx.Client, method: str, **kw: Any) -> httpx.Response:
    """``dpop_request`` with the nonce dance: on ``use_dpop_nonce``, retry once with it."""
    r = dpop_request(http, method, **kw)
    if r.status_code == 401 and "use_dpop_nonce" in r.headers.get("www-authenticate", ""):
        r = dpop_request(http, method, nonce=r.headers["dpop-nonce"], **kw)
    return r
