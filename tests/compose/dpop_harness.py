"""Test harness acting as a DPoP-capable agent against the running stack (ADR-0028).

The host reaches services on published ports (``localhost:<port>``), but proofs and client
assertions must name the URLs the services *believe* they serve (``https://<service>:8443``).
These helpers keep the two apart."""

from __future__ import annotations

import time
from typing import Any

import httpx

from tests.compose.test_mcp_e2e import ASSERTION, IDP_CONFIGURED, IDP_HOST, KEYS
from trustkit.dpop import DpopKey
from trustkit.signing import InMemoryEs256Signer, build_client_assertion


def bound_workload_token(
    http: httpx.Client, client_id: str, key_name: str, dpop: DpopKey, scope: str = "tools.invoke"
) -> tuple[str, int]:
    """Client credentials with DPoP, Okta-style: the first proof is challenged for a nonce and
    the retry (fresh assertion, fresh proof) gets a token bound to ``dpop``.
    Returns ``(token, attempts)``."""
    signer = InMemoryEs256Signer((KEYS / f"{key_name}.pem").read_bytes())
    endpoint = f"{IDP_CONFIGURED}/oauth2/workload/v1/token"
    nonce: str | None = None
    for attempt in (1, 2):
        assertion = build_client_assertion(
            signer, client_id=client_id, token_endpoint=endpoint, now=lambda: int(time.time())
        )
        r = http.post(
            f"{IDP_HOST}/oauth2/workload/v1/token",
            data={
                "grant_type": "client_credentials",
                "scope": scope,
                "client_assertion_type": ASSERTION,
                "client_assertion": assertion,
            },
            headers={"DPoP": dpop.proof("POST", endpoint, nonce=nonce)},
        )
        if r.status_code == 400 and r.json().get("error") == "use_dpop_nonce":
            nonce = r.headers["dpop-nonce"]
            continue
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["token_type"] == "DPoP"
        return str(body["access_token"]), attempt
    raise AssertionError("IdP kept challenging")


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
    """One request: ``Authorization: DPoP`` plus a proof for ``public_url`` (what the gateway
    checks ``htu`` against), sent to ``host_url`` (where the host can reach it)."""
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
