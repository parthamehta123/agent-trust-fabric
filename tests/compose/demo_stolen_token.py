"""Stolen-token demo (ADR-0028, TM-TOK-01): ``make demo-stolen-token`` against the running stack.

Agent alpha holds a DPoP-bound token and gets a model reply with it. A thief has a copy of that
token and copies of alpha's proofs, and gets nothing: every refusal below is a DPoP check at a live
gateway, and the mock LLM's call counter shows the thief caused no model calls.

The file has no ``test_`` prefix, so ``make e2e`` doesn't collect it; CI runs it as its own step
(``make demo-stolen-token``), so every claim it prints is asserted on every PR.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import textwrap
import time
from typing import Any

import httpx
import pytest

from tests.compose.conftest import AGENT, BETA
from tests.compose.dpop_harness import dpop_call, dpop_request, mint_bound
from tests.compose.test_inference_e2e import MODEL, model_calls
from tests.compose.test_mcp_e2e import CA
from trustkit.dpop import DpopKey

pytestmark = [
    pytest.mark.compose,
    pytest.mark.security,
    pytest.mark.skipif(os.environ.get("ATF_COMPOSE") != "1", reason="needs the compose stack"),
]

INFERENCE = ("https://localhost:8445", "https://inference-gateway:8443", "/v1/chat/completions")
MCP = ("https://localhost:8444", "https://mcp-gateway:8443", "/mcp")
A2A = ("https://localhost:8446", "https://a2a-gateway:8443", f"/agents/{BETA}/a2a")
"""(published host URL, the URL the gateway believes it serves, path)."""
CHAT = {"model": MODEL, "messages": [{"role": "user", "content": "Summarise ticket T-1"}]}
LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def say(text: str = "") -> None:
    print(text, flush=True)


def scene(title: str, story: str) -> None:
    say()
    say(title)
    say(textwrap.fill(story, 96, initial_indent="    ", subsequent_indent="    "))


def claims(token: str) -> dict[str, Any]:
    seg = token.split(".")[1]
    out: dict[str, Any] = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    return out


def reason(r: httpx.Response) -> str:
    """The gateway's refusal code, whatever its error shape (REST or JSON-RPC)."""
    try:
        err = r.json().get("error")
    except ValueError:
        return r.text[:80]
    if isinstance(err, dict):
        return str(err.get("type") or err.get("message"))
    return str(err)


def refused(r: httpx.Response, expected: str) -> None:
    say(f"    -> HTTP {r.status_code} {reason(r)}: refused")
    assert (r.status_code, reason(r)) == (401, expected), r.text


def url(gw: tuple[str, str, str], public: bool = False) -> str:
    return f"{gw[1] if public else gw[0]}{gw[2]}"


def test_stolen_token_is_useless_without_the_key() -> None:
    with httpx.Client(verify=ssl.create_default_context(cafile=str(CA)), timeout=15) as http:
        _demo(http)


def _demo(http: httpx.Client) -> None:
    say("\n=== Stolen-token demo: DPoP at the live gateways (ADR-0028) ===")

    # --- Act 1: the token is worth stealing -------------------------------------------------
    key = DpopKey()  # alpha's private key: generated in memory, never leaves the process
    form = {"grant_type": "client_credentials", "scope": "inference.invoke"}
    token, _ = mint_bound(http, "/oauth2/inference/v1/token", AGENT, "agent", form, key)
    c = claims(token)
    scene(
        "[0] Agent alpha gets a token",
        "Client credentials with a DPoP proof: the IdP challenged for a nonce, then issued a token "
        "bound to the thumbprint of alpha's key.",
    )
    scope = c.get("scope") or " ".join(c.get("scp", []))  # RFC 9068 or Okta shape (A-15)
    say(f"    sub={c['sub']}  aud={c['aud']}  scope={scope}")
    say(f"    expires in {int(c['exp'] - time.time())} s   cnf.jkt={c['cnf']['jkt']}")
    assert c["cnf"] == {"jkt": key.jkt}

    challenge = dpop_request(
        http,
        "POST",
        host_url=url(INFERENCE),
        public_url=url(INFERENCE, True),
        token=token,
        key=key,
        json=CHAT,
    )
    assert 'error="use_dpop_nonce"' in challenge.headers["www-authenticate"]
    nonce = challenge.headers["dpop-nonce"]
    proof = key.proof("POST", url(INFERENCE, True), access_token=token, nonce=nonce)
    sent = {"Authorization": f"DPoP {token}", "DPoP": proof}
    calls_before = model_calls()
    ok = http.post(url(INFERENCE), json=CHAT, headers=sent)
    scene(
        "[1] Alpha calls the model",
        "Alpha signs a proof for this exact request (method, URL, token hash, gateway nonce) "
        "and sends it with the token.",
    )
    say(f"    -> HTTP {ok.status_code}: {ok.json()['choices'][0]['message']['content'][:60]!r}")
    assert ok.status_code == 200, ok.text
    assert model_calls() == calls_before + 1
    calls_before = model_calls()

    say("\n--- A thief now has a copy of the token and of every proof alpha sent ---")

    # --- Act 2: the thief ------------------------------------------------------------------
    scene(
        "[2] Send the stolen token with no proof",
        "The token is genuine: valid signature, right audience, not expired. But it is bound, "
        "and a bound token without a proof is refused (no downgrade).",
    )
    refused(
        http.post(url(INFERENCE), json=CHAT, headers={"Authorization": f"Bearer {token}"}),
        "dpop_missing",
    )

    scene(
        "[3] Sign a proof with the thief's own key",
        "The proof is well formed, but its key's thumbprint isn't the cnf.jkt in the token. The "
        "thief is refused before the nonce check, so it never even gets a nonce.",
    )
    r = dpop_call(
        http,
        "POST",
        host_url=url(INFERENCE),
        public_url=url(INFERENCE, True),
        token=token,
        key=DpopKey(),
        json=CHAT,
    )
    refused(r, "dpop_key_mismatch")
    assert "dpop-nonce" not in r.headers

    scene(
        "[4] Resend alpha's accepted request, byte for byte",
        "Alpha's own proof, signed with the right key. Each proof is single use: the gateway "
        "remembers its jti for as long as the proof could be valid.",
    )
    refused(http.post(url(INFERENCE), json=CHAT, headers=sent), "dpop_replay")

    scene(
        "[5] Send a proof alpha signed two minutes ago",
        "Captured earlier and never used, with a nonce that is still valid. Proofs are only "
        "accepted within 60 s of their iat, so an old capture is worthless.",
    )
    stale = key.proof(
        "POST",
        url(INFERENCE, True),
        access_token=token,
        nonce=nonce,
        now=lambda: int(time.time()) - 120,
    )
    refused(
        http.post(
            url(INFERENCE), json=CHAT, headers={"Authorization": f"DPoP {token}", "DPoP": stale}
        ),
        "dpop_stale",
    )

    tool_form = {"grant_type": "client_credentials", "scope": "tools.invoke"}
    tool_token, _ = mint_bound(http, "/oauth2/workload/v1/token", AGENT, "agent", tool_form, key)
    scene(
        "[6] Redirect a proof to a different gateway",
        "Alpha's tool-gateway token is valid at both the MCP and the A2A gateway. The thief "
        "intercepts a proof on its way to the MCP gateway and sends it, unused, to the A2A "
        "gateway. The proof names the URL it was signed for (htu), so it is refused there.",
    )
    first = dpop_request(
        http,
        "POST",
        host_url=url(MCP),
        public_url=url(MCP, True),
        token=tool_token,
        key=key,
        json=LIST,
        headers={"X-Subject-Token": "t2"},
    )
    mcp_proof = key.proof(
        "POST", url(MCP, True), access_token=tool_token, nonce=first.headers["dpop-nonce"]
    )
    redirected = {"Authorization": f"DPoP {tool_token}", "DPoP": mcp_proof, "X-Subject-Token": "t2"}
    refused(http.post(url(A2A), json=LIST, headers=redirected), "dpop_wrong_target")

    calls_after = model_calls()
    say()
    thief_calls = calls_after - calls_before
    say(f"=== Five attempts, five refusals. Model calls caused by the thief: {thief_calls} ===")
    assert calls_after == calls_before
