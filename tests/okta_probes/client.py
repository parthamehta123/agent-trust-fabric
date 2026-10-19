"""Token-endpoint calls for the probes: a fresh ``private_key_jwt`` assertion per request, and the
DPoP nonce challenge handled the way Okta documents it (one retry with ``DPoP-Nonce``)."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tests.okta_probes.login import CLIENT_ASSERTION_TYPE
from trustkit.dpop import DpopKey
from trustkit.exchange import HttpResult
from trustkit.signing import KeySigner, build_client_assertion
from trustkit_http.endpoint import HttpxTokenEndpoint

GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TT_ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
TT_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
TT_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


@dataclass(frozen=True)
class Call:
    result: HttpResult
    nonce_challenged: bool


def post_token(
    http: HttpxTokenEndpoint,
    url: str,
    form: Mapping[str, str],
    *,
    signer: KeySigner,
    client_id: str,
    dpop: DpopKey | None = None,
) -> Call:
    nonce: str | None = None
    challenged = False
    for _ in range(2):
        assertion = build_client_assertion(
            signer, client_id=client_id, token_endpoint=url, now=lambda: int(time.time())
        )
        body = {
            **form,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        }
        headers = {"DPoP": dpop.proof("POST", url, nonce=nonce)} if dpop is not None else None
        res = http.post_form(url, body, headers=headers)
        if (
            dpop is not None
            and nonce is None
            and res.status == 400
            and res.body.get("error") == "use_dpop_nonce"
            and res.dpop_nonce
        ):
            nonce, challenged = res.dpop_nonce, True
            continue
        return Call(res, challenged)
    raise AssertionError("unreachable")  # pragma: no cover


def error_code(res: HttpResult) -> str:
    """The OAuth ``error`` code only (descriptions can echo request data)."""
    err = res.body.get("error")
    return err if isinstance(err, str) and len(err) <= 64 else f"http_{res.status}"


def unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Header and claims, for recording *shapes* only; validation is always done separately."""

    def seg(s: str) -> dict[str, Any]:
        out: dict[str, Any] = json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        return out

    h, c, _ = token.split(".")
    return seg(h), seg(c)


def shape(claims: Mapping[str, Any]) -> list[str]:
    """``name:type`` for every claim, e.g. ``scp:list``, sorted: evidence without values."""
    return sorted(f"{k}:{type(v).__name__}" for k, v in claims.items())
