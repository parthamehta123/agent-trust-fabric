"""Interactive sign-in for the user-facing probes: authorization code + PKCE (RFC 7636).

You sign in yourself, in your own browser. This module only:

* serves **one** request on ``127.0.0.1`` (never another interface), for at most ``timeout_s``;
* checks ``state`` in constant time and refuses anything else;
* redeems the code with the chat app's ``private_key_jwt`` assertion and the PKCE verifier;
* validates the ID token (signature, ``iss``, ``aud``, ``nonce``) and keeps it **in memory**.

Nothing is written to disk and no token is ever logged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from tests.okta_probes.config import OktaPreflightConfig
from trustkit.jwt import JwksKeyResolver, TokenValidator, ValidationPolicy, VerifiedToken
from trustkit.signing import KeySigner, build_client_assertion
from trustkit_http.endpoint import HttpxTokenEndpoint

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class LoginError(Exception):
    """Log-safe: carries an OAuth error code or a fixed message, never a token or a code."""


@dataclass(frozen=True)
class Login:
    id_token: str = field(repr=False)
    claims: VerifiedToken = field(repr=False)


def pkce_pair() -> tuple[str, str]:
    """``(verifier, S256 challenge)``: a 43-character verifier from 32 random bytes."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def authorize_url(
    cfg: OktaPreflightConfig, *, state: str, nonce: str, challenge: str, redirect_uri: str
) -> str:
    query = {
        "client_id": cfg.clients.chat,
        "response_type": "code",
        "scope": "openid profile",
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{cfg.org}/oauth2/v1/authorize?{urlencode(query)}"


def wait_for_code(
    *,
    port: int,
    state: str,
    on_listening: Callable[[int], None],
    timeout_s: float = 180,
) -> str:
    """Serve one ``GET /callback`` on 127.0.0.1 and return its ``code``. ``on_listening`` gets
    the bound port (``port=0`` picks one, for tests) once the listener is up."""
    outcome: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(parts.query).items() if v}
            if parts.path != "/callback":
                outcome.setdefault("error", "unexpected_path")
            elif not hmac.compare_digest(q.get("state", ""), state):
                outcome.setdefault("error", "state_mismatch")
            elif "error" in q:
                outcome.setdefault("error", q["error"][:64])
            elif not q.get("code"):
                outcome.setdefault("error", "no_code")
            else:
                outcome.setdefault("code", q["code"])
            ok = "code" in outcome
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"Signed in. You can close this tab." if ok else b"Sign-in failed.")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            """Silence the stdlib access log: the request line holds the code."""

    server = HTTPServer(("127.0.0.1", port), Handler)
    server.timeout = 0.5
    try:
        on_listening(server.server_address[1])
        deadline = time.monotonic() + timeout_s
        while not outcome and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if "code" in outcome:
        return outcome["code"]
    raise LoginError(outcome.get("error", "timed_out"))


def login(
    cfg: OktaPreflightConfig,
    *,
    http: HttpxTokenEndpoint,
    signer: KeySigner,
    open_browser: Callable[[str], Any] = webbrowser.open,
    timeout_s: float = 180,
) -> Login:
    verifier, challenge = pkce_pair()
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    redirect_uri = cfg.redirect_uri

    def listening(_: int) -> None:
        url = authorize_url(
            cfg, state=state, nonce=nonce, challenge=challenge, redirect_uri=redirect_uri
        )
        threading.Thread(target=open_browser, args=(url,), daemon=True).start()

    code = wait_for_code(
        port=cfg.redirect_port, state=state, on_listening=listening, timeout_s=timeout_s
    )
    endpoint = cfg.org_token_endpoint
    res = http.post_form(
        endpoint,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": build_client_assertion(
                signer,
                client_id=cfg.clients.chat,
                token_endpoint=endpoint,
                now=lambda: int(time.time()),
            ),
        },
    )
    if res.status != 200 or not isinstance(res.body.get("id_token"), str):
        err = res.body.get("error")
        raise LoginError(f"code redemption failed: {err if isinstance(err, str) else res.status}")
    id_token = str(res.body["id_token"])
    validator = TokenValidator(
        ValidationPolicy(issuer=cfg.org, audiences=frozenset({cfg.clients.chat})),
        JwksKeyResolver(fetch=lambda: http.get_json(cfg.org_jwks_uri)),
    )
    claims = validator.validate(id_token)
    if not hmac.compare_digest(str(claims.claims.get("nonce", "")), nonce):
        raise LoginError("nonce mismatch")
    return Login(id_token=id_token, claims=claims)
