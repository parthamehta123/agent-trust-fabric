"""Agent workload tokens: OAuth client_credentials with private_key_jwt (ADR-0016 §2).

Runs inside the agent runtime. The agent's key is used only through ``KeySigner`` (KMS in AWS),
so it never leaves KMS. Tokens are cached until ``exp - refresh_margin_s``.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from trustkit.exchange import CLIENT_ASSERTION_TYPE, TokenEndpoint, TransportError
from trustkit.signing import KeySigner, SigningError, build_client_assertion


class WorkloadTokenError(Exception):
    """Log-safe: never contains token material or IdP error descriptions."""


class WorkloadTokenProvider:
    def __init__(
        self,
        *,
        http: TokenEndpoint,
        signer: KeySigner,
        client_id: str,
        token_endpoint: str,
        scope: str,
        now: Callable[[], int] = lambda: int(time.time()),
        refresh_margin_s: int = 30,
        max_lifetime_s: int = 300,
    ) -> None:
        if not token_endpoint.startswith("https://"):
            raise ValueError("token_endpoint must be an https URL")
        self._http, self._signer, self._client_id = http, signer, client_id
        self._endpoint, self._scope, self._now = token_endpoint, scope, now
        self._margin, self._max_lifetime = refresh_margin_s, max_lifetime_s
        self._cached: tuple[str, int] | None = None
        self._lock = threading.Lock()

    def token(self) -> str:
        """A valid workload token, from cache or freshly issued. Raises ``WorkloadTokenError``."""
        with self._lock:
            now = self._now()
            if self._cached is not None and now < self._cached[1] - self._margin:
                return self._cached[0]
            token, expires_in = self._issue()
            self._cached = (token, now + expires_in)
            return token

    def _issue(self) -> tuple[str, int]:
        try:
            assertion = build_client_assertion(
                self._signer,
                client_id=self._client_id,
                token_endpoint=self._endpoint,
                now=self._now,
            )
            res = self._http.post_form(
                self._endpoint,
                {
                    "grant_type": "client_credentials",
                    "scope": self._scope,
                    "client_assertion_type": CLIENT_ASSERTION_TYPE,
                    "client_assertion": assertion,
                },
            )
        except (SigningError, TransportError, ValueError):
            raise WorkloadTokenError("workload token unavailable") from None
        body = res.body
        token, ttype, expires_in = (
            body.get("access_token"),
            body.get("token_type"),
            body.get("expires_in"),
        )
        if (
            res.status != 200
            or not isinstance(token, str)
            or not token
            or not isinstance(ttype, str)
            or ttype.lower() != "bearer"
            or not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or not 0 < expires_in <= self._max_lifetime
        ):
            raise WorkloadTokenError("workload token response rejected")
        return token, expires_in
