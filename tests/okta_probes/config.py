"""Local configuration for the Okta preflight probes (docs/runbooks/okta-preflight.md).

The file lives in ``.okta-preflight/`` (gitignored) next to the probes' private keys. It holds
URLs and client ids only, never secrets.
"""

from __future__ import annotations

import json
import pathlib
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from trustkit.profiles import HttpsUrl, Scope
from trustkit_policy.idps import TrustedIdps

ClientId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,128}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class AuthServer(_Strict):
    """A custom authorization server: its issuer, the audience it mints for, and one scope."""

    issuer: HttpsUrl
    audience: Annotated[str, StringConstraints(pattern=r"^\S{1,512}$")]
    scope: Scope

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/v1/token"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/v1/keys"


class AuthServers(_Strict):
    agent: AuthServer
    """The agent's resource AS: JWT-bearer with an ID-JAG -> T2 (A-2)."""
    workload: AuthServer
    """Client credentials for the agent's workload token (A-14, A-15)."""
    tool: AuthServer
    """Token exchange with an actor token -> delegated tool token (A-16, A-12)."""


class Clients(_Strict):
    chat: ClientId
    """The front-end app: signs the user in (PKCE) and requests the ID-JAG."""
    agent: ClientId
    """The agent: client credentials at ``workload``; the actor in delegation."""
    tool_gateway: ClientId
    """The tool gateway: performs the delegation exchange at ``tool``."""


class OktaPreflightConfig(_Strict):
    org: HttpsUrl
    """The Okta org, origin only: ``https://<tenant>.okta.com``."""
    authorization_servers: AuthServers
    clients: Clients
    redirect_port: Annotated[int, Field(ge=1024, le=65535)] = 8765
    """``http://127.0.0.1:<port>/callback`` must be a sign-in redirect URI of the chat app."""

    @model_validator(mode="after")
    def _servers_belong_to_the_org(self) -> OktaPreflightConfig:
        """Same rule the platform applies (ADR-0027 review #1): every issuer on the org's
        origin, with its keys under it."""
        trusted = TrustedIdps(frozenset({self.org}))
        for name in ("agent", "workload", "tool"):
            srv: AuthServer = getattr(self.authorization_servers, name)
            if not srv.issuer.startswith(f"{self.org}/oauth2/") or not trusted.allows(
                srv.issuer, srv.jwks_uri
            ):
                raise ValueError(
                    f"{name}: issuer must be a custom authorization server of {self.org}"
                )
        return self

    @property
    def org_token_endpoint(self) -> str:
        return f"{self.org}/oauth2/v1/token"

    @property
    def org_jwks_uri(self) -> str:
        return f"{self.org}/oauth2/v1/keys"

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.redirect_port}/callback"


def load_config(path: pathlib.Path) -> OktaPreflightConfig:
    return OktaPreflightConfig.model_validate_json(path.read_text())


def example() -> dict[str, object]:
    """The committed example (docs/runbooks/okta-preflight.config.example.json)."""
    root = pathlib.Path(__file__).parents[2]
    out: dict[str, object] = json.loads(
        (root / "docs" / "runbooks" / "okta-preflight.config.example.json").read_text()
    )
    return out
