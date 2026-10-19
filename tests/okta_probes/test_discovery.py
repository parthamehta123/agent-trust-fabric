"""Authorization-server metadata (RFC 8414) for the org and each custom authorization server."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.okta_probes.client import GRANT_JWT_BEARER, GRANT_TOKEN_EXCHANGE
from tests.okta_probes.config import OktaPreflightConfig
from trustkit_http.endpoint import HttpxTokenEndpoint
from trustkit_policy.idps import TrustedIdps


def metadata(http: HttpxTokenEndpoint, issuer: str) -> dict[str, Any]:
    return dict(http.get_json(f"{issuer}/.well-known/oauth-authorization-server"))


@pytest.mark.assumption("A-2")
@pytest.mark.parametrize("server", ["agent", "workload", "tool"])
def test_metadata_matches_the_platform_rules(
    cfg: OktaPreflightConfig,
    http: HttpxTokenEndpoint,
    evidence: Callable[[str, Any], None],
    server: str,
) -> None:
    """The issuer is exact (RFC 8414 §3.3), and its JWKS is where the platform expects it: on the
    org's origin, under the issuer (ADR-0027 review #1)."""
    srv = getattr(cfg.authorization_servers, server)
    md = metadata(http, srv.issuer)
    grants = md.get("grant_types_supported", [])
    evidence("grant_types_supported", sorted(g.rsplit(":", 1)[-1] for g in grants))
    evidence("dpop_algs", md.get("dpop_signing_alg_values_supported", []))
    assert md.get("issuer") == srv.issuer
    assert md.get("jwks_uri") == srv.jwks_uri
    assert md.get("token_endpoint") == srv.token_endpoint
    assert TrustedIdps(frozenset({cfg.org})).allows(md["issuer"], md["jwks_uri"])
    needed = {"agent": GRANT_JWT_BEARER, "tool": GRANT_TOKEN_EXCHANGE}.get(server)
    if needed is not None:
        assert needed in grants, f"{server} AS doesn't list the grant the platform needs"


@pytest.mark.assumption("A-14")
def test_workload_server_advertises_dpop_es256(
    cfg: OktaPreflightConfig, http: HttpxTokenEndpoint, evidence: Callable[[str, Any], None]
) -> None:
    md = metadata(http, cfg.authorization_servers.workload.issuer)
    algs = md.get("dpop_signing_alg_values_supported", [])
    evidence("dpop_algs", algs)
    assert "ES256" in algs
