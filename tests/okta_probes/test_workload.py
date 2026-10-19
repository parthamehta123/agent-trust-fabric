"""The agent's workload token: client credentials with DPoP (A-14) and its shape (A-15)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.okta_probes.client import error_code, post_token, shape, unverified
from tests.okta_probes.config import OktaPreflightConfig
from trustkit.dpop import DpopKey
from trustkit.jwt import AccessTokenProfile, KeyResolver, TokenValidator, ValidationPolicy
from trustkit.signing import KeySigner
from trustkit_http.endpoint import HttpxTokenEndpoint


@pytest.fixture(scope="module")
def workload(
    cfg: OktaPreflightConfig, http: HttpxTokenEndpoint, signer: Callable[[str], KeySigner]
) -> tuple[DpopKey, Any]:
    key = DpopKey()
    srv = cfg.authorization_servers.workload
    call = post_token(
        http,
        srv.token_endpoint,
        {"grant_type": "client_credentials", "scope": srv.scope},
        signer=signer("agent"),
        client_id=cfg.clients.agent,
        dpop=key,
    )
    return key, call


@pytest.mark.assumption("A-14")
def test_dpop_client_credentials_bind_the_token(
    workload: tuple[DpopKey, Any], evidence: Callable[[str, Any], None]
) -> None:
    """ADR-0028 Phase 1: a DPoP-bound workload token, with Okta's nonce challenge handled the
    way `WorkloadTokenProvider` handles it."""
    key, call = workload
    res = call.result
    evidence("nonce_challenged", call.nonce_challenged)
    if res.status != 200:
        pytest.fail(f"A-14 refuted: client credentials with DPoP -> {error_code(res)}")
    evidence("token_type", str(res.body.get("token_type")))
    assert str(res.body.get("token_type")).lower() == "dpop"
    _, claims = unverified(str(res.body["access_token"]))
    evidence("cnf_jkt_is_our_key", claims.get("cnf", {}).get("jkt") == key.jkt)
    assert claims.get("cnf") == {"jkt": key.jkt}


@pytest.mark.assumption("A-15")
def test_workload_token_passes_the_okta_profile(
    cfg: OktaPreflightConfig,
    workload: tuple[DpopKey, Any],
    jwks: Callable[[str], KeyResolver],
    evidence: Callable[[str, Any], None],
) -> None:
    """The same validator configuration the gateways run (ATF_ACCESS_TOKEN_PROFILE=okta)."""
    _, call = workload
    if call.result.status != 200:
        pytest.skip("no workload token (see the A-14 probe)")
    token = str(call.result.body["access_token"])
    header, claims = unverified(token)
    evidence("header", sorted(header))
    evidence("claims", shape(claims))
    srv = cfg.authorization_servers.workload
    verified = TokenValidator(
        ValidationPolicy(
            issuer=srv.issuer,
            audiences=frozenset({srv.audience}),
            expected_typ="at+jwt",
            access_token_profile=AccessTokenProfile.OKTA,
        ),
        jwks(srv.jwks_uri),
    ).validate(token)
    c = verified.claims
    assert c["client_id"] == cfg.clients.agent
    assert c["sub"] == c["client_id"], "a workload token names the agent as sub == client_id"
    assert srv.scope in str(c["scope"]).split()
