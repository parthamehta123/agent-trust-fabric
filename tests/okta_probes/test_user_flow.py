"""A signed-in user's path: ID-JAG and T2 (A-2, A-15), delegation (A-16), DPoP on the token
exchanges (A-12). Needs ``ATF_OKTA_LOGIN=1``: you sign in once, in your own browser."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.okta_probes.client import (
    GRANT_JWT_BEARER,
    GRANT_TOKEN_EXCHANGE,
    TT_ACCESS_TOKEN,
    TT_ID_JAG,
    TT_ID_TOKEN,
    error_code,
    post_token,
    shape,
    unverified,
)
from tests.okta_probes.config import OktaPreflightConfig
from trustkit.dpop import DpopKey
from trustkit.jwt import (
    CORE_REQUIRED_CLAIMS,
    AccessTokenProfile,
    KeyResolver,
    TokenValidator,
    ValidationPolicy,
)
from trustkit.signing import KeySigner
from trustkit_http.endpoint import HttpxTokenEndpoint

OKTA = AccessTokenProfile.OKTA
Signer = Callable[[str], KeySigner]


def id_jag(cfg: OktaPreflightConfig, http: HttpxTokenEndpoint, signer: Signer, user: Any) -> Any:
    """A fresh ID-JAG for the agent AS (single use, so every consumer gets its own)."""
    agent = cfg.authorization_servers.agent
    return post_token(
        http,
        cfg.org_token_endpoint,
        {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "requested_token_type": TT_ID_JAG,
            "subject_token": user.id_token,
            "subject_token_type": TT_ID_TOKEN,
            "audience": agent.issuer,
            "scope": agent.scope,
        },
        signer=signer("chat"),
        client_id=cfg.clients.chat,
    )


def t2(
    cfg: OktaPreflightConfig,
    http: HttpxTokenEndpoint,
    signer: Signer,
    user: Any,
    dpop: DpopKey | None = None,
) -> Any:
    jag = id_jag(cfg, http, signer, user).result
    if jag.status != 200:
        pytest.skip(f"no ID-JAG (see the A-2 probe): {error_code(jag)}")
    return post_token(
        http,
        cfg.authorization_servers.agent.token_endpoint,
        {"grant_type": GRANT_JWT_BEARER, "assertion": str(jag.body["access_token"])},
        signer=signer("chat"),
        client_id=cfg.clients.chat,
        dpop=dpop,
    )


def t2_validator(cfg: OktaPreflightConfig, jwks: Callable[[str], KeyResolver]) -> TokenValidator:
    agent = cfg.authorization_servers.agent
    return TokenValidator(
        ValidationPolicy(
            issuer=agent.issuer,
            audiences=frozenset({agent.audience}),
            expected_typ="at+jwt",
            access_token_profile=OKTA,
        ),
        jwks(agent.jwks_uri),
    )


@pytest.mark.assumption("A-2")
def test_org_issues_an_id_jag(
    cfg: OktaPreflightConfig,
    http: HttpxTokenEndpoint,
    signer: Signer,
    user: Any,
    jwks: Callable[[str], KeyResolver],
    evidence: Callable[[str, Any], None],
) -> None:
    res = id_jag(cfg, http, signer, user).result
    if res.status != 200:
        pytest.fail(f"A-2 refuted: ID-JAG request -> {error_code(res)}")
    evidence("issued_token_type", str(res.body.get("issued_token_type")))
    evidence("token_type", str(res.body.get("token_type")))
    assert res.body.get("issued_token_type") == TT_ID_JAG
    assert str(res.body.get("token_type")).lower() == "n_a"
    token = str(res.body["access_token"])
    header, claims = unverified(token)
    evidence("typ", str(header.get("typ")))
    evidence("claims", shape(claims))
    TokenValidator(  # exactly what the exchanger checks
        ValidationPolicy(
            issuer=cfg.org,
            audiences=frozenset({cfg.authorization_servers.agent.issuer}),
            expected_typ="oauth-id-jag+jwt",
            required_claims=CORE_REQUIRED_CLAIMS | {"client_id", "jti"},
        ),
        jwks(cfg.org_jwks_uri),
    ).validate(token)
    assert claims["sub"] == user.claims.subject
    assert claims["client_id"] == cfg.clients.chat


@pytest.mark.assumption("A-2")
def test_jwt_bearer_turns_the_id_jag_into_t2(
    cfg: OktaPreflightConfig,
    http: HttpxTokenEndpoint,
    signer: Signer,
    user: Any,
    jwks: Callable[[str], KeyResolver],
    evidence: Callable[[str, Any], None],
) -> None:
    res = t2(cfg, http, signer, user).result
    if res.status != 200:
        pytest.fail(f"A-2 refuted: JWT-bearer with the ID-JAG -> {error_code(res)}")
    header, claims = unverified(str(res.body["access_token"]))
    evidence("header", sorted(header))
    evidence("claims", shape(claims))
    t2_validator(cfg, jwks).validate(str(res.body["access_token"]))


@pytest.mark.assumption("A-15")
def test_t2_names_the_user_like_the_id_token(
    cfg: OktaPreflightConfig,
    http: HttpxTokenEndpoint,
    signer: Signer,
    user: Any,
    jwks: Callable[[str], KeyResolver],
    evidence: Callable[[str, Any], None],
) -> None:
    """The `okta` profile takes the user from `uid`; the mix-up defence then needs it to equal
    the ID token's `sub`, and the client to be the one that asked."""
    res = t2(cfg, http, signer, user).result
    if res.status != 200:
        pytest.skip(f"no T2 (see the A-2 probes): {error_code(res)}")
    _, raw = unverified(str(res.body["access_token"]))
    evidence("has_uid", "uid" in raw)
    evidence("sub_equals_id_token_sub", raw.get("sub") == user.claims.subject)
    c = t2_validator(cfg, jwks).validate(str(res.body["access_token"])).claims
    assert c["sub"] == user.claims.subject, "normalised T2 sub must equal the ID token's sub"
    assert c["client_id"] == cfg.clients.chat


@pytest.mark.assumption("A-16")
def test_delegation_exchange_emits_act(
    cfg: OktaPreflightConfig,
    http: HttpxTokenEndpoint,
    signer: Signer,
    user: Any,
    jwks: Callable[[str], KeyResolver],
    evidence: Callable[[str, Any], None],
) -> None:
    """ADR-0016: T2 (subject) + the agent's workload token (actor) at the tool AS, as the tool
    gateway. The tool token must carry ``act: {"sub": <agent>}``."""
    subject = t2(cfg, http, signer, user).result
    if subject.status != 200:
        pytest.skip(f"no T2 (see the A-2 probes): {error_code(subject)}")
    wl = cfg.authorization_servers.workload
    actor = post_token(
        http,
        wl.token_endpoint,
        {"grant_type": "client_credentials", "scope": wl.scope},
        signer=signer("agent"),
        client_id=cfg.clients.agent,
        dpop=DpopKey(),
    ).result
    if actor.status != 200:
        pytest.skip(f"no workload token (see the A-14 probe): {error_code(actor)}")
    tool = cfg.authorization_servers.tool
    res = post_token(
        http,
        tool.token_endpoint,
        {
            "grant_type": GRANT_TOKEN_EXCHANGE,
            "requested_token_type": TT_ACCESS_TOKEN,
            "subject_token": str(subject.body["access_token"]),
            "subject_token_type": TT_ACCESS_TOKEN,
            "actor_token": str(actor.body["access_token"]),
            "actor_token_type": TT_ACCESS_TOKEN,
            "audience": tool.issuer,
            "resource": tool.audience,
            "scope": tool.scope,
        },
        signer=signer("tool-gateway"),
        client_id=cfg.clients.tool_gateway,
    ).result
    if res.status != 200:
        pytest.fail(f"A-16 refuted: delegation exchange -> {error_code(res)}")
    _, raw = unverified(str(res.body["access_token"]))
    evidence("claims", shape(raw))
    evidence("act_shape", shape(raw["act"]) if isinstance(raw.get("act"), dict) else "absent")
    c = (
        TokenValidator(
            ValidationPolicy(
                issuer=tool.issuer,
                audiences=frozenset({tool.audience}),
                expected_typ="at+jwt",
                access_token_profile=OKTA,
            ),
            jwks(tool.jwks_uri),
        )
        .validate(str(res.body["access_token"]))
        .claims
    )
    assert c.get("act") == {"sub": cfg.clients.agent}, "A-16 refuted: no RFC 8693 act claim"
    assert c["sub"] == user.claims.subject
    assert c["client_id"] == cfg.clients.tool_gateway


@pytest.mark.assumption("A-12")
def test_jwt_bearer_output_can_be_dpop_bound(
    cfg: OktaPreflightConfig,
    http: HttpxTokenEndpoint,
    signer: Signer,
    user: Any,
    evidence: Callable[[str, Any], None],
) -> None:
    """ADR-0028 Phase 2: T2 bound to a key when the JWT-bearer request carries a DPoP proof."""
    key = DpopKey()
    call = t2(cfg, http, signer, user, dpop=key)
    evidence("nonce_challenged", call.nonce_challenged)
    res = call.result
    if res.status != 200:
        pytest.fail(f"A-12 refuted: JWT-bearer with DPoP -> {error_code(res)}")
    _, raw = unverified(str(res.body["access_token"]))
    evidence("token_type", str(res.body.get("token_type")))
    evidence("cnf_jkt_is_our_key", raw.get("cnf", {}).get("jkt") == key.jkt)
    assert raw.get("cnf") == {"jkt": key.jkt}, "A-12 refuted: the T2 isn't bound to the key"
