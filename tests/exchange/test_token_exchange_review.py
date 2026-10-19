"""Token-exchange RFC self-review (RFC 8693, RFC 7523, ID-JAG): a regression test per finding."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from tests.exchange.conftest import (
    AGENT_CLIENT,
    ALICE,
    CHAT,
    GATEWAY_CLIENT,
    World,
    make_profile,
    make_world,
    mint_t2,
    mint_workload,
)
from tests.exchange.test_egress import ALPHA_POLICY, egress_profile
from trustkit.binding import AgentPolicy, BindingError, BindingReason, bind_actor
from trustkit.exchange import ExchangeError, ExchangeReason, HttpResult, TransportError
from trustkit.jwt import AccessTokenProfile, TokenValidator, ValidationPolicy


def parts(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    def seg(s: str) -> dict[str, Any]:
        out: dict[str, Any] = json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        return out

    h, c, _ = token.split(".")
    return seg(h), seg(c)


# ----------------------------------------------------------------------------- #1 Okta shape


class TestOktaShapedAccessTokens:
    """A-15: Okta custom authorization servers issue access tokens with no ``typ``, ``scp`` (an
    array), ``cid``, and for a user ``sub`` = login with the stable id in ``uid``. The ``okta``
    profile accepts and normalises exactly that; the ``rfc9068`` profile refuses it."""

    def test_the_mock_issues_okta_shaped_tokens(self, okta_world: World) -> None:
        at, _ = okta_world.idp.login(ALICE, CHAT, ingress_as_id="ingress")
        header, c = parts(at)
        assert "typ" not in header
        assert (c["uid"], c["cid"]) == (ALICE, CHAT)
        assert c["sub"] != ALICE  # the login, not the id
        assert "client_id" not in c

    def test_ingress_exchange_end_to_end(self, okta_world: World) -> None:
        bound = okta_world.login_and_bind()
        assert bound.subject == ALICE  # uid, the same id the ID token carries
        r = okta_world.exchanger.exchange(bound, okta_world.profile)
        header, raw = parts(r.token)
        assert "typ" not in header
        assert isinstance(raw["scp"], list)
        c = r.claims.claims  # normalised for every consumer
        assert (c["sub"], c["client_id"], c["scope"]) == (ALICE, CHAT, "agent.invoke")

    def test_delegated_exchange_end_to_end(self, okta_world: World) -> None:
        okta = AccessTokenProfile.OKTA
        p = egress_profile()
        ei = p.egress_inbound
        assert ei is not None
        workload_v = TokenValidator(
            ValidationPolicy(
                issuer=ei.issuer,
                audiences=ei.audiences,
                expected_typ="at+jwt",
                access_token_profile=okta,
            ),
            okta_world.jwks(ei.jwks_uri),
            now=okta_world.clock,
        )
        t2_v = TokenValidator(
            ValidationPolicy(
                issuer=ALPHA_POLICY["t2_issuer"],
                audiences=frozenset({ALPHA_POLICY["t2_audience"]}),
                expected_typ="at+jwt",
                access_token_profile=okta,
            ),
            okta_world.jwks(ALPHA_POLICY["t2_jwks_uri"]),
            now=okta_world.clock,
        )
        binding = bind_actor(
            mint_workload(okta_world),
            mint_t2(okta_world),
            workload_validator=workload_v,
            agents={AGENT_CLIENT: AgentPolicy(t2_v, frozenset({"tickets.read"}))},
        )
        assert (binding.agent_client_id, binding.subject) == (AGENT_CLIENT, ALICE)
        c = okta_world.exchanger.exchange_delegated(binding, p).claims.claims
        assert (c["sub"], c["client_id"], c["scope"]) == (ALICE, GATEWAY_CLIENT, "tickets.read")
        assert c["act"] == {"sub": AGENT_CLIENT}

    @pytest.mark.security
    def test_rfc9068_validators_refuse_okta_tokens(self) -> None:
        """The finding: without the profile, real Okta tokens fail closed at the first check."""
        w = make_world(claim_shape="okta")
        with pytest.raises(BindingError) as e:
            w.login_and_bind()
        assert e.value.reason is BindingReason.SUBJECT_MISMATCH  # login vs user id


# ----------------------------------------------------------------------------- #3 cache key


@pytest.mark.security
def test_narrowed_profile_scopes_never_served_from_cache(world: World) -> None:
    """A T2 minted under broader profile scopes is not served once the profile is narrowed."""
    bound = world.login_and_bind()
    broad = make_profile(
        target={"audience": "api://agent-alpha", "scopes": ["agent.invoke", "tickets.read"]}
    )
    first = world.exchanger.exchange(bound, broad)
    assert set(first.claims.claims["scope"].split()) == {"agent.invoke", "tickets.read"}
    narrow = world.exchanger.exchange(bound, world.profile)  # scopes: agent.invoke only
    assert not narrow.cached
    assert narrow.claims.claims["scope"] == "agent.invoke"


# ----------------------------------------------------------------------------- #4 retries


class _FailFirstJwtBearer:
    """Wraps the recording endpoint: the first JWT-bearer call fails in transport."""

    def __init__(self, world: World, *, maybe_sent: bool) -> None:
        self.inner, self.maybe_sent, self.failed = world.endpoint, maybe_sent, False
        self.jwt_bearer_calls = 0

    def post_form(self, url: str, form: Any, *, headers: Any = None) -> HttpResult:
        if form.get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer":
            self.jwt_bearer_calls += 1
            if not self.failed:
                self.failed = True
                if self.maybe_sent:  # the request reached the IdP, then the reply was lost
                    self.inner.post_form(url, form)
                raise TransportError("simulated", maybe_sent=self.maybe_sent)
        return self.inner.post_form(url, form)


@pytest.mark.security
def test_id_jag_is_not_resent_after_a_timeout(world: World) -> None:
    """The ID-JAG is single use: once a request may have reached the IdP, a resend can only be
    refused, so the exchanger fails fast instead of spending a retry on it."""
    flaky = _FailFirstJwtBearer(world, maybe_sent=True)
    world.exchanger._http = flaky
    with pytest.raises(ExchangeError) as e:
        world.exchanger.exchange(world.login_and_bind(), world.profile)
    assert (e.value.reason, e.value.step) == (ExchangeReason.IDP_UNAVAILABLE, "jwt_bearer")
    assert flaky.jwt_bearer_calls == 1


def test_connect_failure_is_still_retried(world: World) -> None:
    """A request that never left can be retried, single-use input or not."""
    flaky = _FailFirstJwtBearer(world, maybe_sent=False)
    world.exchanger._http = flaky
    assert world.exchanger.exchange(world.login_and_bind(), world.profile).token
    assert flaky.jwt_bearer_calls == 2


def test_token_exchange_step_still_retries_after_a_timeout(world: World) -> None:
    """The first step's inputs (an ID token, a fresh client assertion) can be resent."""
    world.endpoint.transport_failures = 1  # maybe_sent defaults to True
    assert world.exchanger.exchange(world.login_and_bind(), world.profile).token
    assert world.idp_calls() == 3
