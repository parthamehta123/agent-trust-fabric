"""Egress delegation (ADR-0016): bind_actor, exchange_delegated, WorkloadTokenProvider."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from tests.exchange.conftest import (
    AGENT_BETA_CLIENT,
    AGENT_CLIENT,
    ALICE,
    BASE,
    BOB,
    GATEWAY_CLIENT,
    TOOL_AUDIENCE,
    World,
    egress_doc,
    mint_t2,
    mint_workload,
)
from trustkit.binding import (
    ActorBindingError,
    ActorBindingReason,
    AgentPolicy,
    bind_actor,
)
from trustkit.exchange import (
    TOKEN_TYPE_ACCESS_TOKEN,
    ExchangeError,
    ExchangeReason,
    HttpResult,
    TransportError,
)
from trustkit.jwt import TokenValidator, ValidationPolicy
from trustkit.profiles import GatewayProfile, load_profiles
from trustkit.workload import WorkloadTokenError, WorkloadTokenProvider

ALPHA_POLICY = {
    "t2_issuer": f"{BASE}/oauth2/agent-alpha",
    "t2_audience": "api://agent-alpha",
    "t2_jwks_uri": f"{BASE}/oauth2/agent-alpha/v1/keys",
    "allowed_scopes": ["tickets.read"],
}
BETA_POLICY = {
    "t2_issuer": f"{BASE}/oauth2/agent-beta",
    "t2_audience": "api://agent-beta",
    "t2_jwks_uri": f"{BASE}/oauth2/agent-beta/v1/keys",
    "allowed_scopes": ["tickets.read"],
}
ALPHA_ONLY = {AGENT_CLIENT: ALPHA_POLICY}
BOTH = {AGENT_CLIENT: ALPHA_POLICY, AGENT_BETA_CLIENT: BETA_POLICY}
"""Test-local agent bindings. In the product these come from the signed policy bundle
(ADR-0022); here they exercise ``bind_actor`` and ``exchange_delegated`` directly."""


def egress_profile(**overrides: Any) -> GatewayProfile:
    reg = load_profiles(json.dumps({"version": 1, "profiles": [egress_doc(**overrides)]}))
    assert not reg.rejected, reg.rejected
    return reg.lookup("gw-tools")


def validators(
    world: World, profile: GatewayProfile, agents_doc: dict[str, dict[str, Any]] | None = None
) -> tuple[TokenValidator, dict[str, AgentPolicy]]:
    ei = profile.egress_inbound
    assert ei is not None
    workload_v = TokenValidator(
        ValidationPolicy(issuer=ei.issuer, audiences=ei.audiences, expected_typ="at+jwt"),
        world.jwks(ei.jwks_uri),
        now=world.clock,
    )
    agents = {
        cid: AgentPolicy(
            TokenValidator(
                ValidationPolicy(
                    issuer=a["t2_issuer"],
                    audiences=frozenset({a["t2_audience"]}),
                    expected_typ="at+jwt",
                ),
                world.jwks(a["t2_jwks_uri"]),
                now=world.clock,
            ),
            frozenset(a["allowed_scopes"]),
        )
        for cid, a in (agents_doc or ALPHA_ONLY).items()
    }
    return workload_v, agents


def claims(token: str) -> dict[str, Any]:
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))  # type: ignore[no-any-return]


def binding(
    world: World,
    *,
    workload: str | None = None,
    t2: str | None = None,
    profile: GatewayProfile | None = None,
    agents_doc: dict[str, dict[str, Any]] | None = None,
) -> Any:
    p = profile or egress_profile()
    wv, agents = validators(world, p, agents_doc)
    return bind_actor(
        workload or mint_workload(world), t2 or mint_t2(world), workload_validator=wv, agents=agents
    )


def binding_fails(world: World, reason: ActorBindingReason, **kw: Any) -> ActorBindingError:
    with pytest.raises(ActorBindingError) as ei:
        binding(world, **kw)
    assert ei.value.reason is reason, ei.value
    return ei.value


# ----------------------------------------------------------------------------- bind_actor


class TestBindActor:
    def test_binds_agent_and_user(self, world: World) -> None:
        b = binding(world)
        assert (b.agent_client_id, b.subject) == (AGENT_CLIENT, ALICE)
        assert b.allowed_scopes == frozenset({"tickets.read"})

    def test_repr_has_no_tokens(self, world: World) -> None:
        wl, t2 = mint_workload(world), mint_t2(world)
        r = repr(binding(world, workload=wl, t2=t2))
        assert wl not in r
        assert t2 not in r


@pytest.mark.security
class TestBindActorRejects:
    def test_confused_deputy_agent_b_spends_agent_a_t2(self, world: World) -> None:
        """TM-TOOL-01: beta is a legitimate agent, but this T2 was issued to alpha."""
        binding_fails(
            world,
            ActorBindingReason.SUBJECT_INVALID,
            workload=mint_workload(world, AGENT_BETA_CLIENT),
            t2=mint_t2(world),
            agents_doc=BOTH,
        )

    def test_agent_not_allowed_through_this_gateway(self, world: World) -> None:
        binding_fails(
            world,
            ActorBindingReason.AGENT_NOT_ALLOWED,
            workload=mint_workload(world, AGENT_BETA_CLIENT),
        )

    def test_t2_presented_as_workload_token(self, world: World) -> None:
        """Token confusion: the user's T2 is not the agent's identity."""
        t2 = mint_t2(world)
        binding_fails(world, ActorBindingReason.WORKLOAD_INVALID, workload=t2, t2=t2)

    def test_garbage_workload(self, world: World) -> None:
        binding_fails(world, ActorBindingReason.WORKLOAD_INVALID, workload="junk")

    def test_expired_subject(self, world: World) -> None:
        t2 = mint_t2(world)
        world.clock.t += 301 + 60
        binding_fails(
            world, ActorBindingReason.SUBJECT_INVALID, workload=mint_workload(world), t2=t2
        )

    def test_delegation_chain_refused(self, world: World) -> None:
        """TM-TOOL-07: a token that already carries `act` can't be delegated again (depth 1)."""
        tool_token = self._delegated_token(world)
        accepts_tool_tokens = {
            AGENT_CLIENT: {
                "t2_issuer": f"{BASE}/oauth2/tool-tickets",
                "t2_audience": TOOL_AUDIENCE,
                "t2_jwks_uri": f"{BASE}/oauth2/tool-tickets/v1/keys",
                "allowed_scopes": ["tickets.read"],
            }
        }
        binding_fails(
            world,
            ActorBindingReason.DELEGATION_CHAIN,
            t2=tool_token,
            agents_doc=accepts_tool_tokens,
        )

    @staticmethod
    def _delegated_token(world: World) -> str:
        return world.exchanger.exchange_delegated(binding(world), egress_profile()).token


# ----------------------------------------------------------------------------- exchange_delegated


class TestDelegatedExchange:
    def test_tool_token_carries_user_agent_and_intersected_scope(self, world: World) -> None:
        r = world.exchanger.exchange_delegated(binding(world), egress_profile())
        c = r.claims.claims
        assert r.claims.header["typ"] == "at+jwt"
        assert (c["iss"], c["aud"]) == (f"{BASE}/oauth2/tool-tickets", TOOL_AUDIENCE)
        assert (c["sub"], c["act"], c["client_id"]) == (
            ALICE,
            {"sub": AGENT_CLIENT},
            GATEWAY_CLIENT,
        )
        assert c["scope"] == "tickets.read", "target {read, write} ∩ agent {read}"

    def test_wire_format(self, world: World) -> None:
        wl, t2 = mint_workload(world), mint_t2(world)
        before = len(world.endpoint.calls)
        world.exchanger.exchange_delegated(binding(world, workload=wl, t2=t2), egress_profile())
        ((url, form),) = world.endpoint.calls[before:]
        assert url == f"{BASE}/oauth2/tool-tickets/v1/token"
        assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
        assert (form["subject_token"], form["actor_token"]) == (t2, wl)
        assert form["subject_token_type"] == form["actor_token_type"] == TOKEN_TYPE_ACCESS_TOKEN
        assert form["resource"] == TOOL_AUDIENCE
        assert claims(form["client_assertion"])["iss"] == GATEWAY_CLIENT, (
            "gateway's key, never the agent's"
        )

    def test_cached_per_subject_and_actor(self, world: World) -> None:
        wl, t2 = mint_workload(world), mint_t2(world)
        p = egress_profile()
        world.exchanger.exchange_delegated(binding(world, workload=wl, t2=t2), p)
        assert world.exchanger.exchange_delegated(binding(world, workload=wl, t2=t2), p).cached
        assert not world.exchanger.exchange_delegated(
            binding(world, workload=mint_workload(world), t2=t2), p
        ).cached


@pytest.mark.security
class TestDelegatedExchangeRejects:
    def _deny(
        self,
        world: World,
        reason: ExchangeReason,
        b: Any = None,
        profile: GatewayProfile | None = None,
    ) -> ExchangeError:
        with pytest.raises(ExchangeError) as ei:
            world.exchanger.exchange_delegated(b or binding(world), profile or egress_profile())
        assert ei.value.reason is reason, ei.value
        return ei.value

    def test_ingress_profile_refused(self, world: World) -> None:
        self._deny(world, ExchangeReason.PROFILE_NOT_EGRESS, profile=world.profile)

    def test_disabled(self, world: World) -> None:
        self._deny(world, ExchangeReason.PROFILE_DISABLED, profile=egress_profile(enabled=False))

    def test_agent_without_grant_for_target(self, world: World) -> None:
        """No granted scope for this target (bundle, ADR-0022): refuse before any IdP call."""
        from dataclasses import replace

        b = replace(binding(world), allowed_scopes=frozenset({"wiki.read"}))
        calls = len(world.endpoint.calls)
        self._deny(world, ExchangeReason.AGENT_NOT_CONFIGURED, b=b)
        assert len(world.endpoint.calls) == calls

    @pytest.mark.security
    def test_narrowed_grant_never_served_from_cache(self, world: World) -> None:
        """A policy bundle narrows the agent's scopes: the broader cached token must not be
        reused for the narrower request (cache key includes the requested scopes)."""
        from dataclasses import replace

        wide = binding(world)
        wide = replace(wide, allowed_scopes=frozenset({"tickets.read", "tickets.write"}))
        first = world.exchanger.exchange_delegated(wide, egress_profile())
        narrow = replace(wide, allowed_scopes=frozenset({"tickets.read"}))
        second = world.exchanger.exchange_delegated(narrow, egress_profile())
        assert not second.cached
        assert first.token != second.token
        assert claims(second.token)["scope"] == "tickets.read"

    def test_tool_as_also_enforces_actor_is_subjects_agent(self, world: World) -> None:
        """Defence in depth: bypass binding and the tool AS still refuses beta on alpha's T2."""
        from dataclasses import replace

        good = binding(world)
        beta_wl = mint_workload(world, AGENT_BETA_CLIENT)
        forged = replace(good, raw_workload=beta_wl)
        err = self._deny(world, ExchangeReason.IDP_ERROR, b=forged)
        assert err.idp_error == "invalid_grant"

    def test_scope_escalation(self, world: World) -> None:
        world.endpoint.rewrite_request = lambda url, f: {**f, "scope": "tickets.read tickets.write"}
        self._deny(world, ExchangeReason.T2_SCOPE_ESCALATION)

    def test_token_for_another_user(self, world: World) -> None:
        bob_token = world.exchanger.exchange_delegated(
            binding(world, t2=mint_t2(world, BOB)), egress_profile()
        ).token
        world.endpoint.rewrite_response = lambda url, r: HttpResult(
            200, {**r.body, "access_token": bob_token}
        )
        self._deny(world, ExchangeReason.DELEGATED_INVALID)

    def test_token_without_act(self, world: World) -> None:
        """A tool-audience token that doesn't name the agent as actor is not our delegated token."""
        t2 = mint_t2(world)
        world.endpoint.rewrite_response = lambda url, r: HttpResult(
            200, {**r.body, "access_token": t2}
        )
        self._deny(world, ExchangeReason.DELEGATED_INVALID)


# ----------------------------------------------------------------------------- workload provider


def provider(world: World, **kw: Any) -> WorkloadTokenProvider:
    args: dict[str, Any] = {
        "http": world.endpoint,
        "signer": world.signers["local:agent"],
        "client_id": AGENT_CLIENT,
        "token_endpoint": f"{BASE}/oauth2/workload/v1/token",
        "scope": "tools.invoke",
        "now": world.clock,
    }
    args.update(kw)
    return WorkloadTokenProvider(**args)


class TestWorkloadProvider:
    def test_issues_and_caches(self, world: World) -> None:
        p = provider(world)
        tok = p.token()
        c = claims(tok)
        assert (c["sub"], c["client_id"], c["aud"]) == (
            AGENT_CLIENT,
            AGENT_CLIENT,
            "api://tool-gateway",
        )
        before = len(world.endpoint.calls)
        assert p.token() == tok
        assert len(world.endpoint.calls) == before

    def test_refreshes_before_expiry(self, world: World) -> None:
        p = provider(world)
        first = p.token()
        world.clock.t += 300 - 30
        assert p.token() != first

    @pytest.mark.security
    @pytest.mark.parametrize(
        "rewrite",
        [
            pytest.param(
                lambda url, r: HttpResult(
                    400, {"error": "invalid_client", "error_description": "SECRET"}
                ),
                id="idp-error",
            ),
            pytest.param(
                lambda url, r: HttpResult(200, {**r.body, "token_type": "N_A"}), id="wrong-type"
            ),
            pytest.param(
                lambda url, r: HttpResult(200, {**r.body, "expires_in": 86_400}),
                id="too-long-lived",
            ),
            pytest.param(lambda url, r: HttpResult(200, {"token_type": "Bearer"}), id="no-token"),
        ],
    )
    def test_bad_responses(self, world: World, rewrite: Any) -> None:
        world.endpoint.rewrite_response = rewrite
        with pytest.raises(WorkloadTokenError) as ei:
            provider(world).token()
        assert "SECRET" not in str(ei.value)

    @pytest.mark.security
    def test_transport_failure(self, world: World) -> None:
        world.endpoint.transport_failures = 5
        with pytest.raises(WorkloadTokenError):
            provider(world).token()

    @pytest.mark.security
    def test_https_only(self, world: World) -> None:
        with pytest.raises(ValueError, match="https"):
            provider(world, token_endpoint="http://idp/token")


_ = TransportError  # re-exported for readers; transport failures are injected via the endpoint


@pytest.mark.security
class TestDpopBoundWorkloadToken:
    """ADR-0028: trustkit's DPoP client against the mock IdP's *independent* verifier."""

    @staticmethod
    def require_dpop(world: World) -> None:
        import dataclasses

        reg = world.idp._clients[AGENT_CLIENT]
        world.idp._clients[AGENT_CLIENT] = dataclasses.replace(reg, dpop_required=True)

    def test_nonce_round_trip_yields_a_bound_token(self, world: World) -> None:
        from trustkit.dpop import DpopKey

        self.require_dpop(world)
        key = DpopKey()
        tok = provider(world, dpop=key).token()
        assert claims(tok)["cnf"] == {"jkt": key.jkt}
        # First attempt is challenged for a nonce; the retry carries it.
        assert len(world.endpoint.calls) == 2
        assert all(h for h in world.endpoint.dpop_headers)

    def test_each_attempt_uses_a_fresh_client_assertion(self, world: World) -> None:
        from trustkit.dpop import DpopKey

        self.require_dpop(world)
        provider(world, dpop=DpopKey()).token()
        a1, a2 = (f["client_assertion"] for _, f in world.endpoint.calls)
        assert claims(a1)["jti"] != claims(a2)["jti"]

    def test_required_client_without_proof_gets_no_token(self, world: World) -> None:
        from trustkit.workload import WorkloadTokenError

        self.require_dpop(world)
        with pytest.raises(WorkloadTokenError):
            provider(world).token()

    def test_bearer_response_refused_when_dpop_requested(self, world: World) -> None:
        """Asked for a bound token but got a bearer one: never silently fall back."""
        from trustkit.dpop import DpopKey
        from trustkit.workload import WorkloadTokenError

        def as_bearer(url: str, r: HttpResult) -> HttpResult:
            return HttpResult(r.status, {**r.body, "token_type": "Bearer"}, r.dpop_nonce)

        self.require_dpop(world)
        world.endpoint.rewrite_response = as_bearer
        with pytest.raises(WorkloadTokenError):
            provider(world, dpop=DpopKey()).token()

    def test_one_nonce_retry_only(self, world: World) -> None:
        """A server that keeps challenging can't make the agent loop."""
        from trustkit.dpop import DpopKey
        from trustkit.workload import WorkloadTokenError

        def always_challenge(url: str, r: HttpResult) -> HttpResult:
            return HttpResult(
                400, {"error": "use_dpop_nonce"}, "n-" + str(len(world.endpoint.calls))
            )

        self.require_dpop(world)
        world.endpoint.rewrite_response = always_challenge
        with pytest.raises(WorkloadTokenError):
            provider(world, dpop=DpopKey()).token()
        assert len(world.endpoint.calls) == 2
