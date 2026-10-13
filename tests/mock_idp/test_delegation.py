"""Mock tool-AS conformance: client_credentials and RFC 8693 delegation (ADR-0016)."""

from __future__ import annotations

from typing import Any

import pytest

from mock_idp.core import TOKEN_TYPE_ACCESS_TOKEN, TokenResponse
from tests.exchange.conftest import (
    AGENT_BETA_CLIENT,
    AGENT_CLIENT,
    ALICE,
    BASE,
    GATEWAY_CLIENT,
    TOOL_AUDIENCE,
    World,
    mint_t2,
    mint_workload,
    world,
)
from trustkit.signing import build_client_assertion

__all__ = ["world"]
TOOL_EP = f"{BASE}/oauth2/tool-tickets/v1/token"
WORKLOAD_EP = f"{BASE}/oauth2/workload/v1/token"


def auth(world: World, client: str, ref: str, ep: str) -> dict[str, str]:
    return {
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": build_client_assertion(
            world.signers[ref], client_id=client, token_endpoint=ep, now=world.clock
        ),
    }


def delegate(
    world: World, *, subject: str | None = None, actor: str | None = None, **form: str | None
) -> TokenResponse:
    f: dict[str, str | None] = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": subject or mint_t2(world),
        "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
        "actor_token": actor or mint_workload(world),
        "actor_token_type": TOKEN_TYPE_ACCESS_TOKEN,
        "audience": f"{BASE}/oauth2/tool-tickets",
        "resource": TOOL_AUDIENCE,
        "scope": "tickets.read",
    }
    f.update(form)
    body = {k: v for k, v in f.items() if v is not None}
    return world.idp.token(
        TOOL_EP, {**body, **auth(world, GATEWAY_CLIENT, "local:gateway", TOOL_EP)}
    )


def err(r: TokenResponse, error: str, status: int = 400) -> None:
    assert (r.status, r.body.get("error")) == (status, error), r.body
    assert "access_token" not in r.body


class TestClientCredentials:
    def test_workload_token(self, world: World) -> None:
        from tests.exchange.test_egress import claims

        c = claims(mint_workload(world))
        assert (c["sub"], c["client_id"], c["aud"], c["scope"]) == (
            AGENT_CLIENT,
            AGENT_CLIENT,
            "api://tool-gateway",
            "tools.invoke",
        )

    @pytest.mark.security
    def test_client_not_registered_at_as(self, world: World) -> None:
        r = world.idp.token(
            TOOL_EP,
            {
                "grant_type": "client_credentials",
                **auth(world, AGENT_CLIENT, "local:agent", TOOL_EP),
            },
        )
        err(r, "invalid_client", 401)

    @pytest.mark.security
    def test_scope_outside_policy(self, world: World) -> None:
        r = world.idp.token(
            WORKLOAD_EP,
            {
                "grant_type": "client_credentials",
                "scope": "admin",
                **auth(world, AGENT_CLIENT, "local:agent", WORKLOAD_EP),
            },
        )
        err(r, "invalid_scope")


class TestDelegation:
    def test_issues_act_token(self, world: World) -> None:
        from tests.exchange.test_egress import claims

        r = delegate(world)
        assert r.status == 200, r.body
        assert r.body["issued_token_type"] == TOKEN_TYPE_ACCESS_TOKEN
        c = claims(r.body["access_token"])
        assert (c["sub"], c["aud"], c["act"], c["client_id"]) == (
            ALICE,
            TOOL_AUDIENCE,
            {"sub": AGENT_CLIENT},
            GATEWAY_CLIENT,
        )


@pytest.mark.security
class TestDelegationRejects:
    def test_actor_is_not_the_subjects_agent(self, world: World) -> None:
        """AS-side confused-deputy guard (ADR-0016 §5)."""
        err(delegate(world, actor=mint_workload(world, AGENT_BETA_CLIENT)), "invalid_grant")

    def test_subject_with_act_refused(self, world: World) -> None:
        tool_token = delegate(world).body["access_token"]
        err(delegate(world, subject=tool_token), "invalid_grant")

    def test_id_token_as_subject(self, world: World) -> None:
        _, idt = world.idp.login(ALICE, "0oa-chat", ingress_as_id="ingress")
        err(delegate(world, subject=idt), "invalid_grant")

    @pytest.mark.parametrize(
        "override",
        [
            {"subject_token_type": "urn:ietf:params:oauth:token-type:id_token"},
            {"actor_token": None},
            {"actor_token_type": None},
        ],
    )
    def test_malformed_requests(self, world: World, override: dict[str, Any]) -> None:
        err(delegate(world, **override), "invalid_request")

    def test_wrong_resource(self, world: World) -> None:
        err(delegate(world, resource="api://other-tool"), "invalid_target")

    def test_scope_outside_policy(self, world: World) -> None:
        err(delegate(world, scope="tickets.admin"), "invalid_scope")

    def test_client_without_policy_for_this_as(self, world: World) -> None:
        """The agent itself can't call the tool AS's delegation endpoint (not registered there)."""
        r = world.idp.token(
            TOOL_EP,
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": mint_t2(world),
                "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
                "actor_token": mint_workload(world),
                "actor_token_type": TOKEN_TYPE_ACCESS_TOKEN,
                "resource": TOOL_AUDIENCE,
                **auth(world, AGENT_CLIENT, "local:agent", TOOL_EP),
            },
        )
        err(r, "invalid_client", 401)


class TestGroupsClaim:
    """ADR-0021 §2: admin roles arrive as a `groups` claim (Okta custom-AS groups claim)."""

    def test_groups_emitted_only_for_clients_that_have_them(self, world: World) -> None:
        import dataclasses

        from tests.exchange.test_egress import claims

        def cc() -> dict[str, Any]:
            r = world.idp.token(
                WORKLOAD_EP,
                {
                    "grant_type": "client_credentials",
                    **auth(world, AGENT_CLIENT, "local:agent", WORKLOAD_EP),
                },
            )
            assert r.status == 200, r.body
            return claims(str(r.body["access_token"]))

        assert "groups" not in cc()
        reg = world.idp._clients[AGENT_CLIENT]
        world.idp._clients[AGENT_CLIENT] = dataclasses.replace(
            reg, groups=("team-alpha", "atf-registry-approvers")
        )
        assert cc()["groups"] == ["atf-registry-approvers", "team-alpha"]
