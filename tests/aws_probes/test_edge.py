"""The ingress edge as deployed (A-8, A-9, ADR-0012 §4, ADR-0026 §15/§22)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from trustkit.policy import RESERVED_HEADERS


def test_gateway_runs_the_interceptor_on_both_phases(aws: Any, outputs: dict[str, Any]) -> None:
    gw = aws.client("bedrock-agentcore-control").get_gateway(
        gatewayIdentifier=outputs["gateway_id"]
    )
    ic = gw["interceptorConfigurations"][0]
    assert set(ic["interceptionPoints"]) == {"REQUEST", "RESPONSE"}
    assert ic["inputConfiguration"]["passRequestHeaders"] is True
    assert gw["authorizerType"] == "CUSTOM_JWT"
    assert "policyEngineConfiguration" not in gw  # the signed bundle is the only policy source


def test_target_allowlist_is_exactly_the_reserved_headers(
    aws: Any, outputs: dict[str, Any]
) -> None:
    """A-9 / ADR-0012 §4: as stored by AWS, not just as written in Terraform."""
    ctl = aws.client("bedrock-agentcore-control")
    (summary,) = ctl.list_gateway_targets(gatewayIdentifier=outputs["gateway_id"])["items"]
    target = ctl.get_gateway_target(
        gatewayIdentifier=outputs["gateway_id"], targetId=summary["targetId"]
    )
    allowed = {h.lower() for h in target["metadataConfiguration"]["allowedRequestHeaders"]}
    assert allowed == set(RESERVED_HEADERS)


def test_gateway_id_parameter_matches(aws: Any, outputs: dict[str, Any]) -> None:
    """ADR-0026 §22: the interceptor binds exactly this id at cold start."""
    name = outputs["interceptor_environment"]["ATF_GATEWAY_ID_PARAMETER"]
    value = aws.client("ssm").get_parameter(Name=name)["Parameter"]["Value"]
    assert value == outputs["gateway_id"]


@pytest.mark.security
@pytest.mark.parametrize("auth", [None, "Bearer not-a-jwt"])
def test_unauthenticated_calls_never_reach_the_agent(
    outputs: dict[str, Any], auth: str | None
) -> None:
    """TM-RT-01 at the edge: the JWT authorizer refuses before the interceptor or the runtime."""
    headers = {"Authorization": auth} if auth else {}
    r = httpx.post(
        f"{outputs['gateway_url'].rstrip('/')}/invocations", json={}, headers=headers, timeout=15
    )
    assert r.status_code in (401, 403)
