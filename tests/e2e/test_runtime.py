"""AgentRuntime: authorizes from T2 only (ADR-0014 §1, TM-RT-01/02)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest
from atf_agent_runtime.runtime import AgentRuntime
from joserfc.jwk import RSAKey

from tests.conftest import NOW, Mint, StaticKeys, good_claims
from trustkit.resource import Principal, ResourceAuthorizer

ISS, AUD = "https://idp.example.test/oauth2/agent-alpha", "api://agent-alpha"


def echo(p: Principal, req: Mapping[str, Any]) -> Mapping[str, Any]:
    return {"output": f"echo: {req.get('prompt', '')}"}


@pytest.fixture
def runtime(rsa_key: RSAKey) -> AgentRuntime:
    authz = ResourceAuthorizer(issuer=ISS, audience=AUD, keys=StaticKeys(rsa_key), now=lambda: NOW)
    return AgentRuntime(authorizer=authz, agent=echo)


def t2(mint: Mint, **o: Any) -> str:
    base: dict[str, Any] = {
        "iss": ISS,
        "aud": AUD,
        "client_id": "0oa-chat",
        "scope": "agent.invoke",
    }
    return mint(good_claims(**{**base, **o}), header={"typ": "at+jwt"})


class TestRuntime:
    def test_authorized_invocation(self, runtime: AgentRuntime, mint: Mint) -> None:
        r = runtime.invoke({"Authorization": f"Bearer {t2(mint)}"}, b'{"prompt": "hi"}')
        assert r.status == 200
        assert json.loads(r.body) == {"output": "echo: hi"}
        assert runtime.principals_seen[-1].subject == "00u-user-1"

    def test_header_name_case_insensitive(self, runtime: AgentRuntime, mint: Mint) -> None:
        assert runtime.invoke({"authorization": f"Bearer {t2(mint)}"}, b"{}").status == 200


@pytest.mark.security
class TestRuntimeRejects:
    def test_no_token(self, runtime: AgentRuntime) -> None:
        r = runtime.invoke({}, b"{}")
        assert r.status == 401
        assert r.headers["WWW-Authenticate"] == "Bearer"
        assert runtime.principals_seen == []

    def test_x_atf_headers_confer_nothing(self, runtime: AgentRuntime) -> None:
        """TM-RT-02: advisory headers alone never authorize."""
        r = runtime.invoke({"x-atf-decision": "allow", "x-atf-request-id": "r1"}, b"{}")
        assert r.status == 401

    def test_identity_comes_from_t2_not_headers(self, runtime: AgentRuntime, mint: Mint) -> None:
        """TM-RT-02: forged hints don't change who the runtime thinks is calling."""
        runtime.invoke({"Authorization": f"Bearer {t2(mint)}", "x-atf-subject": "00u-admin"}, b"{}")
        assert runtime.principals_seen[-1].subject == "00u-user-1"

    def test_duplicate_authorization_headers(self, runtime: AgentRuntime, mint: Mint) -> None:
        """Header smuggling: two case-variant credentials are ambiguous, so never pick one."""
        r = runtime.invoke(
            {"Authorization": f"Bearer {t2(mint)}", "authorization": "Bearer x"}, b"{}"
        )
        assert r.status == 401
        assert runtime.principals_seen == []

    def test_wrong_scope_403(self, runtime: AgentRuntime, mint: Mint) -> None:
        r = runtime.invoke({"Authorization": f"Bearer {t2(mint, scope='agent.read')}"}, b"{}")
        assert r.status == 403
        assert "insufficient_scope" in r.headers["WWW-Authenticate"]

    @pytest.mark.parametrize("body", [b"not json", b"[1]", b'"s"'])
    def test_body_must_be_json_object(self, runtime: AgentRuntime, mint: Mint, body: bytes) -> None:
        assert runtime.invoke({"Authorization": f"Bearer {t2(mint)}"}, body).status == 400

    def test_body_size_limit(self, runtime: AgentRuntime, mint: Mint) -> None:
        big = json.dumps({"prompt": "x" * 300_000}).encode()
        assert runtime.invoke({"Authorization": f"Bearer {t2(mint)}"}, big).status == 413

    def test_authz_before_body_parsing(self, runtime: AgentRuntime) -> None:
        """Unauthenticated callers get 401, not a parser oracle (400/413)."""
        assert runtime.invoke({}, b"not json").status == 401

    def test_error_bodies_are_generic(self, runtime: AgentRuntime, mint: Mint) -> None:
        tok = t2(mint, aud="api://other")
        r = runtime.invoke({"Authorization": f"Bearer {tok}"}, b"{}")
        assert r.status == 401
        assert json.loads(r.body) == {"error": "unauthorized"}
        for seg in tok.split("."):
            assert seg.encode() not in r.body

    def test_agent_exception_is_500_without_details(self, rsa_key: RSAKey, mint: Mint) -> None:
        def broken(p: Principal, req: Mapping[str, Any]) -> Mapping[str, Any]:
            raise RuntimeError("secret internal detail")

        authz = ResourceAuthorizer(
            issuer=ISS, audience=AUD, keys=StaticKeys(rsa_key), now=lambda: NOW
        )
        r = AgentRuntime(authorizer=authz, agent=broken).invoke(
            {"Authorization": f"Bearer {t2(mint)}"}, b"{}"
        )
        assert r.status == 500
        assert b"secret" not in r.body
