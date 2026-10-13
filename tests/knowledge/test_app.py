"""Knowledge server MCP endpoint (ADR-0025 §4, §6)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from atf_knowledge_server.app import Caller, caller_from_token, create_app
from atf_knowledge_server.store import LocalVectorStore, write_index
from fastapi.testclient import TestClient

from tests.knowledge.test_retrieval import ALICE_SCOPES, A, SpyStore, retriever
from tests.knowledge.test_store import corpus


def call(args: Any, rid: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": "search", "arguments": args},
    }


@pytest.fixture
def client(tmp_path: Any) -> TestClient:
    write_index(corpus(), tmp_path / "i.jsonl")
    r = retriever(SpyStore(LocalVectorStore(tmp_path / "i.jsonl")))

    def caller(headers: Any) -> Caller:
        if headers.get("authorization") != "Bearer good":
            raise ValueError("bad token")
        return Caller(user="alice", agent_id=A, chain=(), scopes=ALICE_SCOPES)

    return TestClient(create_app(r, caller))


class TestMcp:
    def test_tools_list(self, client: TestClient) -> None:
        r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        (tool,) = r.json()["result"]["tools"]
        assert tool["name"] == "search"
        assert set(tool["inputSchema"]["properties"]) == {"query", "top_k"}

    def test_search(self, client: TestClient) -> None:
        r = client.post(
            "/mcp",
            json=call({"query": "deploy pipeline", "top_k": 3}),
            headers={"Authorization": "Bearer good"},
        )
        text = r.json()["result"]["content"][0]["text"]
        assert "[eng/internal] Deploy" in text

    @pytest.mark.security
    def test_output_never_includes_embeddings_or_provenance(self, client: TestClient) -> None:
        r = client.post(
            "/mcp",
            json=call({"query": "deploy", "top_k": 5}),
            headers={"Authorization": "Bearer good"},
        )
        blob = json.dumps(r.json())
        for leak in ("s3://", "sha256", "ingested_by", "vector", "0.0"):
            assert leak not in blob

    @pytest.mark.security
    def test_call_requires_token(self, client: TestClient) -> None:
        r = client.post("/mcp", json=call({"query": "x"}))
        assert (r.status_code, r.json()["error"]["code"]) == (401, -32001)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "args",
        [
            {},
            {"query": 7},
            {"query": "x", "top_k": 50},
            {"query": "x", "collections": ["hr"]},  # agents can't supply or widen the filter
            {"query": "x" * 5000},
        ],
    )
    def test_invalid_arguments(self, client: TestClient, args: Any) -> None:
        r = client.post("/mcp", json=call(args), headers={"Authorization": "Bearer good"})
        assert r.json()["error"]["code"] == -32602

    def test_unknown_tool_and_method(self, client: TestClient) -> None:
        bad_tool = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "delete", "arguments": {}},
        }
        assert (
            client.post("/mcp", json=bad_tool, headers={"Authorization": "Bearer good"}).json()[
                "error"
            ]["code"]
            == -32602
        )
        assert (
            client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "x"}).json()["error"][
                "code"
            ]
            == -32601
        )


@pytest.mark.security
class TestCallerFromToken:
    """Real delegated tokens from the in-process IdP (tool AS stands in for the KB AS)."""

    def validator(self, world: Any) -> Any:
        from tests.exchange.conftest import BASE, TOOL_AUDIENCE
        from trustkit.jwt import TokenValidator, ValidationPolicy

        return TokenValidator(
            ValidationPolicy(
                issuer=f"{BASE}/oauth2/tool-tickets",
                audiences=frozenset({TOOL_AUDIENCE}),
                expected_typ="at+jwt",
            ),
            world.jwks(f"{BASE}/oauth2/tool-tickets/v1/keys"),
            now=world.clock,
        )

    def test_single_actor(self, world: Any) -> None:
        from tests.exchange.test_egress import binding, egress_profile

        tok = world.exchanger.exchange_delegated(binding(world), egress_profile()).token
        c = caller_from_token(self.validator(world))({"authorization": f"Bearer {tok}"})
        assert (c.user, c.agent_id, c.chain) == ("00u-alice", A, ())
        assert "tickets.read" in c.scopes

    def test_chain(self, world: Any) -> None:
        from tests.exchange.test_chains import bind_b, token_for_b
        from tests.exchange.test_egress import egress_profile

        tok = world.exchanger.exchange_delegated(
            bind_b(world, token_for_b(world)), egress_profile()
        ).token
        c = caller_from_token(self.validator(world))({"authorization": f"Bearer {tok}"})
        assert (c.agent_id, c.chain) == ("0oa-agent-beta", (A,))

    @pytest.mark.parametrize("header", [None, "", "Bearer", "Bearer x.y.z", "Basic abc"])
    def test_rejects(self, world: Any, header: Any) -> None:
        headers = {} if header is None else {"authorization": header}
        with pytest.raises(ValueError):  # noqa: PT011
            caller_from_token(self.validator(world))(headers)

    def test_token_without_act_rejected(self, world: Any) -> None:
        """Only gateway-minted delegated tokens: a user's own token has no act."""
        from tests.exchange.conftest import mint_t2

        with pytest.raises(ValueError):  # noqa: PT011
            caller_from_token(self.validator(world))({"authorization": f"Bearer {mint_t2(world)}"})


@pytest.mark.security
class TestHttpEdges:
    def test_malformed_requests(self, client: TestClient) -> None:
        assert client.post("/mcp", content=b"{nope").status_code == 400
        assert client.post("/mcp", json=[1]).status_code == 400
        h = [("Authorization", "Bearer good"), ("authorization", "Bearer good")]
        assert client.post("/mcp", json=call({"query": "x"}), headers=h).status_code == 400

    def test_backend_outage_is_503(self, tmp_path: Any) -> None:
        r = retriever(SpyStore(None), bundle=None)

        def caller(headers: Any) -> Caller:
            return Caller(user="alice", agent_id=A, chain=(), scopes=ALICE_SCOPES)

        c = TestClient(create_app(r, caller))
        resp = c.post("/mcp", json=call({"query": "x"}), headers={"Authorization": "Bearer good"})
        assert (resp.status_code, resp.json()["error"]["code"]) == (503, -32002)

    def test_ping(self, client: TestClient) -> None:
        assert client.get("/ping").json() == {"status": "ok"}


@pytest.mark.security
class TestCallerEdgeCases:
    def sign(self, world: Any, claims: dict[str, Any]) -> str:
        from tests.exchange.conftest import TOOL_AUDIENCE

        idp, now = world.idp, world.clock()
        base = {
            "iss": idp.issuer("tool-tickets"),
            "aud": TOOL_AUDIENCE,
            "sub": "00u-alice",
            "jti": "j",
            "iat": now,
            "exp": now + 60,
            "client_id": "0oa-tool-gateway",
        }
        return idp._sign(idp._server_keys["tool-tickets"], "at+jwt", {**base, **claims})

    def test_three_actors_refused(self, world: Any) -> None:
        tok = self.sign(
            world,
            {"scope": "kb.eng.read", "act": {"sub": "c", "act": {"sub": "b", "act": {"sub": "a"}}}},
        )
        with pytest.raises(ValueError):  # noqa: PT011
            caller_from_token(TestCallerFromToken().validator(world))(
                {"authorization": f"Bearer {tok}"}
            )

    def test_missing_scope_refused(self, world: Any) -> None:
        tok = self.sign(world, {"act": {"sub": A}})
        with pytest.raises(ValueError):  # noqa: PT011
            caller_from_token(TestCallerFromToken().validator(world))(
                {"authorization": f"Bearer {tok}"}
            )


class TestBuildApp:
    @pytest.fixture
    def env(self, tmp_path: Any) -> dict[str, str]:
        from tests.inference.test_wiring import _ca_pem
        from tests.policy.test_bundle import SIGNER

        (tmp_path / "ca.pem").write_bytes(_ca_pem())
        (tmp_path / "k.jwk").write_text(json.dumps(SIGNER.public_jwk()))
        write_index(corpus(), tmp_path / "index.jsonl")
        return {
            "ATF_KB_ISSUER": "https://mock-idp:8443/oauth2/knowledge",
            "ATF_KB_AUDIENCE": "api://knowledge",
            "ATF_KB_JWKS_URI": "https://mock-idp:8443/oauth2/knowledge/v1/keys",
            "ATF_CA_BUNDLE": str(tmp_path / "ca.pem"),
            "ATF_BUNDLE_ISSUER": "atf-bundle-publisher",
            "ATF_BUNDLE_PUBLIC_JWK_PATH": str(tmp_path / "k.jwk"),
            "ATF_BUNDLE_PATH": str(tmp_path / "bundle.jws"),
            "ATF_KB_INDEX_PATH": str(tmp_path / "index.jsonl"),
        }

    def test_local(self, env: dict[str, str]) -> None:
        from atf_knowledge_server.app import build_app

        c = TestClient(build_app(env))
        assert c.get("/ping").status_code == 200
        assert c.post("/mcp", json=call({"query": "x"})).status_code == 401

    def test_bedrock_backend_selected(self, env: dict[str, str]) -> None:
        from atf_knowledge_server.app import build_app

        e = {k: v for k, v in env.items() if k != "ATF_KB_INDEX_PATH"}
        assert (
            TestClient(build_app({**e, "ATF_KB_BEDROCK_ID": "KBEXAMPLE1"})).get("/ping").status_code
            == 200
        )

    @pytest.mark.security
    def test_exactly_one_backend(self, env: dict[str, str]) -> None:
        from atf_knowledge_server.app import build_app

        with pytest.raises(ValueError, match="backend"):
            build_app({**env, "ATF_KB_BEDROCK_ID": "KBEXAMPLE1"})
        with pytest.raises(ValueError, match="backend"):
            build_app({k: v for k, v in env.items() if k != "ATF_KB_INDEX_PATH"})

    def test_app_from_env(self, env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
        from atf_knowledge_server.app import app_from_env

        for k, v in env.items():
            monkeypatch.setenv(k, v)
        assert TestClient(app_from_env()).get("/ping").status_code == 200
