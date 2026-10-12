"""An in-process world: mock IdP + real trustkit binding/exchange, with fault injection."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mock_idp.core import AuthorizationServer, ClientRegistration, MockIdp
from trustkit.binding import BoundIdentity, bind
from trustkit.cache import TokenCache
from trustkit.exchange import (
    ExchangeResult,
    HttpResult,
    IdJagExchanger,
    TransportError,
)
from trustkit.jwt import JwksKeyResolver, KeyResolver, TokenValidator, ValidationPolicy
from trustkit.profiles import GatewayProfile, load_profiles
from trustkit.signing import InMemoryEs256Signer, KeySigner, SigningError

BASE = "https://idp.example.test"
CHAT, OTHER = "0oa-chat", "0oa-other"
AGENT_CLIENT, AGENT_BETA_CLIENT, GATEWAY_CLIENT = (
    "0oa-agent-alpha",
    "0oa-agent-beta",
    "0oa-tool-gateway",
)
TOOL_AUDIENCE = "api://tool-tickets"
ALICE, BOB = "00u-alice", "00u-bob"
T0 = 1_800_000_000


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> int:
        return self.t


@dataclass
class RecordingEndpoint:
    """TokenEndpoint over the in-process mock, with hooks for fault injection."""

    idp: MockIdp
    calls: list[tuple[str, dict[str, str]]] = field(default_factory=list)
    transport_failures: int = 0
    rewrite_request: Callable[[str, dict[str, str]], dict[str, str]] | None = None
    rewrite_response: Callable[[str, HttpResult], HttpResult] | None = None

    def post_form(self, url: str, form: Mapping[str, str]) -> HttpResult:
        f = dict(form)
        self.calls.append((url, f))
        if self.transport_failures > 0:
            self.transport_failures -= 1
            raise TransportError("simulated")
        if self.rewrite_request:
            f = self.rewrite_request(url, f)
        r = self.idp.token(url, f)
        result = HttpResult(r.status, dict(r.body))
        return self.rewrite_response(url, result) if self.rewrite_response else result


def _pem() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def profile_doc(**overrides: Any) -> dict[str, Any]:
    p: dict[str, Any] = {
        "profile_id": "agent-alpha-ingress",
        "gateway_id": "gw-alpha",
        "flow": "ingress",
        "enabled": True,
        "idp": {
            "issuer": BASE,
            "jwks_uri": f"{BASE}/oauth2/v1/keys",
            "token_endpoint": f"{BASE}/oauth2/v1/token",
            "resource_issuer": f"{BASE}/oauth2/agent-alpha",
            "resource_token_endpoint": f"{BASE}/oauth2/agent-alpha/v1/token",
            "resource_jwks_uri": f"{BASE}/oauth2/agent-alpha/v1/keys",
        },
        "target": {"audience": "api://agent-alpha", "scopes": ["agent.invoke"]},
        "ingress_clients": {CHAT: "local:chat"},
        "max_auth_age_s": 43_200,
        "ingress_token": {
            "issuer": f"{BASE}/oauth2/ingress",
            "audiences": ["api://agent-ingress"],
            "jwks_uri": f"{BASE}/oauth2/ingress/v1/keys",
        },
    }
    p.update(overrides)
    return p


def egress_doc(**overrides: Any) -> dict[str, Any]:
    """A valid egress (tool gateway) profile per ADR-0016."""
    p = profile_doc(
        profile_id="tools-egress",
        gateway_id="gw-tools",
        flow="egress",
        idp={
            "issuer": BASE,
            "jwks_uri": f"{BASE}/oauth2/v1/keys",
            "token_endpoint": f"{BASE}/oauth2/v1/token",
            "resource_issuer": f"{BASE}/oauth2/tool-tickets",
            "resource_token_endpoint": f"{BASE}/oauth2/tool-tickets/v1/token",
            "resource_jwks_uri": f"{BASE}/oauth2/tool-tickets/v1/keys",
        },
        target={"audience": TOOL_AUDIENCE, "scopes": ["tickets.read", "tickets.write"]},
        client={"client_id": "0oa-tool-gateway", "signing_key": "local:gateway"},
        egress_inbound={
            "issuer": f"{BASE}/oauth2/workload",
            "audiences": ["api://tool-gateway"],
            "jwks_uri": f"{BASE}/oauth2/workload/v1/keys",
        },
        agents={
            AGENT_CLIENT: {
                "t2_issuer": f"{BASE}/oauth2/agent-alpha",
                "t2_audience": "api://agent-alpha",
                "t2_jwks_uri": f"{BASE}/oauth2/agent-alpha/v1/keys",
                "allowed_scopes": ["tickets.read"],
            }
        },
    )
    for k in ("ingress_clients", "max_auth_age_s", "ingress_token"):
        del p[k]
    p.update(overrides)
    return p


def make_profile(**overrides: Any) -> GatewayProfile:
    reg = load_profiles(json.dumps({"version": 1, "profiles": [profile_doc(**overrides)]}))
    assert not reg.rejected, reg.rejected
    return reg.lookup(overrides.get("gateway_id", "gw-alpha"))


@dataclass
class World:
    idp: MockIdp
    clock: Clock
    signers: dict[str, KeySigner]
    endpoint: RecordingEndpoint
    cache: TokenCache[ExchangeResult]
    exchanger: IdJagExchanger
    profile: GatewayProfile
    at_validator: TokenValidator
    idt_validator: TokenValidator
    jwks: Callable[[str], KeyResolver]

    def login_and_bind(self, user: str = ALICE, client: str = CHAT) -> BoundIdentity:
        at, idt = self.idp.login(user, client, ingress_as_id="ingress")
        return self.bind(at, idt)

    def bind(self, at: str, idt: str) -> BoundIdentity:
        return bind(
            at,
            idt,
            access_token_validator=self.at_validator,
            id_token_validator=self.idt_validator,
            allowed_clients=frozenset({CHAT, OTHER}),
            max_auth_age_s=43_200,
            now=self.clock,
        )

    def idp_calls(self) -> int:
        return len(self.endpoint.calls)


@pytest.fixture
def world() -> World:
    clock = Clock()
    idp = MockIdp(BASE, now=clock)
    idp.add_authorization_server(
        AuthorizationServer("ingress", "api://agent-ingress", frozenset({CHAT, OTHER}))
    )
    for server in (
        AuthorizationServer(
            "agent-alpha", "api://agent-alpha", frozenset({CHAT, OTHER}), AGENT_CLIENT
        ),
        AuthorizationServer("agent-beta", "api://agent-beta", frozenset({CHAT}), AGENT_BETA_CLIENT),
        AuthorizationServer(
            "workload", "api://tool-gateway", frozenset({AGENT_CLIENT, AGENT_BETA_CLIENT})
        ),
        AuthorizationServer("tool-tickets", TOOL_AUDIENCE, frozenset({GATEWAY_CLIENT})),
    ):
        idp.add_authorization_server(server)

    signers: dict[str, KeySigner] = {
        ref: InMemoryEs256Signer(_pem())
        for ref in ("local:chat", "local:other", "local:agent", "local:agent-beta", "local:gateway")
    }
    for client, ref in ((CHAT, "local:chat"), (OTHER, "local:other")):
        s = signers[ref]
        assert isinstance(s, InMemoryEs256Signer)
        idp.register_client(
            ClientRegistration(
                client,
                {"keys": [{**s.public_jwk(), "kid": s.key_id}]},
                {
                    idp.issuer("agent-alpha"): frozenset({"agent.invoke", "agent.admin"}),
                    idp.issuer("agent-beta"): frozenset({"agent.invoke"}),
                },
            )
        )

    for client, ref, policy in (
        (AGENT_CLIENT, "local:agent", {idp.issuer("workload"): frozenset({"tools.invoke"})}),
        (
            AGENT_BETA_CLIENT,
            "local:agent-beta",
            {idp.issuer("workload"): frozenset({"tools.invoke"})},
        ),
        (
            GATEWAY_CLIENT,
            "local:gateway",
            {idp.issuer("tool-tickets"): frozenset({"tickets.read", "tickets.write"})},
        ),
    ):
        sg = signers[ref]
        assert isinstance(sg, InMemoryEs256Signer)
        idp.register_client(
            ClientRegistration(client, {"keys": [{**sg.public_jwk(), "kid": sg.key_id}]}, policy)
        )

    resolvers: dict[str, KeyResolver] = {}

    def jwks(uri: str) -> KeyResolver:
        if uri not in resolvers:
            as_id = (
                None
                if uri == f"{BASE}/oauth2/v1/keys"
                else uri.removeprefix(f"{BASE}/oauth2/").split("/")[0]
            )
            resolvers[uri] = JwksKeyResolver(
                fetch=lambda: idp.jwks(as_id), now=lambda: float(clock())
            )
        return resolvers[uri]

    def signer_for(ref: str) -> KeySigner:
        if ref not in signers:
            raise SigningError("unknown key reference")
        return signers[ref]

    endpoint = RecordingEndpoint(idp)
    cache: TokenCache[ExchangeResult] = TokenCache(now=clock)
    exchanger = IdJagExchanger(http=endpoint, signers=signer_for, jwks=jwks, cache=cache, now=clock)
    at_v = TokenValidator(
        ValidationPolicy(
            issuer=idp.issuer("ingress"), audiences=frozenset({"api://agent-ingress"})
        ),
        jwks(f"{BASE}/oauth2/ingress/v1/keys"),
        now=clock,
    )
    idt_v = TokenValidator(
        ValidationPolicy(issuer=BASE, audiences=frozenset({CHAT, OTHER})),
        jwks(f"{BASE}/oauth2/v1/keys"),
        now=clock,
    )
    return World(idp, clock, signers, endpoint, cache, exchanger, make_profile(), at_v, idt_v, jwks)


# ----------------------------------------------------------------------------- egress helpers


def mint_t2(
    world: World, user: str = ALICE, agent_as: str = "agent-alpha", client: str = CHAT
) -> str:
    """A genuine ingress T2 for ``user`` at ``agent_as`` (ID-JAG + JWT-bearer via the mock)."""
    from trustkit.signing import build_client_assertion

    idp = world.idp
    _, idt = idp.login(user, client, ingress_as_id="ingress")
    ref = "local:chat" if client == CHAT else "local:other"

    def assertion(ep: str) -> str:
        return build_client_assertion(
            world.signers[ref], client_id=client, token_endpoint=ep, now=world.clock
        )

    ep = idp.token_endpoint()
    jag = idp.token(
        ep,
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            "subject_token": idt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "audience": idp.issuer(agent_as),
            "scope": "agent.invoke",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(ep),
        },
    )
    assert jag.status == 200, jag.body
    ep2 = idp.token_endpoint(agent_as)
    t2 = idp.token(
        ep2,
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jag.body["access_token"],
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion(ep2),
        },
    )
    assert t2.status == 200, t2.body
    return str(t2.body["access_token"])


def mint_workload(world: World, agent: str = AGENT_CLIENT) -> str:
    """A genuine workload token for ``agent`` via client_credentials at the workload AS."""
    from trustkit.signing import build_client_assertion

    ref = {AGENT_CLIENT: "local:agent", AGENT_BETA_CLIENT: "local:agent-beta"}[agent]
    ep = world.idp.token_endpoint("workload")
    r = world.idp.token(
        ep,
        {
            "grant_type": "client_credentials",
            "scope": "tools.invoke",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": build_client_assertion(
                world.signers[ref], client_id=agent, token_endpoint=ep, now=world.clock
            ),
        },
    )
    assert r.status == 200, r.body
    return str(r.body["access_token"])
