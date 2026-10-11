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
    }
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
    idp.add_authorization_server(
        AuthorizationServer("agent-alpha", "api://agent-alpha", frozenset({CHAT, OTHER}))
    )
    idp.add_authorization_server(
        AuthorizationServer("agent-beta", "api://agent-beta", frozenset({CHAT}))
    )

    signers: dict[str, KeySigner] = {
        "local:chat": InMemoryEs256Signer(_pem()),
        "local:other": InMemoryEs256Signer(_pem()),
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
    return World(idp, clock, signers, endpoint, cache, exchanger, make_profile(), at_v, idt_v)
