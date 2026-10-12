"""Mock IdP conformance: RFC 8693 -> ID-JAG, RFC 7523 -> RFC 9068 T2, private_key_jwt client auth.

These tests pin the mock to the specs. Every later trustkit exchange test trusts this mock,
so a lenient mock would silently make lenient client code look correct.
"""

from __future__ import annotations

import base64
import itertools
import json
from typing import Any

import pytest
from joserfc import jwt as jose_jwt
from joserfc.jwk import ECKey, KeySet

from mock_idp.core import (
    ACCESS_TOKEN_TYP,
    CLIENT_ASSERTION_TYPE,
    GRANT_JWT_BEARER,
    GRANT_TOKEN_EXCHANGE,
    ID_JAG_TYP,
    TOKEN_TYPE_ID_JAG,
    TOKEN_TYPE_ID_TOKEN,
    AuthorizationServer,
    ClientRegistration,
    MockIdp,
    TokenResponse,
)

T0 = 1_800_000_000
CHAT, OTHER = "0oa-chat", "0oa-other"
USER = "00u-alice"


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> int:
        return self.t


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture(scope="module")
def keys() -> dict[str, ECKey]:
    return {
        c: ECKey.generate_key("P-256", parameters={"kid": f"{c}-k1"}, private=True)
        for c in (CHAT, OTHER, "attacker")
    }


@pytest.fixture
def idp(clock: Clock, keys: dict[str, ECKey]) -> MockIdp:
    idp = MockIdp(now=clock)
    for as_id, aud, clients in [
        ("ingress", "api://agent-ingress", {CHAT, OTHER}),
        ("agent-alpha", "api://agent-alpha", {CHAT, OTHER}),
        ("agent-beta", "api://agent-beta", {CHAT}),
    ]:
        idp.add_authorization_server(AuthorizationServer(as_id, aud, frozenset(clients)))
    idp.register_client(
        ClientRegistration(
            CHAT,
            {"keys": [keys[CHAT].as_dict(private=False)]},
            {idp.issuer("agent-alpha"): frozenset({"agent.invoke", "agent.read"})},
        )
    )
    idp.register_client(ClientRegistration(OTHER, {"keys": [keys[OTHER].as_dict(private=False)]}))
    return idp


# ----------------------------------------------------------------------------- helpers


_jti = itertools.count()


def client_assertion(
    idp: MockIdp, key: ECKey, client_id: str, endpoint: str, **overrides: Any
) -> str:
    now = idp.now()
    claims: dict[str, Any] = {
        "iss": client_id,
        "sub": client_id,
        "aud": endpoint,
        "iat": now,
        "exp": now + 60,
        "jti": f"assertion-{next(_jti)}",
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jose_jwt.encode({"alg": "ES256", "kid": key.kid}, claims, key, algorithms=["ES256"])


def client_auth(
    idp: MockIdp, key: ECKey, client_id: str, endpoint: str, **kw: Any
) -> dict[str, str]:
    return {
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": client_assertion(idp, key, client_id, endpoint, **kw),
    }


def exchange_form(idp: MockIdp, id_token: str, **overrides: str | None) -> dict[str, str]:
    form: dict[str, str | None] = {
        "grant_type": GRANT_TOKEN_EXCHANGE,
        "requested_token_type": TOKEN_TYPE_ID_JAG,
        "subject_token": id_token,
        "subject_token_type": TOKEN_TYPE_ID_TOKEN,
        "audience": idp.issuer("agent-alpha"),
        "scope": "agent.invoke",
    }
    form.update(overrides)
    return {k: v for k, v in form.items() if v is not None}


def do_exchange(
    idp: MockIdp,
    keys: dict[str, ECKey],
    *,
    client: str = CHAT,
    key: str | None = None,
    id_token: str | None = None,
    auth: dict[str, str] | None = None,
    **form: str | None,
) -> TokenResponse:
    ep = idp.token_endpoint()
    if id_token is None:
        _, id_token = idp.login(USER, client, ingress_as_id="ingress")
    auth = auth if auth is not None else client_auth(idp, keys[key or client], client, ep)
    return idp.token(ep, {**exchange_form(idp, id_token, **form), **auth})


def do_redeem(
    idp: MockIdp,
    keys: dict[str, ECKey],
    id_jag: str,
    *,
    as_id: str = "agent-alpha",
    client: str = CHAT,
    auth: dict[str, str] | None = None,
) -> TokenResponse:
    ep = idp.token_endpoint(as_id)
    auth = auth if auth is not None else client_auth(idp, keys[client], client, ep)
    return idp.token(ep, {"grant_type": GRANT_JWT_BEARER, "assertion": id_jag, **auth})


def verify(token: str, jwks: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Independent verification with joserfc, used to check what the mock *issues*."""
    t = jose_jwt.decode(token, KeySet.import_key_set(jwks))  # type: ignore[arg-type]
    return dict(t.header), dict(t.claims)


def unverified_claims(token: str) -> dict[str, Any]:
    seg = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))  # type: ignore[no-any-return]


def assert_error(resp: TokenResponse, error: str, status: int = 400) -> None:
    assert resp.status == status, resp
    assert resp.body["error"] == error, resp.body
    assert "access_token" not in resp.body


# ----------------------------------------------------------------------------- happy path


class TestFullFlow:
    def test_login_tokens(self, idp: MockIdp) -> None:
        at, idt = idp.login(USER, CHAT, ingress_as_id="ingress", auth_time=T0 - 100)
        at_h, at_c = verify(at, idp.jwks("ingress"))
        assert at_h["typ"] == ACCESS_TOKEN_TYP
        assert at_c["iss"] == idp.issuer("ingress")
        assert at_c["aud"] == "api://agent-ingress"
        assert (at_c["sub"], at_c["cid"]) == (USER, CHAT)
        _, idt_c = verify(idt, idp.jwks())
        assert (idt_c["iss"], idt_c["aud"], idt_c["sub"]) == (idp.org_issuer, CHAT, USER)
        assert idt_c["auth_time"] == T0 - 100

    def test_exchange_then_redeem(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        r = do_exchange(idp, keys)
        assert r.status == 200, r.body
        assert r.body["issued_token_type"] == TOKEN_TYPE_ID_JAG
        assert r.body["token_type"] == "N_A"
        assert r.body["expires_in"] == 60
        jag_h, jag = verify(r.body["access_token"], idp.jwks())
        assert jag_h["typ"] == ID_JAG_TYP
        assert jag["aud"] == idp.issuer("agent-alpha")
        assert (jag["iss"], jag["sub"], jag["client_id"]) == (idp.org_issuer, USER, CHAT)
        assert jag["scope"] == "agent.invoke"
        assert jag["exp"] - jag["iat"] == 60

        t2r = do_redeem(idp, keys, r.body["access_token"])
        assert t2r.status == 200, t2r.body
        assert t2r.body["token_type"] == "Bearer"
        assert t2r.body["expires_in"] == 300
        assert t2r.body["scope"] == "agent.invoke"
        t2_h, t2 = verify(t2r.body["access_token"], idp.jwks("agent-alpha"))
        assert t2_h["typ"] == ACCESS_TOKEN_TYP
        assert t2["iss"] == idp.issuer("agent-alpha")
        assert t2["aud"] == "api://agent-alpha"
        assert (t2["sub"], t2["client_id"], t2["scope"]) == (USER, CHAT, "agent.invoke")
        assert t2["exp"] - t2["iat"] == 300

    def test_issuers_use_distinct_signing_keys(self, idp: MockIdp) -> None:
        """A token signed by one AS must not verify under another AS's JWKS."""
        kids = {
            k["kid"] for asid in (None, "ingress", "agent-alpha") for k in idp.jwks(asid)["keys"]
        }
        assert len(kids) == 3

    def test_jwks_are_public_only(self, idp: MockIdp) -> None:
        for asid in (None, "ingress", "agent-alpha"):
            for k in idp.jwks(asid)["keys"]:
                assert "d" not in k


# ----------------------------------------------------------------------------- client auth


@pytest.mark.security
class TestClientAuthentication:
    """Applies to both endpoints; exercised on the org AS. TM-EXC-01."""

    def test_missing_assertion(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        assert_error(do_exchange(idp, keys, auth={}), "invalid_client", 401)

    def test_wrong_assertion_type(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        auth = client_auth(idp, keys[CHAT], CHAT, idp.token_endpoint())
        auth["client_assertion_type"] = "urn:something:else"
        assert_error(do_exchange(idp, keys, auth=auth), "invalid_client", 401)

    def test_client_secret_not_accepted(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        """private_key_jwt only: shared secrets are not a supported auth method."""
        assert_error(
            do_exchange(idp, keys, auth={"client_id": CHAT, "client_secret": "s"}),
            "invalid_client",
            401,
        )

    def test_signed_by_unregistered_key(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        assert_error(do_exchange(idp, keys, key="attacker"), "invalid_client", 401)

    def test_unknown_client(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        auth = client_auth(idp, keys["attacker"], "0oa-unknown", idp.token_endpoint())
        assert_error(do_exchange(idp, keys, auth=auth), "invalid_client", 401)

    @pytest.mark.parametrize(
        "override",
        [
            pytest.param(
                {"aud": "https://idp.example.test/oauth2/agent-alpha/v1/token"},
                id="aud-other-endpoint",
            ),
            pytest.param({"aud": "https://idp.example.test"}, id="aud-issuer-not-endpoint"),
            pytest.param({"sub": OTHER}, id="iss-ne-sub"),
            pytest.param({"exp": T0 - 1}, id="expired"),
            pytest.param({"exp": T0 + 3600}, id="lifetime-over-60s"),
            pytest.param({"exp": None}, id="no-exp"),
            pytest.param({"jti": None}, id="no-jti"),
        ],
    )
    def test_bad_assertion_claims(
        self, idp: MockIdp, keys: dict[str, ECKey], override: dict[str, Any]
    ) -> None:
        auth = client_auth(idp, keys[CHAT], CHAT, idp.token_endpoint(), **override)
        assert_error(do_exchange(idp, keys, auth=auth), "invalid_client", 401)

    def test_assertion_replay(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        """TM-EXC-08: the same client assertion twice is a replay."""
        auth = client_auth(idp, keys[CHAT], CHAT, idp.token_endpoint())
        assert do_exchange(idp, keys, auth=auth).status == 200
        assert_error(do_exchange(idp, keys, auth=auth), "invalid_client", 401)

    def test_client_id_param_must_match_assertion(
        self, idp: MockIdp, keys: dict[str, ECKey]
    ) -> None:
        auth = {**client_auth(idp, keys[CHAT], CHAT, idp.token_endpoint()), "client_id": OTHER}
        assert_error(do_exchange(idp, keys, auth=auth), "invalid_client", 401)


# ----------------------------------------------------------------------------- exchange


@pytest.mark.security
class TestTokenExchange:
    def test_unsupported_grant(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        assert_error(
            do_exchange(idp, keys, grant_type="client_credentials"), "unsupported_grant_type"
        )

    def test_wrong_requested_token_type(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        r = do_exchange(
            idp, keys, requested_token_type="urn:ietf:params:oauth:token-type:access_token"
        )
        assert_error(r, "invalid_request")

    def test_wrong_subject_token_type(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        r = do_exchange(
            idp, keys, subject_token_type="urn:ietf:params:oauth:token-type:access_token"
        )
        assert_error(r, "invalid_request")

    @pytest.mark.parametrize("missing", ["subject_token", "audience"])
    def test_missing_param(self, idp: MockIdp, keys: dict[str, ECKey], missing: str) -> None:
        assert_error(do_exchange(idp, keys, **{missing: None}), "invalid_request")

    def test_access_token_as_subject(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        """An access token labelled as an ID token is not an ID token (wrong issuer)."""
        at, _ = idp.login(USER, CHAT, ingress_as_id="ingress")
        assert_error(do_exchange(idp, keys, id_token=at), "invalid_grant")

    def test_expired_id_token(self, idp: MockIdp, keys: dict[str, ECKey], clock: Clock) -> None:
        _, idt = idp.login(USER, CHAT, ingress_as_id="ingress")
        clock.t += 7200
        assert_error(do_exchange(idp, keys, id_token=idt), "invalid_grant")

    def test_tampered_id_token(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        _, idt = idp.login(USER, CHAT, ingress_as_id="ingress")
        h, _, s = idt.split(".")
        forged = (
            base64.urlsafe_b64encode(
                json.dumps({**unverified_claims(idt), "sub": "00u-admin"}).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        assert_error(do_exchange(idp, keys, id_token=f"{h}.{forged}.{s}"), "invalid_grant")

    def test_strict_subject_token_audience(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        """ADR-0009 / A-4: a client may only exchange ID tokens issued *to it*."""
        _, chat_idt = idp.login(USER, CHAT, ingress_as_id="ingress")
        assert_error(do_exchange(idp, keys, client=OTHER, id_token=chat_idt), "invalid_grant")

    def test_unknown_audience(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        assert_error(
            do_exchange(idp, keys, audience="https://evil.test/oauth2/x"), "invalid_target"
        )

    def test_audience_not_in_client_policy(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        """ADR-0009: a front end may only mint ID-JAGs for the agents it fronts."""
        r = do_exchange(idp, keys, audience=idp.issuer("agent-beta"))
        assert_error(r, "unauthorized_client")

    def test_scope_outside_policy(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        assert_error(do_exchange(idp, keys, scope="agent.invoke agent.admin"), "invalid_scope")

    def test_error_descriptions_never_echo_tokens(
        self, idp: MockIdp, keys: dict[str, ECKey]
    ) -> None:
        _, idt = idp.login(USER, CHAT, ingress_as_id="ingress")
        r = do_exchange(idp, keys, client=OTHER, id_token=idt)
        blob = json.dumps(dict(r.body))
        for seg in idt.split("."):
            assert seg not in blob


# ----------------------------------------------------------------------------- jwt-bearer


@pytest.mark.security
class TestJwtBearer:
    @pytest.fixture
    def id_jag(self, idp: MockIdp, keys: dict[str, ECKey]) -> str:
        r = do_exchange(idp, keys)
        assert r.status == 200, r.body
        return str(r.body["access_token"])

    def test_missing_assertion(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        ep = idp.token_endpoint("agent-alpha")
        r = idp.token(
            ep, {"grant_type": GRANT_JWT_BEARER, **client_auth(idp, keys[CHAT], CHAT, ep)}
        )
        assert_error(r, "invalid_request")

    def test_replay(self, idp: MockIdp, keys: dict[str, ECKey], id_jag: str) -> None:
        """TM-EXC-08: an ID-JAG is single-use."""
        assert do_redeem(idp, keys, id_jag).status == 200
        assert_error(do_redeem(idp, keys, id_jag), "invalid_grant")

    def test_expired(self, idp: MockIdp, keys: dict[str, ECKey], id_jag: str, clock: Clock) -> None:
        clock.t += 61
        assert_error(do_redeem(idp, keys, id_jag), "invalid_grant")

    def test_redeemed_at_wrong_as(self, idp: MockIdp, keys: dict[str, ECKey], id_jag: str) -> None:
        """ID-JAG aud names agent-alpha's AS; agent-beta's AS must refuse it."""
        assert_error(do_redeem(idp, keys, id_jag, as_id="agent-beta"), "invalid_grant")

    def test_redeemed_by_other_client(
        self, idp: MockIdp, keys: dict[str, ECKey], id_jag: str
    ) -> None:
        """Stolen ID-JAG is useless without the client it was issued to."""
        assert_error(do_redeem(idp, keys, id_jag, client=OTHER), "invalid_grant")

    def test_client_not_registered_at_as(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        idp.register_client(
            ClientRegistration(
                OTHER,
                {"keys": [keys[OTHER].as_dict(private=False)]},
                {idp.issuer("agent-beta"): frozenset({"agent.invoke"})},
            )
        )
        r = do_exchange(idp, keys, client=OTHER, audience=idp.issuer("agent-beta"))
        assert r.status == 200, r.body
        assert_error(
            do_redeem(idp, keys, r.body["access_token"], as_id="agent-beta", client=OTHER),
            "invalid_client",
            401,
        )

    def test_id_token_is_not_an_id_jag(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        """typ confusion: an org-signed ID token must not be redeemable as an ID-JAG."""
        _, idt = idp.login(USER, CHAT, ingress_as_id="ingress")
        assert_error(do_redeem(idp, keys, idt), "invalid_grant")

    def test_forged_id_jag(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        """Signed by someone other than the org AS."""
        fake = jose_jwt.encode(
            {"alg": "ES256", "typ": ID_JAG_TYP, "kid": keys["attacker"].kid},
            {
                "iss": idp.org_issuer,
                "sub": USER,
                "aud": idp.issuer("agent-alpha"),
                "client_id": CHAT,
                "jti": "x",
                "iat": T0,
                "exp": T0 + 60,
                "scope": "agent.invoke",
            },
            keys["attacker"],
            algorithms=["ES256"],
        )
        assert_error(do_redeem(idp, keys, fake), "invalid_grant")


@pytest.mark.security
class TestOracleRejectPaths:
    """The mock is the oracle for every exchange test, so its reject paths are tested too."""

    @pytest.mark.parametrize("junk", ["not-a-jwt", "a.!!!.c", "a.W10.c"])
    def test_malformed_client_assertion(
        self, idp: MockIdp, keys: dict[str, ECKey], junk: str
    ) -> None:
        auth = {"client_assertion_type": CLIENT_ASSERTION_TYPE, "client_assertion": junk}
        assert_error(do_exchange(idp, keys, auth=auth), "invalid_client", 401)

    def test_unknown_endpoint(self, idp: MockIdp) -> None:
        assert_error(
            idp.token("https://idp.example.test/oauth2/nope/v1/token", {}), "invalid_request", 404
        )

    def test_id_jag_as_subject_token(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        """typ confusion the other way: an ID-JAG must not be re-exchanged as an ID token."""
        jag = do_exchange(idp, keys).body["access_token"]
        assert_error(do_exchange(idp, keys, id_token=jag), "invalid_grant")

    def test_wrong_grant_at_custom_as(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        ep = idp.token_endpoint("agent-alpha")
        form = {"grant_type": "authorization_code", **client_auth(idp, keys[CHAT], CHAT, ep)}
        assert_error(idp.token(ep, form), "unsupported_grant_type")

    def test_assertion_issued_in_future(self, idp: MockIdp, keys: dict[str, ECKey]) -> None:
        auth = client_auth(idp, keys[CHAT], CHAT, idp.token_endpoint(), iat=T0 + 120, exp=T0 + 150)
        assert_error(do_exchange(idp, keys, auth=auth), "invalid_client", 401)

    def test_multi_audience_id_token_accepted_when_it_contains_client(
        self, idp: MockIdp, keys: dict[str, ECKey]
    ) -> None:
        idt = idp._sign(
            idp._org_key,
            "JWT",
            {
                "iss": idp.org_issuer,
                "sub": USER,
                "aud": [CHAT, "other-app"],
                "iat": T0,
                "exp": T0 + 600,
            },
        )
        assert do_exchange(idp, keys, id_token=idt).status == 200

    @pytest.mark.parametrize(
        "claims",
        [
            pytest.param({"iss": "https://evil.test", "sub": USER, "aud": CHAT}, id="wrong-iss"),
            pytest.param({"iss": "https://idp.example.test", "aud": CHAT}, id="no-sub"),
            pytest.param({"iss": "https://idp.example.test", "sub": USER, "aud": 7}, id="bad-aud"),
        ],
    )
    def test_org_signed_but_invalid_id_token(
        self, idp: MockIdp, keys: dict[str, ECKey], claims: dict[str, Any]
    ) -> None:
        idt = idp._sign(idp._org_key, "JWT", {**claims, "iat": T0, "exp": T0 + 600})
        assert_error(do_exchange(idp, keys, id_token=idt), "invalid_grant")
