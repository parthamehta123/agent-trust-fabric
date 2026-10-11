"""IdJagExchanger end-to-end against the mock IdP (ADR-0002/0009/0011)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.exchange.conftest import ALICE, BASE, BOB, CHAT, OTHER, World, make_profile
from trustkit.exchange import (
    CLIENT_ASSERTION_TYPE,
    GRANT_JWT_BEARER,
    GRANT_TOKEN_EXCHANGE,
    ExchangeError,
    ExchangeReason,
    HttpResult,
)


def assert_denied(
    world: World, reason: ExchangeReason, profile: Any = None, **kw: Any
) -> ExchangeError:
    bound = kw.pop("bound", None) or world.login_and_bind()
    with pytest.raises(ExchangeError) as ei:
        world.exchanger.exchange(bound, profile or world.profile)
    assert ei.value.reason is reason, f"expected {reason}, got {ei.value.reason} ({ei.value})"
    return ei.value


# ----------------------------------------------------------------------------- happy path


class TestExchange:
    def test_t2_is_scoped_to_target(self, world: World) -> None:
        r = world.exchanger.exchange(world.login_and_bind(), world.profile)
        assert not r.cached
        c = r.claims.claims
        assert c["iss"] == f"{BASE}/oauth2/agent-alpha"
        assert c["aud"] == "api://agent-alpha"
        assert (c["sub"], c["client_id"], c["scope"]) == (ALICE, CHAT, "agent.invoke")
        assert r.claims.header["typ"] == "at+jwt"

    def test_wire_format(self, world: World) -> None:
        """Two calls to the right endpoints; private_key_jwt; the ID token is the subject."""
        bound = world.login_and_bind()
        world.exchanger.exchange(bound, world.profile)
        (u1, f1), (u2, f2) = world.endpoint.calls
        assert u1 == f"{BASE}/oauth2/v1/token"
        assert f1["grant_type"] == GRANT_TOKEN_EXCHANGE
        assert f1["subject_token"] == bound.raw_id_token
        assert f1["audience"] == f"{BASE}/oauth2/agent-alpha"
        assert f1["scope"] == "agent.invoke"
        assert u2 == f"{BASE}/oauth2/agent-alpha/v1/token"
        assert f2["grant_type"] == GRANT_JWT_BEARER
        for f in (f1, f2):
            assert f["client_assertion_type"] == CLIENT_ASSERTION_TYPE
            assert "client_secret" not in f

    def test_access_token_never_sent_to_idp(self, world: World) -> None:
        """T1 (the access token) authorised the call; only the ID token is an exchange input."""
        at, idt = world.idp.login(ALICE, CHAT, ingress_as_id="ingress")
        world.exchanger.exchange(world.bind(at, idt), world.profile)
        for _, form in world.endpoint.calls:
            assert at not in form.values()

    def test_result_repr_has_no_token(self, world: World) -> None:
        """TM-ING-06"""
        r = world.exchanger.exchange(world.login_and_bind(), world.profile)
        assert r.token not in repr(r)


# ----------------------------------------------------------------------------- cache


class TestCaching:
    def test_second_call_hits_cache(self, world: World) -> None:
        bound = world.login_and_bind()
        first = world.exchanger.exchange(bound, world.profile)
        second = world.exchanger.exchange(bound, world.profile)
        assert second.cached
        assert second.token == first.token
        assert world.idp_calls() == 2

    @pytest.mark.security
    def test_new_login_misses(self, world: World) -> None:
        """TM-EXC-03 / ADR-0011: a new AT or ID token is a new cache key."""
        world.exchanger.exchange(world.login_and_bind(), world.profile)
        assert not world.exchanger.exchange(world.login_and_bind(), world.profile).cached

    @pytest.mark.security
    def test_users_never_share_entries(self, world: World) -> None:
        """TM-EXC-03"""
        a = world.exchanger.exchange(world.login_and_bind(ALICE), world.profile)
        b = world.exchanger.exchange(world.login_and_bind(BOB), world.profile)
        assert not b.cached
        assert a.claims.subject == ALICE
        assert b.claims.subject == BOB

    @pytest.mark.security
    def test_kill_switch_beats_cache(self, world: World) -> None:
        """A disabled profile denies immediately, even with a warm cache entry."""
        bound = world.login_and_bind()
        world.exchanger.exchange(bound, world.profile)
        assert_denied(
            world, ExchangeReason.PROFILE_DISABLED, make_profile(enabled=False), bound=bound
        )

    def test_entry_expires_before_t2(self, world: World) -> None:
        """ADR-0003: never hand out a T2 within 30 s of its expiry (same tokens, so same key)."""
        at, idt = world.idp.login(ALICE, CHAT, ingress_as_id="ingress")
        world.exchanger.exchange(world.bind(at, idt), world.profile)
        world.clock.t += 300 - 31
        assert world.exchanger.exchange(world.bind(at, idt), world.profile).cached
        world.clock.t += 1
        assert not world.exchanger.exchange(world.bind(at, idt), world.profile).cached

    @pytest.mark.security
    def test_missing_jti_disables_caching(self, world: World) -> None:
        """ADR-0011: no jti -> no cache, never a weaker key."""
        bound = world.login_and_bind()
        stripped = type(bound)(
            subject=bound.subject,
            client_id=bound.client_id,
            access_token=type(bound.access_token)(
                bound.access_token.header,
                {k: v for k, v in bound.access_token.claims.items() if k != "jti"},
            ),
            id_token=bound.id_token,
            raw_id_token=bound.raw_id_token,
        )
        world.exchanger.exchange(stripped, world.profile)
        assert not world.exchanger.exchange(stripped, world.profile).cached
        assert world.idp_calls() == 4


# ----------------------------------------------------------------------------- profile gating


@pytest.mark.security
class TestProfileGating:
    def test_egress_profile_refused(self, world: World) -> None:
        egress = make_profile(
            flow="egress",
            ingress_clients=None,
            max_auth_age_s=None,
            ingress_token=None,
            client={"client_id": "0oa-agent", "signing_key": "local:chat"},
        )
        assert_denied(world, ExchangeReason.PROFILE_NOT_INGRESS, egress)

    def test_disabled(self, world: World) -> None:
        assert_denied(world, ExchangeReason.PROFILE_DISABLED, make_profile(enabled=False))
        assert world.idp_calls() == 0

    def test_client_not_in_profile(self, world: World) -> None:
        """ADR-0009: binding allowed OTHER, but this agent's profile does not front it."""
        assert_denied(
            world, ExchangeReason.CLIENT_NOT_CONFIGURED, bound=world.login_and_bind(client=OTHER)
        )
        assert world.idp_calls() == 0

    def test_unknown_signing_key(self, world: World) -> None:
        p = make_profile(ingress_clients={CHAT: "local:missing"})
        assert_denied(world, ExchangeReason.SIGNING_FAILED, p)
        assert world.idp_calls() == 0


# ----------------------------------------------------------------------------- retries


@pytest.mark.security
class TestRetries:
    def test_one_transport_failure_is_retried_with_fresh_assertion(self, world: World) -> None:
        """ADR-0011: the retried request must carry a new client assertion (new jti)."""
        world.endpoint.transport_failures = 1
        world.exchanger.exchange(world.login_and_bind(), world.profile)
        (u1, f1), (u2, f2) = world.endpoint.calls[:2]
        assert u1 == u2
        assert f1["client_assertion"] != f2["client_assertion"]

    def test_two_transport_failures_deny(self, world: World) -> None:
        """TM-EXC-07"""
        world.endpoint.transport_failures = 2
        assert_denied(world, ExchangeReason.IDP_UNAVAILABLE)
        assert world.idp_calls() == 2

    @pytest.mark.parametrize("status", [429, 500, 503])
    def test_http_errors_never_retried(self, world: World, status: int) -> None:
        """TM-EXC-07: retrying into an overloaded IdP amplifies the incident."""
        world.endpoint.rewrite_response = lambda url, r: HttpResult(
            status, {"error": "server_error"}
        )
        assert_denied(world, ExchangeReason.IDP_ERROR)
        assert world.idp_calls() == 1


# ----------------------------------------------------------------------------- IdP errors


@pytest.mark.security
class TestIdpErrors:
    def test_policy_refusal_surfaces_code(self, world: World) -> None:
        p = make_profile(
            target={"audience": "api://agent-alpha", "scopes": ["agent.invoke"]},
            idp={**make_profile().idp.model_dump(), "resource_issuer": f"{BASE}/oauth2/nowhere"},
        )
        err = assert_denied(world, ExchangeReason.IDP_ERROR, p)
        assert err.idp_error == "invalid_target"
        assert err.step == "token_exchange"

    def test_unknown_error_codes_and_descriptions_dropped(self, world: World) -> None:
        """TM-ING-06: IdP-controlled strings never reach our logs."""
        world.endpoint.rewrite_response = lambda url, r: HttpResult(
            400, {"error": "<script>evil", "error_description": "user alice@example.com secret=xyz"}
        )
        err = assert_denied(world, ExchangeReason.IDP_ERROR)
        assert err.idp_error is None
        assert "alice" not in str(err)
        assert "evil" not in str(err)


# ----------------------------------------------------------------------------- mix-up / tampering


@pytest.mark.security
class TestResponseValidation:
    def _swap_first(self, world: World, replacement: str) -> None:
        def rw(url: str, r: HttpResult) -> HttpResult:
            if url.endswith("/oauth2/v1/token") and r.status == 200:
                return HttpResult(200, {**r.body, "access_token": replacement})
            return r

        world.endpoint.rewrite_response = rw

    def test_id_jag_for_another_user(self, world: World) -> None:
        """TM-EXC-02 (mix-up): IdP returns a valid ID-JAG, but for Bob."""
        bob_jag = self._mint_id_jag(world, BOB)
        self._swap_first(world, bob_jag)
        assert_denied(world, ExchangeReason.ID_JAG_INVALID)

    def test_id_jag_for_another_audience(self, world: World) -> None:
        """TM-EXC-02: valid ID-JAG, but for agent-beta's AS."""
        beta = make_profile(
            idp={**make_profile().idp.model_dump(), "resource_issuer": f"{BASE}/oauth2/agent-beta"}
        )
        jag = self._mint_id_jag(world, ALICE, beta)
        self._swap_first(world, jag)
        assert_denied(world, ExchangeReason.ID_JAG_INVALID)

    def test_id_token_returned_as_id_jag(self, world: World) -> None:
        """typ confusion: org-signed, right user, but not an ID-JAG."""
        _, idt = world.idp.login(ALICE, CHAT, ingress_as_id="ingress")
        self._swap_first(world, idt)
        assert_denied(world, ExchangeReason.ID_JAG_INVALID)

    def test_wrong_issued_token_type(self, world: World) -> None:
        world.endpoint.rewrite_response = lambda url, r: (
            HttpResult(
                200,
                {**r.body, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"},
            )
            if url.endswith("/oauth2/v1/token")
            else r
        )
        assert_denied(world, ExchangeReason.MALFORMED_RESPONSE)

    @pytest.mark.parametrize("body", [{}, {"access_token": 7}, {"access_token": ""}])
    def test_malformed_success_body(self, world: World, body: dict[str, Any]) -> None:
        world.endpoint.rewrite_response = lambda url, r: HttpResult(200, body)
        assert_denied(world, ExchangeReason.MALFORMED_RESPONSE)

    def test_t2_replaced_with_ingress_access_token(self, world: World) -> None:
        """TM-EXC-02: an at+jwt from a different AS is not our T2."""
        at, _ = world.idp.login(ALICE, CHAT, ingress_as_id="ingress")
        world.endpoint.rewrite_response = lambda url, r: (
            HttpResult(200, {**r.body, "access_token": at}) if "agent-alpha" in url else r
        )
        assert_denied(world, ExchangeReason.T2_INVALID)

    def test_t2_scope_escalation(self, world: World) -> None:
        """TM-EXC-02: the IdP grants more than the profile asked for -> deny, never forward."""

        def widen(url: str, form: dict[str, str]) -> dict[str, str]:
            if url.endswith("/oauth2/v1/token"):
                return {**form, "scope": "agent.invoke agent.admin"}
            return form

        world.endpoint.rewrite_request = widen
        assert_denied(world, ExchangeReason.T2_SCOPE_ESCALATION)

    def test_errors_are_log_safe(self, world: World) -> None:
        """TM-ING-06"""
        bound = world.login_and_bind()
        self._swap_first(world, self._mint_id_jag(world, BOB))
        err = assert_denied(world, ExchangeReason.ID_JAG_INVALID, bound=bound)
        for seg in bound.raw_id_token.split("."):
            assert seg not in str(err)

    # helper: get a genuine ID-JAG from the mock via a side channel
    def _mint_id_jag(self, world: World, user: str, profile: Any = None) -> str:
        from trustkit.signing import build_client_assertion

        p = profile or world.profile
        _, idt = world.idp.login(user, CHAT, ingress_as_id="ingress")
        ep = p.idp.token_endpoint
        r = world.idp.token(
            ep,
            {
                "grant_type": GRANT_TOKEN_EXCHANGE,
                "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "subject_token": idt,
                "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "audience": p.idp.resource_issuer,
                "scope": "agent.invoke",
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": build_client_assertion(
                    world.signers["local:chat"], client_id=CHAT, token_endpoint=ep, now=world.clock
                ),
            },
        )
        assert r.status == 200, r.body
        return str(r.body["access_token"])


@pytest.mark.security
class TestEdgePaths:
    def test_signer_failing_mid_flight_denies_without_idp_call(self, world: World) -> None:
        """TM-EXC-01: KMS key revoked after cold start (incident response) -> clean deny."""
        from trustkit.signing import SigningError

        class Revoked:
            key_id = "k"
            algorithm = "ES256"

            def sign(self, signing_input: bytes) -> bytes:
                raise SigningError("kms sign failed")

        world.signers["local:chat"] = Revoked()  # type: ignore[assignment]
        err = assert_denied(world, ExchangeReason.SIGNING_FAILED)
        assert err.step == "token_exchange"
        assert world.idp_calls() == 0

    def test_second_step_wrong_token_type(self, world: World) -> None:
        world.endpoint.rewrite_response = lambda url, r: (
            HttpResult(200, {**r.body, "token_type": "N_A"}) if "agent-alpha" in url else r
        )
        err = assert_denied(world, ExchangeReason.MALFORMED_RESPONSE)
        assert err.step == "jwt_bearer"

    def test_first_step_right_metadata_but_no_token(self, world: World) -> None:
        world.endpoint.rewrite_response = lambda url, r: (
            HttpResult(200, {k: v for k, v in r.body.items() if k != "access_token"})
            if url.endswith("/oauth2/v1/token")
            else r
        )
        err = assert_denied(world, ExchangeReason.MALFORMED_RESPONSE)
        assert err.step == "token_exchange"
