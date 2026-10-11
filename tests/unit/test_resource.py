"""ResourceAuthorizer: the runtime's own T2 check (ADR-0014 §1, TM-RT-01)."""

from __future__ import annotations

from typing import Any

import pytest
from joserfc.jwk import RSAKey

from tests.conftest import NOW, Mint, StaticKeys, good_claims
from trustkit.jwt import Reason
from trustkit.resource import AuthzFailure, ResourceAuthorizer, ResourceAuthzError

ISS = "https://idp.example.test/oauth2/agent-alpha"
AUD = "api://agent-alpha"


def t2_claims(**o: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iss": ISS,
        "aud": AUD,
        "client_id": "0oa-chat",
        "scope": "agent.invoke agent.read",
    }
    return good_claims(**{**base, **o})


@pytest.fixture
def authz(rsa_key: RSAKey) -> ResourceAuthorizer:
    return ResourceAuthorizer(issuer=ISS, audience=AUD, keys=StaticKeys(rsa_key), now=lambda: NOW)


def at(mint: Mint, **o: Any) -> str:
    header = {"typ": "at+jwt", **o.pop("header", {})}
    return "Bearer " + mint(t2_claims(**o), header=header)


def fails(
    authz: ResourceAuthorizer,
    header: str | None,
    failure: AuthzFailure,
    scope: str = "agent.invoke",
) -> ResourceAuthzError:
    with pytest.raises(ResourceAuthzError) as ei:
        authz.authorize(header, required_scope=scope)
    assert ei.value.failure is failure, ei.value
    return ei.value


class TestAuthorize:
    def test_valid_t2(self, authz: ResourceAuthorizer, mint: Mint) -> None:
        p = authz.authorize(at(mint), required_scope="agent.invoke")
        assert (p.subject, p.client_id) == ("00u-user-1", "0oa-chat")
        assert p.scopes == frozenset({"agent.invoke", "agent.read"})
        assert p.token_jti == "jti-1"


@pytest.mark.security
class TestRejects:
    @pytest.mark.parametrize("header", [None, "", "Basic x", "Bearer", "Bearer a b"])
    def test_missing_or_malformed_header(
        self, authz: ResourceAuthorizer, header: str | None
    ) -> None:
        """TM-RT-01"""
        e = fails(
            authz, header, AuthzFailure.MISSING_TOKEN if not header else AuthzFailure.INVALID_TOKEN
        )
        assert e.status == 401

    def test_t2_for_another_agent(self, authz: ResourceAuthorizer, mint: Mint) -> None:
        """TM-RT-01: a T2 minted for agent-beta is useless at agent-alpha."""
        e = fails(authz, at(mint, aud="api://agent-beta"), AuthzFailure.INVALID_TOKEN)
        assert e.token_reason is Reason.WRONG_AUDIENCE

    def test_caller_t1_presented_directly(self, authz: ResourceAuthorizer, mint: Mint) -> None:
        """TM-RT-01: the ingress token (other issuer/aud) can't bypass the gateway."""
        tok = "Bearer " + mint(
            good_claims(iss="https://idp.example.test/oauth2/ingress", aud="api://agent-ingress"),
            header={"typ": "at+jwt"},
        )
        fails(authz, tok, AuthzFailure.INVALID_TOKEN)

    def test_id_token_rejected_by_typ(self, authz: ResourceAuthorizer, mint: Mint) -> None:
        """TM-RT-01: RFC 9068 typ distinguishes access tokens from ID tokens/ID-JAGs."""
        e = fails(authz, at(mint, header={"typ": "JWT"}), AuthzFailure.INVALID_TOKEN)
        assert e.token_reason is Reason.WRONG_TYP

    @pytest.mark.parametrize("missing", ["client_id", "jti", "scope"])
    def test_required_claims(self, authz: ResourceAuthorizer, mint: Mint, missing: str) -> None:
        fails(authz, at(mint, **{missing: None}), AuthzFailure.INVALID_TOKEN)

    def test_insufficient_scope_is_403(self, authz: ResourceAuthorizer, mint: Mint) -> None:
        e = fails(authz, at(mint, scope="agent.read"), AuthzFailure.INSUFFICIENT_SCOPE)
        assert e.status == 403
        assert 'error="insufficient_scope"' in e.www_authenticate
        assert 'scope="agent.invoke"' in e.www_authenticate

    @pytest.mark.parametrize(
        "scope", ["agent.invoke.admin", "xagent.invoke", "agent.invoke,agent.read"]
    )
    def test_scope_match_is_exact_token(
        self, authz: ResourceAuthorizer, mint: Mint, scope: str
    ) -> None:
        """Space-delimited exact match only (RFC 6749 §3.3); no prefix/substring matching."""
        fails(authz, at(mint, scope=scope), AuthzFailure.INSUFFICIENT_SCOPE)

    def test_invalid_token_challenge(self, authz: ResourceAuthorizer, mint: Mint) -> None:
        e = fails(authz, at(mint, aud="api://other"), AuthzFailure.INVALID_TOKEN)
        assert e.www_authenticate == 'Bearer error="invalid_token"'

    def test_missing_token_challenge_has_no_error_code(self, authz: ResourceAuthorizer) -> None:
        """RFC 6750 §3.1: no error code when no credentials were sent."""
        assert fails(authz, None, AuthzFailure.MISSING_TOKEN).www_authenticate == "Bearer"


@pytest.mark.security
class TestChallengeSafety:
    def test_unsafe_required_scope_never_reaches_header(
        self, authz: ResourceAuthorizer, mint: Mint
    ) -> None:
        """A scope value containing quotes/CRLF must not be able to inject into WWW-Authenticate."""
        e = fails(authz, at(mint), AuthzFailure.INSUFFICIENT_SCOPE, scope='x"\r\nSet-Cookie: a=b')
        assert e.www_authenticate == 'Bearer error="insufficient_scope"'

    def test_non_string_scope_claim(self, authz: ResourceAuthorizer, mint: Mint) -> None:
        e = fails(authz, at(mint, scope=["agent.invoke"]), AuthzFailure.INVALID_TOKEN)
        assert e.token_reason is Reason.MALFORMED
