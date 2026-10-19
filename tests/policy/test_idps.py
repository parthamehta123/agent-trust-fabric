"""Trusted IdPs for agents' T2 (ADR-0027 RFC self-review, finding #1)."""

from __future__ import annotations

import pytest

from trustkit_policy.idps import TrustedIdps

IDP = "https://idp.example.test"
TRUSTED = TrustedIdps(frozenset({IDP, "https://mock-idp:8443"}))


class TestConstruction:
    @pytest.mark.parametrize(
        "origin",
        [
            "http://idp.example.test",
            "https://idp.example.test/oauth2",
            "https://idp.example.test/",
            "https://IDP.example.test",
            "https://idp.example.test:443",
            "https://user@idp.example.test",
            "https://idp.example.test?x=1",
            " https://idp.example.test",
        ],
    )
    def test_only_canonical_https_origins(self, origin: str) -> None:
        with pytest.raises(ValueError, match="origin"):
            TrustedIdps(frozenset({origin}))

    def test_empty_is_refused(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            TrustedIdps(frozenset())

    @pytest.mark.parametrize("raw", [None, "", "  ,  "])
    def test_env_missing_or_empty_is_refused(self, raw: str | None) -> None:
        env = {} if raw is None else {"ATF_TRUSTED_IDP_ORIGINS": raw}
        with pytest.raises(ValueError, match="at least one"):
            TrustedIdps.from_env(env)

    def test_env_list(self) -> None:
        env = {"ATF_TRUSTED_IDP_ORIGINS": "https://a.example, https://b.example:8443/"}
        assert TrustedIdps.from_env(env).origins == {"https://a.example", "https://b.example:8443"}


class TestAllows:
    @pytest.mark.parametrize(
        ("issuer", "jwks"),
        [
            (f"{IDP}/oauth2/agent-alpha", f"{IDP}/oauth2/agent-alpha/v1/keys"),  # Okta custom AS
            (IDP, f"{IDP}/oauth2/v1/keys"),  # Okta org AS
            ("https://IDP.example.test:443/oauth2/a", f"{IDP}/oauth2/a/v1/keys"),  # normalised
            ("https://mock-idp:8443/oauth2/a", "https://mock-idp:8443/oauth2/a/v1/keys"),
        ],
    )
    def test_issuer_on_a_trusted_idp_with_its_own_keys(self, issuer: str, jwks: str) -> None:
        assert TRUSTED.allows(issuer, jwks)

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("issuer", "jwks"),
        [
            # The finding: an owner-run "IdP" (any issuer, any keys).
            (
                "https://idp.attacker.example/oauth2/a",
                "https://idp.attacker.example/oauth2/a/v1/keys",
            ),
            # A trusted issuer with someone else's keys.
            (f"{IDP}/oauth2/a", "https://keys.attacker.example/oauth2/a/v1/keys"),
            # Same host, another port: another origin.
            (f"{IDP}/oauth2/a", "https://idp.example.test:8443/oauth2/a/v1/keys"),
            # Keys of another authorization server on the same IdP.
            (f"{IDP}/oauth2/a", f"{IDP}/oauth2/b/v1/keys"),
            (f"{IDP}/oauth2/a", f"{IDP}/oauth2/ab/v1/keys"),
            # Escaping the issuer's path.
            (f"{IDP}/oauth2/a", f"{IDP}/oauth2/a/../b/v1/keys"),
            (f"{IDP}/oauth2/a", f"{IDP}/oauth2/a/%2e%2e/b/v1/keys"),
            # Not plain https URLs.
            ("http://idp.example.test/oauth2/a", "http://idp.example.test/oauth2/a/v1/keys"),
            (f"{IDP}/oauth2/a", f"{IDP}/oauth2/a/v1/keys?jku=https://x"),
            (f"{IDP}/oauth2/a", f"{IDP}/oauth2/a/v1/keys#x"),
            ("https://u@idp.example.test/oauth2/a", f"{IDP}/oauth2/a/v1/keys"),
            (f"{IDP}/oauth2/a", f"{IDP}/oauth2/a"),  # the issuer itself isn't its key set
        ],
    )
    def test_refused(self, issuer: str, jwks: str) -> None:
        assert not TRUSTED.allows(issuer, jwks)
