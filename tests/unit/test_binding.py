"""Access-token <-> ID-token binding (ADR-0006, TM-ING-08)."""

from __future__ import annotations

from typing import Any

import pytest
from joserfc.jwk import RSAKey

from tests.conftest import AUDIENCE, ISSUER, NOW, Mint, StaticKeys, good_claims
from trustkit.binding import BindingError, BindingReason, BoundIdentity, bind
from trustkit.jwt import Reason, TokenValidator, ValidationPolicy

ORG_ISSUER = "https://idp.example.test"
FRONTEND = "0oa-chat-frontend"
OTHER_FRONTEND = "0oa-other-frontend"
ALLOWED = frozenset({FRONTEND})
MAX_AUTH_AGE = 43_200


def at_claims(**o: Any) -> dict[str, Any]:
    """Access token from the ingress custom AS."""
    return good_claims(cid=FRONTEND, **o)


def idt_claims(**o: Any) -> dict[str, Any]:
    """ID token from the org AS, issued to the front-end client."""
    base: dict[str, Any] = {
        "iss": ORG_ISSUER,
        "aud": FRONTEND,
        "jti": "idt-1",
        "auth_time": NOW - 60,
    }
    base.update(o)
    return good_claims(**base)


@pytest.fixture
def validators(rsa_key: RSAKey) -> tuple[TokenValidator, TokenValidator]:
    keys = StaticKeys(rsa_key)
    at_v = TokenValidator(
        ValidationPolicy(issuer=ISSUER, audiences=frozenset({AUDIENCE})), keys, now=lambda: NOW
    )
    idt_v = TokenValidator(
        ValidationPolicy(issuer=ORG_ISSUER, audiences=frozenset({FRONTEND, OTHER_FRONTEND})),
        keys,
        now=lambda: NOW,
    )
    return at_v, idt_v


@pytest.fixture
def do_bind(validators: tuple[TokenValidator, TokenValidator]) -> Any:
    at_v, idt_v = validators

    def _bind(
        at: str, idt: str, *, allowed: frozenset[str] = ALLOWED, max_auth_age: int = MAX_AUTH_AGE
    ) -> BoundIdentity:
        return bind(
            at,
            idt,
            access_token_validator=at_v,
            id_token_validator=idt_v,
            allowed_clients=allowed,
            max_auth_age_s=max_auth_age,
            now=lambda: NOW,
        )

    return _bind


def assert_binding_fails(
    do_bind: Any, at: str, idt: str, reason: BindingReason, **kw: Any
) -> BindingError:
    with pytest.raises(BindingError) as ei:
        do_bind(at, idt, **kw)
    assert ei.value.reason is reason, f"expected {reason}, got {ei.value.reason}"
    return ei.value


class TestBinds:
    def test_matching_pair(self, do_bind: Any, mint: Mint) -> None:
        idt = mint(idt_claims())
        b = do_bind(mint(at_claims()), idt)
        assert b.subject == "00u-user-1"
        assert b.client_id == FRONTEND
        assert b.raw_id_token == idt

    def test_rfc9068_client_id_claim(self, do_bind: Any, mint: Mint) -> None:
        at = mint(good_claims(client_id=FRONTEND))
        assert do_bind(at, mint(idt_claims())).client_id == FRONTEND

    def test_both_client_claims_equal(self, do_bind: Any, mint: Mint) -> None:
        assert (
            do_bind(mint(at_claims(client_id=FRONTEND)), mint(idt_claims())).client_id == FRONTEND
        )

    def test_single_element_aud_list(self, do_bind: Any, mint: Mint) -> None:
        assert do_bind(mint(at_claims()), mint(idt_claims(aud=[FRONTEND]))).client_id == FRONTEND

    def test_multi_aud_id_token_with_azp(self, do_bind: Any, mint: Mint) -> None:
        idt = mint(idt_claims(aud=[FRONTEND, "api://x"], azp=FRONTEND))
        assert do_bind(mint(at_claims()), idt).client_id == FRONTEND


@pytest.mark.security
class TestBindingAttacks:
    def test_someone_elses_id_token(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08: my access token + victim's ID token must not mint tokens as the victim."""
        assert_binding_fails(
            do_bind,
            mint(at_claims()),
            mint(idt_claims(sub="00u-victim")),
            BindingReason.SUBJECT_MISMATCH,
        )

    def test_id_token_from_a_different_client(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08: tokens from two different apps don't belong to one login."""
        idt = mint(idt_claims(aud=OTHER_FRONTEND))
        assert_binding_fails(
            do_bind,
            mint(at_claims()),
            idt,
            BindingReason.CLIENT_MISMATCH,
            allowed=frozenset({FRONTEND, OTHER_FRONTEND}),
        )

    def test_client_not_in_profile_allowlist(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08 / ADR-0009: only listed front ends may drive exchanges for this agent."""
        at = mint(good_claims(cid=OTHER_FRONTEND))
        idt = mint(idt_claims(aud=OTHER_FRONTEND))
        assert_binding_fails(do_bind, at, idt, BindingReason.CLIENT_NOT_ALLOWED)

    def test_conflicting_client_claims_in_access_token(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08: cid and client_id disagreeing is ambiguous, so deny."""
        at = mint(at_claims(client_id=OTHER_FRONTEND))
        assert_binding_fails(do_bind, at, mint(idt_claims()), BindingReason.CLIENT_MISMATCH)

    def test_access_token_without_client_claim(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08"""
        assert_binding_fails(
            do_bind, mint(good_claims()), mint(idt_claims()), BindingReason.CLIENT_MISMATCH
        )

    @pytest.mark.parametrize("azp", [None, "0oa-not-in-aud"])
    def test_multi_aud_id_token_requires_valid_azp(
        self, do_bind: Any, mint: Mint, azp: str | None
    ) -> None:
        """TM-ING-08 / OIDC Core §2: with several audiences, azp names the client."""
        idt = mint(idt_claims(aud=[FRONTEND, OTHER_FRONTEND], azp=azp))
        assert_binding_fails(do_bind, mint(at_claims()), idt, BindingReason.CLIENT_MISMATCH)

    @pytest.mark.parametrize("azp", [OTHER_FRONTEND, 42])
    def test_single_aud_with_disagreeing_azp(self, do_bind: Any, mint: Mint, azp: Any) -> None:
        """TM-ING-08: aud and azp naming different clients is ambiguous, so deny."""
        idt = mint(idt_claims(azp=azp))
        assert_binding_fails(do_bind, mint(at_claims()), idt, BindingReason.CLIENT_MISMATCH)

    def test_old_login(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08 / ADR-0009: the login itself is too old."""
        idt = mint(idt_claims(auth_time=NOW - MAX_AUTH_AGE - 1))
        assert_binding_fails(do_bind, mint(at_claims()), idt, BindingReason.AUTHENTICATION_TOO_OLD)

    def test_silent_refresh_cannot_launder_old_login(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08 / ADR-0009: a freshly *issued* ID token for a 30-day-old login is still old."""
        idt = mint(idt_claims(iat=NOW - 5, auth_time=NOW - 30 * 86_400))
        assert_binding_fails(do_bind, mint(at_claims()), idt, BindingReason.AUTHENTICATION_TOO_OLD)

    def test_missing_auth_time(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08: without auth_time, login age is unknowable, so deny."""
        err = assert_binding_fails(
            do_bind,
            mint(at_claims()),
            mint(idt_claims(auth_time=None)),
            BindingReason.ID_TOKEN_INVALID,
        )
        assert err.token_reason is Reason.MISSING_CLAIM

    @pytest.mark.parametrize("auth_time", [str(NOW), float(NOW), True])
    def test_auth_time_wrong_type(self, do_bind: Any, mint: Mint, auth_time: Any) -> None:
        """TM-ING-08 / TM-ING-02: no coercion."""
        err = assert_binding_fails(
            do_bind,
            mint(at_claims()),
            mint(idt_claims(auth_time=auth_time)),
            BindingReason.ID_TOKEN_INVALID,
        )
        assert err.token_reason is Reason.MALFORMED

    def test_auth_time_in_future(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08: a future login time would make any token look fresh forever."""
        err = assert_binding_fails(
            do_bind,
            mint(at_claims()),
            mint(idt_claims(auth_time=NOW + 300)),
            BindingReason.ID_TOKEN_INVALID,
        )
        assert err.token_reason is Reason.IAT_IN_FUTURE

    def test_id_token_in_access_token_slot(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08 / TM-ING-02: token-type confusion is caught by audience."""
        idt = mint(idt_claims())
        err = assert_binding_fails(do_bind, idt, idt, BindingReason.ACCESS_TOKEN_INVALID)
        assert err.token_reason is Reason.WRONG_ISSUER

    def test_access_token_in_id_token_slot(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08 / TM-ING-02"""
        at = mint(at_claims())
        assert_binding_fails(do_bind, at, at, BindingReason.ID_TOKEN_INVALID)

    def test_expired_id_token(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-08"""
        err = assert_binding_fails(
            do_bind,
            mint(at_claims()),
            mint(idt_claims(exp=NOW - 120)),
            BindingReason.ID_TOKEN_INVALID,
        )
        assert err.token_reason is Reason.EXPIRED

    def test_error_is_log_safe(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-06: no subjects, client ids or token bytes in the message."""
        at, idt = mint(at_claims()), mint(idt_claims(sub="00u-victim"))
        err = assert_binding_fails(do_bind, at, idt, BindingReason.SUBJECT_MISMATCH)
        for needle in ("00u-victim", "00u-user-1", FRONTEND, *at.split("."), *idt.split(".")):
            assert needle not in str(err)

    def test_repr_never_contains_raw_id_token(self, do_bind: Any, mint: Mint) -> None:
        """TM-ING-06: logging the bound identity must not leak the credential."""
        idt = mint(idt_claims())
        b = do_bind(mint(at_claims()), idt)
        assert idt not in repr(b)
        assert idt.split(".")[2] not in repr(b)
