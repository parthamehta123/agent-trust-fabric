"""TokenValidator / ValidationPolicy / JwksKeyResolver.

Every test marked ``security`` cites the threat-model mitigation it proves.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest
from joserfc.jwk import ECKey, RSAKey

from tests.conftest import AUDIENCE, ISSUER, NOW, Mint, StaticKeys, b64url, good_claims, raw_jws
from trustkit.jwt import (
    FORBIDDEN_HEADER_PARAMS,
    MAX_LEEWAY_SECONDS,
    JwksKeyResolver,
    Reason,
    TokenValidationError,
    TokenValidator,
    ValidationPolicy,
)


def policy(**overrides: Any) -> ValidationPolicy:
    base: dict[str, Any] = {"issuer": ISSUER, "audiences": frozenset({AUDIENCE})}
    base.update(overrides)
    return ValidationPolicy(**base)


@pytest.fixture
def validator(rsa_key: RSAKey, ec_key: ECKey) -> TokenValidator:
    return TokenValidator(policy(), StaticKeys(rsa_key, ec_key), now=lambda: NOW)


def assert_rejected(v: TokenValidator, token: str, reason: Reason) -> TokenValidationError:
    with pytest.raises(TokenValidationError) as ei:
        v.validate(token)
    assert ei.value.reason is reason, f"expected {reason}, got {ei.value.reason}"
    return ei.value


# ----------------------------------------------------------------------------- policy


class TestPolicyConstruction:
    def test_rejects_algorithm_outside_platform_ceiling(self) -> None:
        with pytest.raises(ValueError, match="algorithm"):
            policy(algorithms=frozenset({"RS256", "HS256"}))

    def test_rejects_empty_algorithms(self) -> None:
        with pytest.raises(ValueError, match="algorithm"):
            policy(algorithms=frozenset())

    def test_rejects_empty_audiences(self) -> None:
        with pytest.raises(ValueError, match="audience"):
            policy(audiences=frozenset())

    def test_rejects_excessive_leeway(self) -> None:
        with pytest.raises(ValueError, match="leeway"):
            policy(leeway_seconds=MAX_LEEWAY_SECONDS + 1)

    def test_rejects_negative_leeway(self) -> None:
        with pytest.raises(ValueError, match="leeway"):
            policy(leeway_seconds=-1)

    def test_required_claims_cannot_drop_core_claims(self) -> None:
        """A policy that stops requiring exp would silently accept non-expiring tokens."""
        with pytest.raises(ValueError, match="required"):
            policy(required_claims=frozenset({"iss", "sub", "aud"}))


# ----------------------------------------------------------------------------- happy path


class TestAccepts:
    def test_valid_rs256(self, validator: TokenValidator, mint: Mint) -> None:
        tok = validator.validate(mint())
        assert tok.subject == "00u-user-1"
        assert tok.issuer == ISSUER
        assert tok.jti == "jti-1"

    def test_valid_es256(self, validator: TokenValidator, mint: Mint, ec_key: ECKey) -> None:
        assert validator.validate(mint(key=ec_key, alg="ES256")).subject == "00u-user-1"

    def test_aud_as_list_containing_expected(self, validator: TokenValidator, mint: Mint) -> None:
        validator.validate(mint(good_claims(aud=["api://other", AUDIENCE])))

    def test_expired_within_leeway_accepted(self, validator: TokenValidator, mint: Mint) -> None:
        validator.validate(mint(good_claims(exp=NOW - 30)))

    def test_typ_match_is_case_insensitive(self, rsa_key: RSAKey, mint: Mint) -> None:
        v = TokenValidator(policy(expected_typ="at+jwt"), StaticKeys(rsa_key), now=lambda: NOW)
        v.validate(mint(header={"typ": "AT+JWT"}))


# ----------------------------------------------------------------------------- TM-ING-01


@pytest.mark.security
class TestAlgorithmAttacks:
    def test_alg_none_rejected(self, validator: TokenValidator) -> None:
        """TM-ING-01: unsigned token."""
        tok = raw_jws({"alg": "none", "kid": "rsa-1"}, good_claims())
        assert_rejected(validator, tok, Reason.ALG_NOT_ALLOWED)

    @pytest.mark.parametrize("alg", ["None", "NONE", "nOnE"])
    def test_alg_none_case_variants_rejected(self, validator: TokenValidator, alg: str) -> None:
        """TM-ING-01: historic libraries matched 'none' case-sensitively."""
        assert_rejected(
            validator, raw_jws({"alg": alg, "kid": "rsa-1"}, good_claims()), Reason.ALG_NOT_ALLOWED
        )

    def test_hs256_key_confusion_rejected(self, validator: TokenValidator, rsa_key: RSAKey) -> None:
        """TM-ING-01: HMAC token 'signed' with the RSA public key as the shared secret."""
        header = {"alg": "HS256", "kid": "rsa-1"}
        signing_input = (
            f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(good_claims()).encode())}"
        )
        public_pem = rsa_key.as_pem(private=False)
        sig = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
        assert_rejected(validator, f"{signing_input}.{b64url(sig)}", Reason.ALG_NOT_ALLOWED)

    def test_alg_allowed_by_platform_but_not_policy(self, rsa_key: RSAKey, mint: Mint) -> None:
        """TM-ING-01: policy narrowing is honoured."""
        v = TokenValidator(
            policy(algorithms=frozenset({"RS256"})), StaticKeys(rsa_key), now=lambda: NOW
        )
        assert_rejected(v, mint(alg="PS256"), Reason.ALG_NOT_ALLOWED)

    def test_alg_family_must_match_key_type(self, validator: TokenValidator, ec_key: ECKey) -> None:
        """TM-ING-01: ES256 header pointing at an RSA kid."""
        tok = raw_jws({"alg": "ES256", "kid": "rsa-1"}, good_claims(), b"\x00" * 64)
        assert_rejected(validator, tok, Reason.ALG_NOT_ALLOWED)


# ----------------------------------------------------------------------------- TM-ING-03


@pytest.mark.security
class TestKeySelectionAttacks:
    @pytest.mark.parametrize("param", sorted(FORBIDDEN_HEADER_PARAMS))
    def test_forbidden_header_params(
        self, validator: TokenValidator, mint: Mint, param: str
    ) -> None:
        """TM-ING-03: the token must never choose its own verification key."""
        value: Any = (
            ["x"]
            if param in {"x5c", "crit"}
            else ("https://evil.test/k" if param != "jwk" else {"kty": "oct"})
        )
        # Hand-assembled: compliant encoders refuse some of these, and the check must fire
        # before signature verification anyway.
        tok = raw_jws({"alg": "RS256", "kid": "rsa-1", param: value}, good_claims(), b"\x00" * 256)
        assert_rejected(validator, tok, Reason.FORBIDDEN_HEADER)

    def test_missing_kid(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-03"""
        assert_rejected(validator, mint(header={"kid": None}), Reason.UNKNOWN_KID)

    def test_unknown_kid(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-03"""
        assert_rejected(validator, mint(header={"kid": "nope"}), Reason.UNKNOWN_KID)

    def test_attacker_key_with_victim_kid(
        self, validator: TokenValidator, mint: Mint, attacker_rsa_key: RSAKey
    ) -> None:
        """TM-ING-01/03: right kid, wrong key material."""
        assert_rejected(validator, mint(key=attacker_rsa_key), Reason.BAD_SIGNATURE)

    def test_tampered_payload(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-01: signature must cover the claims actually returned."""
        h, _, s = mint().split(".")
        forged = b64url(json.dumps(good_claims(sub="00u-admin")).encode())
        assert_rejected(validator, f"{h}.{forged}.{s}", Reason.BAD_SIGNATURE)


# ----------------------------------------------------------------------------- TM-ING-02


@pytest.mark.security
class TestClaimAttacks:
    def test_wrong_issuer(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-02"""
        assert_rejected(
            validator,
            mint(good_claims(iss="https://idp.example.test/oauth2/other")),
            Reason.WRONG_ISSUER,
        )

    @pytest.mark.parametrize(
        "iss", [ISSUER + "/", ISSUER + ".evil.test", ISSUER.upper(), " " + ISSUER]
    )
    def test_issuer_is_exact_match(self, validator: TokenValidator, mint: Mint, iss: str) -> None:
        """TM-ING-02: no prefix, suffix, case or whitespace tolerance."""
        assert_rejected(validator, mint(good_claims(iss=iss)), Reason.WRONG_ISSUER)

    def test_wrong_audience(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-02: token minted for another API."""
        assert_rejected(
            validator, mint(good_claims(aud="api://someone-else")), Reason.WRONG_AUDIENCE
        )

    def test_empty_audience_list(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-02"""
        assert_rejected(validator, mint(good_claims(aud=[])), Reason.WRONG_AUDIENCE)

    def test_expired_beyond_leeway(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-02"""
        assert_rejected(validator, mint(good_claims(exp=NOW - 61)), Reason.EXPIRED)

    def test_not_yet_valid(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-02"""
        assert_rejected(validator, mint(good_claims(nbf=NOW + 61)), Reason.NOT_YET_VALID)

    def test_iat_in_future(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-02: pre-minted tokens with a future iat extend their own lifetime."""
        assert_rejected(validator, mint(good_claims(iat=NOW + 61)), Reason.IAT_IN_FUTURE)

    @pytest.mark.parametrize("claim", ["iss", "sub", "aud", "exp", "iat"])
    def test_missing_required_claim(
        self, validator: TokenValidator, mint: Mint, claim: str
    ) -> None:
        """TM-ING-02"""
        assert_rejected(validator, mint(good_claims(**{claim: None})), Reason.MISSING_CLAIM)

    @pytest.mark.parametrize(
        ("claim", "value"), [("exp", "1800000300"), ("iat", 1.5e9), ("sub", 123)]
    )
    def test_wrongly_typed_claims(
        self, validator: TokenValidator, mint: Mint, claim: str, value: Any
    ) -> None:
        """TM-ING-02: no type coercion of security claims (string exp, float iat, numeric sub)."""
        with pytest.raises(TokenValidationError):
            validator.validate(mint(good_claims(**{claim: value})))

    def test_wrong_typ(self, rsa_key: RSAKey, mint: Mint) -> None:
        """TM-ING-02: an ID token or ID-JAG must not pass where an access token is expected."""
        v = TokenValidator(policy(expected_typ="at+jwt"), StaticKeys(rsa_key), now=lambda: NOW)
        assert_rejected(v, mint(header={"typ": "JWT"}), Reason.WRONG_TYP)


# ----------------------------------------------------------------------------- input hygiene


@pytest.mark.security
class TestInputHygiene:
    @pytest.mark.parametrize(
        "token", ["", "abc", "a.b", "a.b.c.d", "!!!.###.$$$", "eyJ.eyJ.", " " * 10]
    )
    def test_malformed(self, validator: TokenValidator, token: str) -> None:
        """TM-ING-01"""
        assert_rejected(validator, token, Reason.MALFORMED)

    def test_too_large(self, validator: TokenValidator, mint: Mint) -> None:
        """TM-ING-05: refuse before parsing."""
        assert_rejected(validator, mint(good_claims(pad="x" * 20_000)), Reason.TOO_LARGE)

    def test_error_never_contains_token_material(
        self, validator: TokenValidator, mint: Mint
    ) -> None:
        """TM-ING-06: rejection messages are log-safe."""
        tok = mint(good_claims(aud="api://someone-else"))
        err = assert_rejected(validator, tok, Reason.WRONG_AUDIENCE)
        for segment in tok.split("."):
            assert segment not in str(err)
            assert segment not in repr(err)
        assert "api://someone-else" not in str(err)


# ----------------------------------------------------------------------------- JWKS resolver


class _Fetcher:
    def __init__(self, *docs: dict[str, Any]) -> None:
        self.docs = list(docs)
        self.calls = 0

    def __call__(self) -> dict[str, Any]:
        self.calls += 1
        doc = self.docs[min(self.calls - 1, len(self.docs) - 1)]
        if isinstance(doc, Exception):
            raise doc
        return doc


def jwks(*keys: RSAKey | ECKey) -> dict[str, Any]:
    return {"keys": [k.as_dict(private=False) for k in keys]}


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class TestJwksKeyResolver:
    def test_resolves_known_kid(self, rsa_key: RSAKey) -> None:
        r = JwksKeyResolver(fetch=_Fetcher(jwks(rsa_key)))
        key = r.resolve("rsa-1")
        assert key is not None
        assert not key.is_private

    def test_rotation_picked_up_after_interval(self, rsa_key: RSAKey, ec_key: ECKey) -> None:
        clock = _Clock()
        fetch = _Fetcher(jwks(rsa_key), jwks(rsa_key, ec_key))
        r = JwksKeyResolver(fetch=fetch, min_refresh_interval_s=60, now=clock)
        assert r.resolve("rsa-1") is not None
        clock.t += 61
        assert r.resolve("ec-1") is not None

    @pytest.mark.security
    def test_unknown_kid_refresh_is_rate_limited(self, rsa_key: RSAKey) -> None:
        """TM-ING-03: random-kid spraying must not amplify into JWKS fetches."""
        clock = _Clock()
        fetch = _Fetcher(jwks(rsa_key))
        r = JwksKeyResolver(fetch=fetch, min_refresh_interval_s=60, now=clock)
        r.resolve("rsa-1")
        for i in range(50):
            assert r.resolve(f"random-{i}") is None
        assert fetch.calls <= 2

    @pytest.mark.security
    def test_symmetric_and_private_keys_in_jwks_ignored(self, rsa_key: RSAKey) -> None:
        """TM-ING-01/03: an 'oct' key or leaked private JWK must never become a verification key."""
        doc = {
            "keys": [
                {"kty": "oct", "kid": "sym", "k": b64url(b"s" * 32)},
                rsa_key.as_dict(private=True),
            ]
        }
        r = JwksKeyResolver(fetch=_Fetcher(doc))
        assert r.resolve("sym") is None
        resolved = r.resolve("rsa-1")
        assert resolved is None or not resolved.is_private

    @pytest.mark.security
    def test_fetch_failure_keeps_cached_keys_and_fails_closed_for_unknown(
        self, rsa_key: RSAKey
    ) -> None:
        """TM-EXC-07: IdP blip doesn't drop known keys; unknown kids still deny."""
        clock = _Clock()
        fetch = _Fetcher(jwks(rsa_key), ConnectionError("idp down"))  # type: ignore[arg-type]
        r = JwksKeyResolver(fetch=fetch, min_refresh_interval_s=60, now=clock)
        assert r.resolve("rsa-1") is not None
        clock.t += 61
        assert r.resolve("new-kid") is None
        assert r.resolve("rsa-1") is not None

    @pytest.mark.security
    def test_key_removed_at_idp_stops_being_trusted(self, rsa_key: RSAKey, ec_key: ECKey) -> None:
        """TM-ING-03: a key the IdP retires (e.g. after compromise) must age out even when its kid
        keeps being presented, i.e. refresh is proactive, not only on unknown kid."""
        clock = _Clock()
        fetch = _Fetcher(jwks(rsa_key, ec_key), jwks(ec_key))
        r = JwksKeyResolver(fetch=fetch, max_key_age_s=3600, now=clock)
        assert r.resolve("rsa-1") is not None
        clock.t += 3601
        assert r.resolve("rsa-1") is None
        assert r.resolve("ec-1") is not None

    @pytest.mark.security
    def test_cached_keys_dropped_after_max_staleness(self, rsa_key: RSAKey) -> None:
        """TM-ING-03 / TM-EXC-07: serve through IdP blips, but never trust keys indefinitely."""
        clock = _Clock()
        fetch = _Fetcher(jwks(rsa_key), ConnectionError("idp down"))  # type: ignore[arg-type]
        r = JwksKeyResolver(fetch=fetch, max_staleness_s=86_400, now=clock)
        assert r.resolve("rsa-1") is not None
        clock.t += 86_000
        assert r.resolve("rsa-1") is not None
        clock.t += 401
        assert r.resolve("rsa-1") is None

    @pytest.mark.security
    def test_duplicate_kids_in_jwks_are_dropped(
        self, rsa_key: RSAKey, attacker_rsa_key: RSAKey
    ) -> None:
        """TM-ING-03: two keys under one kid is ambiguous, so trust neither."""
        r = JwksKeyResolver(fetch=_Fetcher(jwks(rsa_key, attacker_rsa_key)))
        assert r.resolve("rsa-1") is None

    @pytest.mark.security
    @pytest.mark.filterwarnings("ignore:Key size should be")
    def test_weak_rsa_keys_ignored(self) -> None:
        """TM-ING-01: <2048-bit RSA keys are never verification keys."""
        weak = RSAKey.generate_key(1024, parameters={"kid": "weak"}, private=True)
        assert JwksKeyResolver(fetch=_Fetcher(jwks(weak))).resolve("weak") is None

    @pytest.mark.security
    def test_key_with_non_sig_use_ignored(self, rsa_key: RSAKey) -> None:
        """TM-ING-03: an encryption key published in the same JWKS must not verify signatures."""
        k = {**rsa_key.as_dict(private=False), "use": "enc"}
        assert JwksKeyResolver(fetch=_Fetcher({"keys": [k]})).resolve("rsa-1") is None

    @pytest.mark.parametrize("doc", [{}, {"keys": "x"}, {"keys": [1, None, "k"]}, []])
    def test_garbage_jwks_yields_no_keys(self, doc: Any) -> None:
        assert JwksKeyResolver(fetch=_Fetcher(doc)).resolve("rsa-1") is None


# ----------------------------------------------------------------------------- reject-path edges


def _signed_raw_payload(key: RSAKey, payload: bytes) -> str:
    """Validly signed JWS whose payload is not a JSON object (or not JSON at all)."""
    from joserfc import jws

    return jws.serialize_compact(
        {"alg": "RS256", "kid": key.kid}, payload, key, algorithms=["RS256"]
    )


class TestPolicyEdges:
    @pytest.mark.parametrize("iss", ["http://idp.example.test", " https://idp.example.test", ""])
    def test_rejects_non_https_issuer(self, iss: str) -> None:
        with pytest.raises(ValueError, match="issuer"):
            policy(issuer=iss)

    def test_rejects_non_positive_size_limit(self) -> None:
        with pytest.raises(ValueError, match="max_token_bytes"):
            policy(max_token_bytes=0)


@pytest.mark.security
class TestStructuralEdges:
    def test_empty_header_segment(self, validator: TokenValidator) -> None:
        """TM-ING-01"""
        assert_rejected(validator, ".e30.", Reason.MALFORMED)

    def test_header_not_an_object(self, validator: TokenValidator) -> None:
        """TM-ING-01"""
        assert_rejected(validator, f"{b64url(b'[1]')}.e30.", Reason.MALFORMED)

    @pytest.mark.parametrize("payload", [b"not json", b"[1, 2]", b'"str"'])
    def test_signed_non_object_payload(
        self, validator: TokenValidator, rsa_key: RSAKey, payload: bytes
    ) -> None:
        """TM-ING-01: a valid signature over garbage is still garbage."""
        assert_rejected(validator, _signed_raw_payload(rsa_key, payload), Reason.MALFORMED)

    @pytest.mark.parametrize("aud", [123, {"a": 1}, [AUDIENCE, 5]])
    def test_aud_wrong_type(self, validator: TokenValidator, mint: Mint, aud: Any) -> None:
        """TM-ING-02"""
        assert_rejected(validator, mint(good_claims(aud=aud)), Reason.MALFORMED)


@pytest.mark.security
class TestJwksEntryEdges:
    def test_entry_without_kid_ignored(self, rsa_key: RSAKey) -> None:
        """TM-ING-03"""
        k = rsa_key.as_dict(private=False)
        del k["kid"]
        assert JwksKeyResolver(fetch=_Fetcher({"keys": [k]})).resolve("rsa-1") is None

    def test_unsupported_curve_and_kty_ignored(self) -> None:
        """TM-ING-01: only P-256 EC and RSA are verification keys."""
        from joserfc.jwk import OKPKey

        p384 = ECKey.generate_key("P-384", parameters={"kid": "p384"}, private=True)
        ed = OKPKey.generate_key("Ed25519", parameters={"kid": "ed"}, private=True)
        r = JwksKeyResolver(fetch=_Fetcher(jwks(p384, ed)))  # type: ignore[arg-type]
        assert r.resolve("p384") is None
        assert r.resolve("ed") is None

    def test_corrupt_rsa_entry_ignored(self) -> None:
        """TM-ING-03: a malformed entry must not break, or poison, the rest of the set."""
        doc = {"keys": [{"kty": "RSA", "kid": "bad", "n": "!!", "e": "AQAB"}]}
        assert JwksKeyResolver(fetch=_Fetcher(doc)).resolve("bad") is None


# ----------------------------------------------------------------------------- ADR-0027


@pytest.mark.security
class TestKeyRotationUnderSameKid:
    """ADR-0027: an IdP that rotates key material under the same kid recovers within one
    rate-limited refresh, without giving forgers a way to amplify JWKS fetches."""

    @staticmethod
    def rotated(kid: str = "rsa-1") -> RSAKey:
        return RSAKey.generate_key(2048, parameters={"kid": kid}, private=True)

    @staticmethod
    def setup(*docs: dict[str, Any]) -> tuple[TokenValidator, _Fetcher, _Clock]:
        clock, fetch = _Clock(), _Fetcher(*docs)
        resolver = JwksKeyResolver(fetch=fetch, now=clock)
        return TokenValidator(policy(), resolver, now=lambda: NOW), fetch, clock

    def test_rotation_under_same_kid_recovers_with_one_refresh(
        self, rsa_key: RSAKey, mint: Mint
    ) -> None:
        new = self.rotated()
        v, fetch, clock = self.setup(jwks(rsa_key), jwks(new))
        v.validate(mint())  # warm: old key cached
        clock.t += 61
        assert v.validate(mint(key=new)).subject  # same kid, new material: recovers
        assert fetch.calls == 2

    def test_no_refresh_inside_the_rate_limit(self, rsa_key: RSAKey, mint: Mint) -> None:
        new = self.rotated()
        v, fetch, clock = self.setup(jwks(rsa_key), jwks(new))
        v.validate(mint())
        clock.t += 30
        assert_rejected(v, mint(key=new), Reason.BAD_SIGNATURE)
        assert fetch.calls == 1

    def test_forged_signature_flood_is_rate_limited(self, rsa_key: RSAKey, mint: Mint) -> None:
        """A forger presenting a known kid gets BAD_SIGNATURE and at most one fetch per 60 s."""
        forger = self.rotated()
        v, fetch, clock = self.setup(jwks(rsa_key))
        v.validate(mint())
        for _ in range(240):  # 120 s of attack, two tries per second
            clock.t += 0.5
            assert_rejected(v, mint(key=forger), Reason.BAD_SIGNATURE)
        assert fetch.calls <= 1 + 3

    def test_budget_is_shared_with_unknown_kid(self, rsa_key: RSAKey, mint: Mint) -> None:
        forger = self.rotated()
        v, fetch, clock = self.setup(jwks(rsa_key))
        v.validate(mint())
        clock.t += 61
        assert_rejected(v, mint(key=self.rotated("nope")), Reason.UNKNOWN_KID)  # spends it
        assert_rejected(v, mint(key=forger), Reason.BAD_SIGNATURE)  # no second fetch
        assert fetch.calls == 2

    def test_exactly_one_reverify(self, rsa_key: RSAKey, mint: Mint) -> None:
        """Rotated JWKS, but the token was signed by neither key: one refresh, one retry, deny."""
        v, fetch, clock = self.setup(jwks(rsa_key), jwks(self.rotated()))
        v.validate(mint())
        clock.t += 61
        assert_rejected(v, mint(key=self.rotated()), Reason.BAD_SIGNATURE)
        assert fetch.calls == 2

    def test_static_resolvers_never_retry(self, validator: TokenValidator, mint: Mint) -> None:
        assert_rejected(validator, mint(key=self.rotated()), Reason.BAD_SIGNATURE)


@pytest.mark.security
def test_default_revocation_window_is_five_minutes(rsa_key: RSAKey, ec_key: ECKey) -> None:
    """ADR-0027: a key the IdP removes (e.g. after compromise) stops being trusted within 5 min
    with the *default* settings, even while its kid keeps being presented."""
    clock = _Clock()
    r = JwksKeyResolver(fetch=_Fetcher(jwks(rsa_key, ec_key), jwks(ec_key)), now=clock)
    assert r.max_key_age_s == 300
    assert r.resolve("rsa-1") is not None
    clock.t += 299
    assert r.resolve("rsa-1") is not None
    clock.t += 2
    assert r.resolve("rsa-1") is None
