"""DPoP proofs and the gateway guard (ADR-0028 Phase 1, TM-TOK-01)."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from typing import Any

import pytest

from trustkit.dpop import (
    DpopError,
    DpopKey,
    DpopMode,
    DpopReason,
    DpopVerifier,
    NonceIssuer,
    ReplayCache,
    access_token_hash,
    authenticate_workload,
    bound_jkt,
    canonical_htu,
    challenge_headers,
)

T = 1_800_000_000
URL = "https://mcp.atf.example.com/mcp"
TOKEN = "opaque-test-access-token"  # not a credential: DPoP only hashes it (ath)
KEY = b"k" * 32


class Clock:
    def __init__(self, t: float = T) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def b64(d: Any) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def setup(clock: Clock | None = None) -> tuple[DpopKey, DpopVerifier, NonceIssuer, Clock]:
    c = clock or Clock()
    nonces = NonceIssuer(KEY, now=c)
    verifier = DpopVerifier(nonces=nonces, replay=ReplayCache(now=c), now=lambda: int(c.t))
    return DpopKey(), verifier, nonces, c


def proof(key: DpopKey, nonces: NonceIssuer, c: Clock, **over: Any) -> str:
    args: dict[str, Any] = {"access_token": TOKEN, "nonce": nonces.issue("agent-a")}
    method, url = over.pop("method", "POST"), over.pop("url", URL)
    args.update(over)
    return key.proof(method, url, now=lambda: int(c.t), **args)


def verify(v: DpopVerifier, p: str, key: DpopKey, **over: Any) -> Any:
    args: dict[str, Any] = {
        "method": "POST",
        "url": URL,
        "access_token": TOKEN,
        "expected_jkt": key.jkt,
        "client_id": "agent-a",
    }
    args.update(over)
    return v.verify(p, **args)


def rejected(fn: Any, reason: DpopReason) -> DpopError:
    with pytest.raises(DpopError) as ei:
        fn()
    assert ei.value.reason is reason
    return ei.value


class TestHappyPath:
    def test_proof_verifies(self) -> None:
        key, v, n, c = setup()
        assert verify(v, proof(key, n, c), key).jkt == key.jkt

    def test_htu_is_canonical(self) -> None:
        key, v, n, c = setup()
        p = proof(key, n, c, url="https://MCP.atf.example.com:443/mcp?q=1#f")
        assert verify(v, p, key).jkt == key.jkt

    @pytest.mark.parametrize(
        ("url", "canon"),
        [
            ("https://A.example.com/x?y=1", "https://a.example.com/x"),
            ("https://a.example.com:8443/x", "https://a.example.com:8443/x"),
            ("https://a.example.com", "https://a.example.com/"),
        ],
    )
    def test_canonical_htu(self, url: str, canon: str) -> None:
        assert canonical_htu(url) == canon


@pytest.mark.security
class TestEachCheck:
    def test_wrong_method(self) -> None:
        key, v, n, c = setup()
        rejected(lambda: verify(v, proof(key, n, c, method="GET"), key), DpopReason.WRONG_TARGET)

    def test_wrong_url(self) -> None:
        key, v, n, c = setup()
        p = proof(key, n, c, url="https://inference.atf.example.com/mcp")
        rejected(lambda: verify(v, p, key), DpopReason.WRONG_TARGET)

    def test_proof_for_another_token(self) -> None:
        key, v, n, c = setup()
        p = proof(key, n, c, access_token="other.token.value")
        rejected(lambda: verify(v, p, key), DpopReason.WRONG_TOKEN)

    def test_proof_without_ath(self) -> None:
        key, v, n, c = setup()
        p = key.proof("POST", URL, nonce=n.issue("agent-a"), now=lambda: int(c.t))
        rejected(lambda: verify(v, p, key), DpopReason.WRONG_TOKEN)

    @pytest.mark.parametrize("skew", [-61, 61])
    def test_stale_or_future_iat(self, skew: int) -> None:
        key, v, n, c = setup()
        p = key.proof(
            "POST", URL, access_token=TOKEN, nonce=n.issue("agent-a"), now=lambda: int(c.t) + skew
        )
        rejected(lambda: verify(v, p, key), DpopReason.STALE)

    def test_replay_in_same_instance(self) -> None:
        key, v, n, c = setup()
        p = proof(key, n, c)
        verify(v, p, key)
        rejected(lambda: verify(v, p, key), DpopReason.REPLAY)

    def test_stolen_token_with_attackers_own_key(self) -> None:
        """The core property: the token is bound to the agent's key; a thief's can't prove it."""
        agent, v, n, c = setup()
        thief = DpopKey()
        rejected(lambda: verify(v, proof(thief, n, c), agent), DpopReason.KEY_MISMATCH)

    def test_missing_nonce_is_challenged_with_a_fresh_one(self) -> None:
        key, v, n, c = setup()
        p = key.proof("POST", URL, access_token=TOKEN, now=lambda: int(c.t))
        err = rejected(lambda: verify(v, p, key), DpopReason.USE_NONCE)
        assert err.nonce is not None
        assert n.valid(err.nonce, "agent-a")

    def test_nonce_for_another_client(self) -> None:
        key, v, n, c = setup()
        p = proof(key, n, c, nonce=n.issue("agent-b"))
        rejected(lambda: verify(v, p, key), DpopReason.USE_NONCE)

    def test_refusal_does_not_burn_the_jti(self) -> None:
        """A proof refused before the replay check can be corrected; nothing is recorded early."""
        key, v, n, c = setup()
        bad = key.proof("POST", URL, access_token=TOKEN, now=lambda: int(c.t))
        rejected(lambda: verify(v, bad, key), DpopReason.USE_NONCE)
        assert verify(v, proof(key, n, c), key)

    def test_tampered_payload(self) -> None:
        key, v, n, c = setup()
        h, _, s = proof(key, n, c).split(".")
        forged = f"{h}.{b64({'htm': 'POST', 'htu': URL, 'iat': T, 'jti': 'x' * 16})}.{s}"
        rejected(lambda: verify(v, forged, key), DpopReason.BAD_SIGNATURE)

    @pytest.mark.parametrize(
        "header",
        [
            {"typ": "JWT", "alg": "ES256"},
            {"typ": "dpop+jwt", "alg": "HS256"},
            {"typ": "dpop+jwt", "alg": "none"},
            {"typ": "dpop+jwt", "alg": "ES256", "kid": "x"},  # nothing beyond typ/alg/jwk
        ],
    )
    def test_bad_header(self, header: dict[str, Any]) -> None:
        key, v, n, c = setup()
        _, p, s = proof(key, n, c).split(".")
        hdr = {**header, "jwk": dict(key.public_jwk)}
        rejected(lambda: verify(v, f"{b64(hdr)}.{p}.{s}", key), DpopReason.BAD_HEADER)

    def test_private_key_in_jwk_refused(self) -> None:
        key, v, n, c = setup()
        _, p, s = proof(key, n, c).split(".")
        hdr = {"typ": "dpop+jwt", "alg": "ES256", "jwk": {**key.public_jwk, "d": "AAAA"}}
        rejected(lambda: verify(v, f"{b64(hdr)}.{p}.{s}", key), DpopReason.BAD_HEADER)

    @pytest.mark.parametrize("raw", ["", "a.b", "a.b.c.d", "!!.@@.##", "x" * 5000])
    def test_malformed(self, raw: str) -> None:
        key, v, _, _ = setup()
        rejected(lambda: verify(v, raw, key), DpopReason.MALFORMED)


@pytest.mark.security
class TestNonce:
    def test_previous_epoch_accepted_older_refused(self) -> None:
        c = Clock()
        n = NonceIssuer(KEY, now=c)
        old = n.issue("agent-a")
        c.t += 300
        assert n.valid(old, "agent-a")
        c.t += 300
        assert not n.valid(old, "agent-a")

    def test_instances_sharing_the_key_agree(self) -> None:
        c = Clock()
        assert NonceIssuer(KEY, now=c).valid(NonceIssuer(KEY, now=c).issue("a"), "a")
        assert not NonceIssuer(b"z" * 32, now=c).valid(NonceIssuer(KEY, now=c).issue("a"), "a")

    @pytest.mark.parametrize("bad", ["", "x", "1.", ".mac", "abc.mac", "999999999999.mac"])
    def test_garbage_nonce(self, bad: str) -> None:
        assert not NonceIssuer(KEY, now=Clock()).valid(bad, "a")

    def test_short_key_refused(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            NonceIssuer(b"short")


@pytest.mark.security
class TestReplayCache:
    def test_expires(self) -> None:
        c = Clock()
        r = ReplayCache(ttl_s=120, now=c)
        r.add("j1")
        c.t += 121
        r.add("j1")

    def test_full_cache_fails_closed(self) -> None:
        c = Clock()
        r = ReplayCache(max_entries=2, now=c)
        r.add("a")
        r.add("b")
        rejected(lambda: r.add("c"), DpopReason.CACHE_FULL)
        c.t += 1000
        r.add("c")  # expired entries are purged; live ones are never evicted


# ----------------------------------------------------------------------------- gateway guard


def validated(claims: dict[str, Any]) -> Any:
    return lambda token: SimpleNamespace(claims=claims)


@pytest.mark.security
class TestGuard:
    def guard(
        self, headers: dict[str, str], claims: dict[str, Any], mode: DpopMode = DpopMode.OPTIONAL
    ) -> Any:
        _, v, _, _ = setup()
        return authenticate_workload(
            headers, method="POST", url=URL, validate=validated(claims), verifier=v, mode=mode
        )

    def test_bound_token_with_valid_proof(self) -> None:
        key, v, n, c = setup()
        claims = {"sub": "agent-a", "client_id": "agent-a", "cnf": {"jkt": key.jkt}}
        h = {"authorization": f"DPoP {TOKEN}", "dpop": proof(key, n, c)}
        out = authenticate_workload(
            h,
            method="POST",
            url=URL,
            validate=validated(claims),
            verifier=v,
            mode=DpopMode.REQUIRED,
        )
        assert (out.token, out.bound) == (TOKEN, True)

    def test_bound_token_as_bearer_is_refused(self) -> None:
        """Stripping the proof (and switching scheme) must never downgrade a bound token."""
        claims = {"sub": "a", "cnf": {"jkt": "x"}}
        rejected(
            lambda: self.guard({"authorization": f"Bearer {TOKEN}"}, claims), DpopReason.MISSING
        )

    def test_bound_token_without_proof(self) -> None:
        claims = {"sub": "a", "cnf": {"jkt": "x"}}
        rejected(lambda: self.guard({"authorization": f"DPoP {TOKEN}"}, claims), DpopReason.MISSING)

    def test_unbound_bearer_allowed_only_while_optional(self) -> None:
        assert not self.guard({"authorization": f"Bearer {TOKEN}"}, {"sub": "a"}).bound
        rejected(
            lambda: self.guard(
                {"authorization": f"Bearer {TOKEN}"}, {"sub": "a"}, DpopMode.REQUIRED
            ),
            DpopReason.REQUIRED,
        )

    def test_dpop_scheme_with_unbound_token(self) -> None:
        h = {"authorization": f"DPoP {TOKEN}", "dpop": "x.y.z"}
        rejected(lambda: self.guard(h, {"sub": "a"}), DpopReason.REQUIRED)

    @pytest.mark.parametrize("auth", ["", "Bearer", "Basic abc", "dpop abc"])
    def test_missing_credentials(self, auth: str) -> None:
        with pytest.raises(ValueError, match="missing credentials"):
            self.guard({"authorization": auth}, {"sub": "a"})

    @pytest.mark.parametrize("cnf", [{}, {"jkt": ""}, {"x5t#S256": "abc"}, "jkt", 7])
    def test_malformed_cnf_is_bound_to_nothing(self, cnf: Any) -> None:
        """A malformed ``cnf`` is never read as "unbound"; it can't be proven either."""
        assert bound_jkt({"cnf": cnf}) is not None
        claims = {"sub": "a", "cnf": cnf}
        rejected(
            lambda: self.guard({"authorization": f"Bearer {TOKEN}"}, claims), DpopReason.MISSING
        )


def test_challenge_headers() -> None:
    h = challenge_headers(DpopError(DpopReason.USE_NONCE, nonce="1.mac"))
    assert h == {
        "WWW-Authenticate": 'DPoP error="use_dpop_nonce", algs="ES256"',
        "DPoP-Nonce": "1.mac",
    }
    assert "DPoP-Nonce" not in challenge_headers(DpopError(DpopReason.REPLAY))


def test_ath_matches_rfc_example() -> None:
    """RFC 9449 §7.1 example token and its ``ath``."""
    token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
    assert access_token_hash(token) == "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"


# ----------------------------------------------------------------------------- agent sender


@pytest.mark.security
class TestDpopPost:
    def gateway(self, c: Clock) -> tuple[Any, list[dict[str, str]]]:
        """A fake gateway that demands DPoP with a nonce, like ours."""
        nonces = NonceIssuer(KEY, now=c)
        verifier = DpopVerifier(nonces=nonces, replay=ReplayCache(now=c), now=lambda: int(c.t))
        seen: list[dict[str, str]] = []

        def raw_post(url: str, payload: Any, headers: Any) -> tuple[int, Any, dict[str, str]]:
            seen.append(dict(headers))
            tok = headers["Authorization"].removeprefix("DPoP ")
            try:
                verifier.verify(
                    headers["DPoP"],
                    method="POST",
                    url=url,
                    access_token=tok,
                    expected_jkt=self.key.jkt,
                    client_id="agent-a",
                )
            except DpopError as e:
                return 401, None, {k.lower(): v for k, v in challenge_headers(e).items()}
            return 200, {"ok": True}, {}

        return raw_post, seen

    def test_bearer_becomes_dpop_and_nonce_is_learned(self) -> None:
        from trustkit.dpop import dpop_post

        c = Clock()
        self.key = DpopKey()
        raw, seen = self.gateway(c)
        post = dpop_post(self.key, raw, now=lambda: int(c.t))
        assert post(URL, {}, {"Authorization": f"Bearer {TOKEN}"}) == (200, {"ok": True})
        assert len(seen) == 2  # challenged once, then accepted
        assert all(h["Authorization"] == f"DPoP {TOKEN}" for h in seen)
        assert (
            post(
                "https://mcp.atf.example.com/other/path", {}, {"Authorization": f"Bearer {TOKEN}"}
            )[0]
            == 200
        )
        assert len(seen) == 3  # same origin: the cached nonce is reused, no new challenge

    def test_one_retry_only(self) -> None:
        from trustkit.dpop import dpop_post

        calls: list[int] = []

        def always_challenge(
            url: str, payload: Any, headers: Any
        ) -> tuple[int, Any, dict[str, str]]:
            calls.append(1)
            return (
                401,
                None,
                {"www-authenticate": 'DPoP error="use_dpop_nonce"', "dpop-nonce": f"n{len(calls)}"},
            )

        status, _ = dpop_post(DpopKey(), always_challenge)(
            URL, {}, {"Authorization": f"Bearer {TOKEN}"}
        )
        assert (status, len(calls)) == (401, 2)

    def test_non_bearer_requests_pass_through(self) -> None:
        from trustkit.dpop import dpop_post

        seen: list[Any] = []

        def raw(url: str, payload: Any, headers: Any) -> tuple[int, Any, dict[str, str]]:
            seen.append(headers)
            return 200, None, {}

        dpop_post(DpopKey(), raw)(URL, {}, {"X-Other": "1"})
        assert seen == [{"X-Other": "1"}]
