"""Gateway glue for bundles (ADR-0022 §6, ADR-0023)."""

from __future__ import annotations

import json
import pathlib
import threading
from typing import Any

import pytest

from tests.policy.helpers import loaded_bundle, make_grant
from tests.policy.test_bundle import ISS, SIGNER, MemSource, bundle
from trustkit.jwt import VerifiedToken
from trustkit.profiles import ScannerFailureMode
from trustkit_policy.bundle import BundleHolder, BundleVerifier, RefreshOutcome, sign_bundle
from trustkit_policy.runtime import (
    BundleGuard,
    BundleSettings,
    actor_policies_from_bundle,
    effective_fail_mode,
    policy_from_env,
    read_jwk,
    tool_decision,
    user_scopes,
)

T = 1_800_000_000
BASE = "https://idp.example.test"
AGENT = "0oa-agent-alpha"


def ingress() -> dict[str, str]:
    return {
        "t2_issuer": f"{BASE}/oauth2/agent-alpha",
        "t2_audience": "api://agent-alpha",
        "t2_jwks_uri": f"{BASE}/oauth2/agent-alpha/v1/keys",
    }


# ----------------------------------------------------------------------------- settings


@pytest.fixture
def jwk_file(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "bundle-key.jwk"
    p.write_text(json.dumps(SIGNER.public_jwk()))
    return p


def env(jwk_file: pathlib.Path, **over: str) -> dict[str, str]:
    e = {"ATF_BUNDLE_ISSUER": ISS, "ATF_BUNDLE_PUBLIC_JWK_PATH": str(jwk_file)}
    e.update(over)
    return e


class TestSettings:
    def test_defaults(self, jwk_file: pathlib.Path) -> None:
        s = BundleSettings.from_env(env(jwk_file))
        assert (s.issuer, s.max_age_s, s.refresh_s) == (ISS, 600, 60)
        assert s.public_jwk == SIGNER.public_jwk()

    def test_local_short_ages(self, jwk_file: pathlib.Path) -> None:
        s = BundleSettings.from_env(
            env(jwk_file, ATF_BUNDLE_MAX_AGE_S="20", ATF_BUNDLE_REFRESH_S="2")
        )
        assert (s.max_age_s, s.refresh_s) == (20, 2)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "over",
        [
            {"ATF_BUNDLE_MAX_AGE_S": "601"},  # above the platform ceiling
            {"ATF_BUNDLE_MAX_AGE_S": "0"},
            {"ATF_BUNDLE_MAX_AGE_S": "ten"},
            {"ATF_BUNDLE_REFRESH_S": "600"},  # refresh must be shorter than max age
            {"ATF_BUNDLE_REFRESH_S": "0"},
        ],
    )
    def test_invalid_is_cold_start_failure(
        self, jwk_file: pathlib.Path, over: dict[str, str]
    ) -> None:
        with pytest.raises(ValueError):  # noqa: PT011 - any ValueError is a cold-start failure
            BundleSettings.from_env(env(jwk_file, **over))

    @pytest.mark.security
    def test_private_key_file_refused(self, tmp_path: pathlib.Path) -> None:
        """The pinned verification key must be public; a JWK with ``d`` is a config error."""
        p = tmp_path / "k.jwk"
        p.write_text(json.dumps({**SIGNER.public_jwk(), "d": "secret"}))
        with pytest.raises(ValueError, match="public"):
            read_jwk(p)

    def test_missing_vars(self, jwk_file: pathlib.Path) -> None:
        with pytest.raises(KeyError):
            BundleSettings.from_env({"ATF_BUNDLE_PUBLIC_JWK_PATH": str(jwk_file)})


# ----------------------------------------------------------------------------- guard


class Clock:
    def __init__(self) -> None:
        self.t = T

    def __call__(self) -> int:
        return self.t


class Mono:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def guard(refresh_s: int = 60) -> tuple[BundleGuard, MemSource, Mono, list[RefreshOutcome]]:
    src, clock, mono, seen = MemSource(), Clock(), Mono(), []
    holder = BundleHolder(
        BundleVerifier(SIGNER.public_jwk(), issuer=ISS, now=clock), src, now=clock
    )
    g = BundleGuard(holder, refresh_s=refresh_s, monotonic=mono, on_outcome=seen.append)
    return g, src, mono, seen


class TestGuard:
    def test_first_call_refreshes(self) -> None:
        g, src, _, seen = guard()
        src.data = sign_bundle(bundle(1), SIGNER)
        assert g.current() is not None
        assert seen == [RefreshOutcome.ACCEPTED]

    def test_refresh_only_when_due(self) -> None:
        g, src, mono, seen = guard()
        src.data = sign_bundle(bundle(1), SIGNER)
        g.current()
        src.data = sign_bundle(bundle(2), SIGNER)
        mono.t = 59
        assert g.current().bundle.bundle_version == 1  # type: ignore[union-attr]
        mono.t = 60
        assert g.current().bundle.bundle_version == 2  # type: ignore[union-attr]
        assert seen == [RefreshOutcome.ACCEPTED, RefreshOutcome.ACCEPTED]

    @pytest.mark.security
    def test_rejections_reported(self) -> None:
        g, src, mono, seen = guard()
        src.data = sign_bundle(bundle(5), SIGNER)
        g.current()
        src.data = sign_bundle(bundle(4), SIGNER)
        mono.t = 60
        g.current()
        assert seen[-1] is RefreshOutcome.REJECTED_ROLLBACK

    def test_no_bundle_is_none(self) -> None:
        g, _, _, seen = guard()
        assert g.current() is None
        assert seen == [RefreshOutcome.UNAVAILABLE]

    def test_single_flight(self) -> None:
        """Concurrent callers: exactly one refresh; nobody blocks on it."""
        g, src, _, seen = guard()
        started, release = threading.Event(), threading.Event()
        real = src.fetch

        def slow() -> bytes | None:
            started.set()
            release.wait(5)
            return real()

        src.data = sign_bundle(bundle(1), SIGNER)
        src.fetch = slow  # type: ignore[method-assign]
        first = threading.Thread(target=g.current)
        first.start()
        started.wait(5)
        assert g.current() is None  # second caller returns immediately (nothing loaded yet)
        release.set()
        first.join(5)
        assert seen == [RefreshOutcome.ACCEPTED]

    def test_hook_failure_never_breaks_requests(self) -> None:
        src, clock, mono = MemSource(), Clock(), Mono()
        holder = BundleHolder(
            BundleVerifier(SIGNER.public_jwk(), issuer=ISS, now=clock), src, now=clock
        )

        def boom(_: RefreshOutcome) -> None:
            raise RuntimeError("alerting down")

        g = BundleGuard(holder, refresh_s=60, monotonic=mono, on_outcome=boom)
        src.data = sign_bundle(bundle(1), SIGNER)
        assert g.current() is not None


# ----------------------------------------------------------------------------- actor policies


class FakeResolver:
    def resolve(self, kid: str) -> Any:
        return None


class TestActorPolicies:
    def test_only_grants_with_ingress_and_scopes(self) -> None:
        loaded = loaded_bundle(
            make_grant(AGENT, ingress=ingress()),
            make_grant("0oa-no-ingress"),  # no T2 binding: can't act for users
            make_grant("0oa-no-tools", ingress=ingress(), tools={}),
        )
        seen: list[str] = []

        def jwks(uri: str) -> Any:
            seen.append(uri)
            return FakeResolver()

        policies = actor_policies_from_bundle(
            loaded, jwks, scopes_for=lambda g: frozenset().union(*g.tools.values()), now=lambda: T
        )
        assert set(policies) == {AGENT}
        assert policies[AGENT].allowed_scopes == frozenset({"tickets.read"})
        assert seen == [f"{BASE}/oauth2/agent-alpha/v1/keys"]

    @pytest.mark.security
    def test_expired_grant_excluded(self) -> None:
        loaded = loaded_bundle(make_grant(AGENT, ingress=ingress(), expires_at=T))
        policies = actor_policies_from_bundle(
            loaded, lambda _: FakeResolver(), scopes_for=lambda g: frozenset({"x"}), now=lambda: T
        )
        assert policies == {}

    def test_scopes_for_empty_excluded(self) -> None:
        loaded = loaded_bundle(make_grant(AGENT, ingress=ingress()))
        policies = actor_policies_from_bundle(
            loaded, lambda _: FakeResolver(), scopes_for=lambda g: frozenset(), now=lambda: T
        )
        assert policies == {}


# ----------------------------------------------------------------------------- decisions


def token(scope: Any) -> VerifiedToken:
    claims: dict[str, Any] = {"sub": "alice"}
    if scope is not None:
        claims["scope"] = scope
    return VerifiedToken(header={}, claims=claims)


class TestUserScopes:
    @pytest.mark.parametrize(
        ("scope", "want"),
        [
            ("agent.invoke tickets.read", {"agent.invoke", "tickets.read"}),
            ("", set()),
            (None, set()),
            (["tickets.read"], set()),  # not a string: no entitlements
            ("  tickets.read  ", {"tickets.read"}),
        ],
    )
    def test_parse(self, scope: Any, want: set[str]) -> None:
        assert user_scopes(token(scope)) == frozenset(want)


class TestToolDecision:
    def decide(self, **kw: Any) -> Any:
        args: dict[str, Any] = {
            "agent_id": AGENT,
            "user": "alice",
            "user_scopes": frozenset({"tickets.read"}),
            "server_id": "tickets",
            "delegation": "token",
            "requested": frozenset({"tickets.read"}),
        }
        args.update(kw)
        return tool_decision(loaded_bundle(make_grant(AGENT, ingress=ingress())), **args)

    def test_allowed(self) -> None:
        d = self.decide()
        assert d.allowed
        assert d.policy_ids == ("grant:0oa-agent-alpha:tool:tickets",)

    @pytest.mark.security
    def test_user_not_entitled(self) -> None:
        d = self.decide(user_scopes=frozenset({"agent.invoke"}))
        assert not d.allowed
        assert d.policy_ids == ("guardrail:user-scopes",)

    @pytest.mark.security
    def test_empty_request_is_deny(self) -> None:
        assert not self.decide(requested=frozenset()).allowed

    def test_other_server(self) -> None:
        assert not self.decide(server_id="wiki").allowed


@pytest.mark.parametrize(
    ("profile", "grant", "want"),
    [
        ("closed", "closed", "closed"),
        ("open", "closed", "closed"),
        ("closed", "open", "closed"),
        ("open", "open", "open"),
    ],
)
def test_effective_fail_mode(profile: str, grant: str, want: str) -> None:
    got = effective_fail_mode(ScannerFailureMode(profile), ScannerFailureMode(grant))
    assert got is ScannerFailureMode(want)


# ----------------------------------------------------------------------------- policy_from_env


class TestPolicyFromEnv:
    def test_file_source_end_to_end(self, jwk_file: pathlib.Path, tmp_path: pathlib.Path) -> None:
        import time as _time

        from trustkit_policy.sources import FileBundleSink

        now = int(_time.time())
        FileBundleSink(tmp_path).publish(sign_bundle(bundle(1, iat=now), SIGNER))
        events: list[Any] = []

        class Sink:
            def emit(self, e: Any) -> None:
                events.append(e)

        policy = policy_from_env(
            env(jwk_file, ATF_BUNDLE_PATH=str(tmp_path / "bundle.jws")), audit=Sink()
        )
        loaded = policy()
        assert loaded is not None
        assert loaded.bundle.bundle_version == 1
        assert [(e.event_type, e.reason) for e in events] == [("bundle.refresh", "accepted")]

    @pytest.mark.security
    @pytest.mark.parametrize(
        "over",
        [
            {},  # neither source
            {"ATF_BUNDLE_PATH": "/x", "ATF_BUNDLE_S3_BUCKET": "b", "ATF_BUNDLE_S3_KEY": "k"},
            {"ATF_BUNDLE_S3_BUCKET": "b"},  # bucket without key
        ],
    )
    def test_ambiguous_or_missing_source(
        self, jwk_file: pathlib.Path, over: dict[str, str]
    ) -> None:
        with pytest.raises(ValueError, match="source"):
            policy_from_env(env(jwk_file, **over), s3_factory=lambda b, k: MemSource())

    @pytest.mark.security
    def test_s3_without_factory_refused(self, jwk_file: pathlib.Path) -> None:
        with pytest.raises(ValueError, match="source"):
            policy_from_env(env(jwk_file, ATF_BUNDLE_S3_BUCKET="b", ATF_BUNDLE_S3_KEY="k"))

    def test_s3_source_used(self, jwk_file: pathlib.Path) -> None:
        import time as _time

        src = MemSource()
        src.data = sign_bundle(bundle(3, iat=int(_time.time())), SIGNER)
        got: list[tuple[str, str]] = []

        def factory(b: str, k: str) -> MemSource:
            got.append((b, k))
            return src

        policy = policy_from_env(
            env(jwk_file, ATF_BUNDLE_S3_BUCKET="atf-bundles", ATF_BUNDLE_S3_KEY="b.jws"),
            s3_factory=factory,
        )
        assert policy() is not None
        assert got == [("atf-bundles", "b.jws")]
