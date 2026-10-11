"""Gateway profile schema and fail-closed loading (TM-EXC-02, TM-EXC-05)."""

from __future__ import annotations

import contextlib
import copy
import json
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from trustkit.profiles import (
    PLATFORM_MAX_SCANNER_TIMEOUT_MS,
    Flow,
    ProfileConfigError,
    ScannerFailureMode,
    UnknownGatewayError,
    load_profiles,
)

KMS_ARN = "arn:aws:kms:us-east-1:123456789012:key/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"


def ingress_profile(**overrides: Any) -> dict[str, Any]:
    p: dict[str, Any] = {
        "profile_id": "agent-alpha-ingress",
        "gateway_id": "gw-ingress-alpha",
        "flow": "ingress",
        "enabled": True,
        "idp": {
            "issuer": "https://idp.example.test",
            "jwks_uri": "https://idp.example.test/oauth2/v1/keys",
            "token_endpoint": "https://idp.example.test/oauth2/v1/token",
            "resource_issuer": "https://idp.example.test/oauth2/agent-alpha",
            "resource_token_endpoint": "https://idp.example.test/oauth2/agent-alpha/v1/token",
        },
        "client": {"client_id": "0oa-agent-alpha", "signing_key": KMS_ARN},
        "target": {"audience": "api://agent-alpha", "scopes": ["agent.invoke"]},
        "allowed_ingress_client_ids": ["0oa-chat-frontend"],
        "max_id_token_age_s": 3600,
    }
    p.update(overrides)
    return p


def egress_profile(**overrides: Any) -> dict[str, Any]:
    p = ingress_profile(profile_id="tools-egress", gateway_id="gw-tools", flow="egress")
    del p["allowed_ingress_client_ids"], p["max_id_token_age_s"]
    p.update(overrides)
    return p


def doc(*profiles: dict[str, Any], **top: Any) -> str:
    d: dict[str, Any] = {"version": 1, "profiles": list(profiles)}
    d.update(top)
    return json.dumps(d)


def with_nested(base: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(base)
    *parents, leaf = path.split(".")
    node = out
    for p in parents:
        node = node[p]
    node[leaf] = value
    return out


# ----------------------------------------------------------------------------- happy path


class TestLoads:
    def test_ingress_and_egress_profiles(self) -> None:
        reg = load_profiles(doc(ingress_profile(), egress_profile()))
        assert reg.rejected == {}
        assert reg.lookup("gw-ingress-alpha").flow is Flow.INGRESS
        assert reg.lookup("gw-tools").flow is Flow.EGRESS

    def test_scanner_defaults_to_fail_closed(self) -> None:
        """ADR-0004: absent field means closed."""
        p = load_profiles(doc(ingress_profile())).lookup("gw-ingress-alpha")
        assert p.scanner_failure_mode is ScannerFailureMode.CLOSED

    def test_local_signing_key_ref(self) -> None:
        p = ingress_profile(client={"client_id": "c", "signing_key": "local:agent-alpha"})
        assert (
            load_profiles(doc(p)).lookup("gw-ingress-alpha").client.signing_key
            == "local:agent-alpha"
        )

    def test_disabled_profile_still_loads(self) -> None:
        """Denying requests for a disabled gateway is the interceptor's job, not the loader's."""
        assert (
            load_profiles(doc(ingress_profile(enabled=False))).lookup("gw-ingress-alpha").enabled
            is False
        )

    def test_profile_is_immutable(self) -> None:
        p = load_profiles(doc(ingress_profile())).lookup("gw-ingress-alpha")
        with pytest.raises(ValidationError, match="frozen"):
            p.enabled = False  # type: ignore[misc]


# ----------------------------------------------------------------------------- top level


@pytest.mark.security
class TestTopLevelFailsClosed:
    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "",
            b"",
            "not json",
            "[]",
            "null",
            '{"version": 2, "profiles": []}',
            '{"version": "1", "profiles": []}',
            '{"profiles": []}',
            '{"version": 1}',
            '{"version": 1, "profiles": {}}',
            '{"version": 1, "profiles": [], "extra": true}',
        ],
    )
    def test_unusable_document_raises(self, raw: str | bytes | None) -> None:
        """TM-EXC-05: any top-level problem -> caller denies everything."""
        with pytest.raises(ProfileConfigError):
            load_profiles(raw)

    def test_oversized_document_raises(self) -> None:
        """TM-EXC-05 / TM-ING-05: refuse pathological config before parsing."""
        with pytest.raises(ProfileConfigError):
            load_profiles(doc(ingress_profile(), pad="x" * 2_000_000))

    @settings(max_examples=300)
    @given(
        st.recursive(
            st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(),
            lambda children: st.lists(children) | st.dictionaries(st.text(), children),
            max_leaves=25,
        )
    )
    def test_arbitrary_json_never_escapes_as_other_exception(self, value: Any) -> None:
        """TM-EXC-05: the loader's only failure mode is ProfileConfigError (property-based)."""
        with contextlib.suppress(ProfileConfigError):
            load_profiles(json.dumps(value))

    @settings(max_examples=300)
    @given(st.binary(max_size=512))
    def test_arbitrary_bytes_never_escape_as_other_exception(self, raw: bytes) -> None:
        """TM-EXC-05"""
        with contextlib.suppress(ProfileConfigError):
            load_profiles(raw)


# ----------------------------------------------------------------------------- per profile


@pytest.mark.security
class TestPerProfileRejection:
    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(ingress_profile(client_secret="x"), id="unknown-field"),
            pytest.param(ingress_profile(enabled="true"), id="no-bool-coercion"),
            pytest.param(ingress_profile(flow="sideways"), id="unknown-flow"),
            pytest.param(ingress_profile(profile_id="Has Spaces"), id="bad-slug"),
            pytest.param(
                with_nested(ingress_profile(), "idp.issuer", "http://idp.example.test"),
                id="http-issuer",
            ),
            pytest.param(
                with_nested(ingress_profile(), "idp.jwks_uri", "https://"), id="empty-host"
            ),
            pytest.param(with_nested(ingress_profile(), "target.scopes", []), id="empty-scopes"),
            pytest.param(
                with_nested(ingress_profile(), "target.scopes", ["*"]), id="wildcard-scope"
            ),
            pytest.param(
                with_nested(ingress_profile(), "target.scopes", ["agent.*"]), id="glob-scope"
            ),
            pytest.param(
                with_nested(ingress_profile(), "client.signing_key", "s3cr3t-raw-key"),
                id="raw-key-not-ref",
            ),
            pytest.param(
                with_nested(
                    ingress_profile(),
                    "client.signing_key",
                    "arn:aws:kms:us-east-1:123456789012:alias/agent",
                ),
                id="kms-alias-not-key-arn",
            ),
            pytest.param(
                ingress_profile(scanner_timeout_ms=PLATFORM_MAX_SCANNER_TIMEOUT_MS + 1),
                id="timeout-over-max",
            ),
            pytest.param(ingress_profile(scanner_timeout_ms=0), id="timeout-zero"),
            pytest.param(ingress_profile(scanner_failure_mode="maybe"), id="unknown-fail-mode"),
        ],
    )
    def test_invalid_profile_dropped_others_survive(self, bad: dict[str, Any]) -> None:
        """TM-EXC-05 / TM-EXC-02: one bad profile can't take the platform down or widen access."""
        bad = {**bad, "gateway_id": "gw-bad"}
        reg = load_profiles(doc(bad, egress_profile()))
        assert reg.lookup("gw-tools")
        with pytest.raises(UnknownGatewayError):
            reg.lookup("gw-bad")
        assert len(reg.rejected) == 1

    def test_ingress_requires_binding_fields(self) -> None:
        """ADR-0006: ingress profiles must declare allowed clients + max ID-token age."""
        p = ingress_profile()
        del p["allowed_ingress_client_ids"]
        reg = load_profiles(doc(p))
        with pytest.raises(UnknownGatewayError):
            reg.lookup("gw-ingress-alpha")

    def test_ingress_rejects_empty_client_allowlist(self) -> None:
        """ADR-0006"""
        reg = load_profiles(doc(ingress_profile(allowed_ingress_client_ids=[])))
        with pytest.raises(UnknownGatewayError):
            reg.lookup("gw-ingress-alpha")

    def test_egress_forbids_ingress_fields(self) -> None:
        """Fields that don't apply are a config smell, so reject rather than ignore."""
        reg = load_profiles(doc(egress_profile(max_id_token_age_s=60)))
        with pytest.raises(UnknownGatewayError):
            reg.lookup("gw-tools")

    def test_duplicate_gateway_id_drops_both(self) -> None:
        """TM-EXC-05: two profiles for one gateway is ambiguous, so deny rather than pick one."""
        a = ingress_profile(profile_id="alpha-a")
        b = ingress_profile(profile_id="alpha-b", scanner_failure_mode="open")
        reg = load_profiles(doc(a, b, egress_profile()))
        with pytest.raises(UnknownGatewayError):
            reg.lookup("gw-ingress-alpha")
        assert reg.lookup("gw-tools")
        assert reg.rejected == {"gateway_id=gw-ingress-alpha": "duplicate gateway_id"}

    def test_rejection_reasons_do_not_echo_values(self) -> None:
        """TM-ING-06 / TM-AUD-02: a secret pasted into the wrong field must not reach logs."""
        secret = "s3cr3t-value-DO-NOT-LOG"
        reg = load_profiles(doc(ingress_profile(client_secret=secret), egress_profile()))
        blob = json.dumps(dict(reg.rejected))
        assert secret not in blob
        assert "client_secret" in blob  # the field *name* is useful and safe


class TestLookup:
    def test_unknown_gateway(self) -> None:
        with pytest.raises(UnknownGatewayError):
            load_profiles(doc(ingress_profile())).lookup("gw-nonexistent")

    def test_lookup_is_exact(self) -> None:
        """TM-ING-04: no normalisation that could map an attacker-chosen id onto a real one."""
        reg = load_profiles(doc(ingress_profile()))
        for near in ["GW-INGRESS-ALPHA", "gw-ingress-alpha ", "gw-ingress-alpha/"]:
            with pytest.raises(UnknownGatewayError):
                reg.lookup(near)


@pytest.mark.security
class TestParserDifferentials:
    def test_duplicate_json_keys_rejected(self) -> None:
        """TM-EXC-05: '{"enabled": false, "enabled": true}' means different things to different
        parsers (first-wins vs last-wins), so refuse it outright."""
        raw = doc(ingress_profile()).replace('"enabled": true', '"enabled": false, "enabled": true')
        with pytest.raises(ProfileConfigError):
            load_profiles(raw)

    @pytest.mark.parametrize("const", ["NaN", "Infinity", "-Infinity"])
    def test_non_standard_json_constants_rejected(self, const: str) -> None:
        """TM-EXC-05: Python's json accepts these and RFC 8259 does not."""
        raw = (
            doc(ingress_profile())
            .replace('"scanner_timeout_ms"', '"x"')
            .replace('"enabled": true', f'"enabled": true, "pad": {const}')
        )
        with pytest.raises(ProfileConfigError):
            load_profiles(raw)

    def test_duplicate_profile_id_drops_both(self) -> None:
        """profile_id is part of the T2 cache key (ADR-0003); duplicates could collide."""
        a = ingress_profile(profile_id="same", gateway_id="gw-a")
        b = ingress_profile(profile_id="same", gateway_id="gw-b")
        reg = load_profiles(doc(a, b))
        for gid in ("gw-a", "gw-b"):
            with pytest.raises(UnknownGatewayError):
                reg.lookup(gid)
