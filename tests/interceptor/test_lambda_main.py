"""Lambda entrypoint wiring and cold-start fail-closed behaviour (ADR-0015 §5-§6)."""

from __future__ import annotations

import base64
import json
import pathlib
from types import SimpleNamespace
from typing import Any

import pytest
from atf_interceptor.lambda_main import build_handler, make_signer_factory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tests.exchange.conftest import profile_doc
from trustkit.signing import InMemoryEs256Signer, SigningError

ARN = "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-alpha"


def write_key(d: pathlib.Path, name: str) -> None:
    d.mkdir(exist_ok=True)
    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (d / f"{name}.pem").write_bytes(pem)


def event() -> dict[str, Any]:
    return {
        "interceptorInputVersion": "1.0",
        "http": {
            "gatewayRequest": {
                "path": "/agent-alpha/invocations",
                "httpMethod": "POST",
                "headers": {"Authorization": "Bearer x", "X-Subject-Token": "y"},
                "body": base64.b64encode(b"{}").decode(),
            }
        },
    }


def ctx() -> Any:
    return SimpleNamespace(
        client_context=SimpleNamespace(custom={"GATEWAY_ARN": ARN, "REQUEST_ID": "r1"}),
        aws_request_id="r1",
        get_remaining_time_in_millis=lambda: 10_000,
    )


def status(out: dict[str, Any]) -> int:
    return int(out["http"]["transformedGatewayResponse"]["statusCode"])


@pytest.mark.security
class TestSignerFactory:
    def test_local_keys_in_local_env(self, tmp_path: pathlib.Path) -> None:
        write_key(tmp_path / "keys", "chat")
        f = make_signer_factory({"ATF_ENV": "local", "ATF_LOCAL_KEYS_DIR": str(tmp_path / "keys")})
        s = f("local:chat")
        assert isinstance(s, InMemoryEs256Signer)
        assert f("local:chat") is s, "memoised"

    @pytest.mark.parametrize("env_name", ["prod", "staging", "", "LOCAL"])
    def test_local_keys_refused_elsewhere(self, tmp_path: pathlib.Path, env_name: str) -> None:
        """TM-EXC-01: a file-based key must never be usable outside the local stack."""
        write_key(tmp_path / "keys", "chat")
        f = make_signer_factory({"ATF_ENV": env_name, "ATF_LOCAL_KEYS_DIR": str(tmp_path / "keys")})
        with pytest.raises(SigningError):
            f("local:chat")

    @pytest.mark.parametrize(
        "ref", ["local:../etc/passwd", "local:chat/../x", "local:", "file:/x", "chat"]
    )
    def test_bad_refs_refused(self, tmp_path: pathlib.Path, ref: str) -> None:
        """No path traversal or unknown schemes via profile key refs."""
        write_key(tmp_path / "keys", "chat")
        f = make_signer_factory({"ATF_ENV": "local", "ATF_LOCAL_KEYS_DIR": str(tmp_path / "keys")})
        with pytest.raises(SigningError):
            f(ref)

    def test_missing_local_key_file(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "keys").mkdir()
        f = make_signer_factory({"ATF_ENV": "local", "ATF_LOCAL_KEYS_DIR": str(tmp_path / "keys")})
        with pytest.raises(SigningError):
            f("local:chat")


@pytest.mark.security
class TestColdStartFailsClosed:
    @pytest.mark.parametrize(
        "env",
        [
            pytest.param({}, id="no-env"),
            pytest.param({"ATF_ENV": "local"}, id="no-profiles-path"),
            pytest.param(
                {"ATF_ENV": "local", "ATF_PROFILES_PATH": "/nonexistent.json"}, id="missing-file"
            ),
        ],
    )
    def test_unusable_config_denies_everything(
        self, env: dict[str, str], capsys: pytest.CaptureFixture[str]
    ) -> None:
        handler = build_handler(env)
        out = handler(event(), ctx())
        assert status(out) == 503
        logged = [
            json.loads(line)
            for line in capsys.readouterr().out.splitlines()
            if line.startswith("{")
        ]
        assert any(e["event_type"] == "config.invalid" for e in logged)

    def test_unparseable_profiles_deny(self, tmp_path: pathlib.Path) -> None:
        p = tmp_path / "profiles.json"
        p.write_text("{not json")
        assert (
            status(build_handler({"ATF_ENV": "local", "ATF_PROFILES_PATH": str(p)})(event(), ctx()))
            == 503
        )

    def test_wired_handler_runs(self, tmp_path: pathlib.Path) -> None:
        """Valid wiring: a bogus caller token is a 401 from the real pipeline, not a 503."""
        p = tmp_path / "profiles.json"
        p.write_text(json.dumps({"version": 1, "profiles": [profile_doc(gateway_id="gw-alpha")]}))
        write_key(tmp_path / "keys", "chat")
        env = {
            "ATF_ENV": "local",
            "ATF_PROFILES_PATH": str(p),
            "ATF_LOCAL_KEYS_DIR": str(tmp_path / "keys"),
            "ATF_CA_BUNDLE": write_ca(tmp_path),
        }
        assert status(build_handler(env)(event(), ctx())) == 401
        # The local stack without its pinned CA never widens trust: it fails closed instead.
        no_ca = {k: v for k, v in env.items() if k != "ATF_CA_BUNDLE"}
        assert status(build_handler(no_ca)(event(), ctx())) == 503

    def test_inline_profiles(self, tmp_path: pathlib.Path) -> None:
        """AWS: profiles rendered at deploy as ``ATF_PROFILES_JSON`` (ADR-0026 §13)."""
        doc = json.dumps({"version": 1, "profiles": [profile_doc(gateway_id="gw-alpha")]})
        write_key(tmp_path / "keys", "chat")
        env = {
            "ATF_ENV": "local",
            "ATF_PROFILES_JSON": doc,
            "ATF_LOCAL_KEYS_DIR": str(tmp_path / "keys"),
            "ATF_CA_BUNDLE": write_ca(tmp_path),
        }
        assert status(build_handler(env)(event(), ctx())) == 401
        both = {**env, "ATF_PROFILES_PATH": str(tmp_path / "unused.json")}
        assert status(build_handler(both)(event(), ctx())) == 503

    def test_never_raises_even_with_hostile_env(self) -> None:
        handler = build_handler({"ATF_ENV": "local", "ATF_PROFILES_PATH": "\x00bad"})
        assert status(handler(event(), ctx())) == 503


@pytest.mark.security
def test_kms_reference_builds_kms_signer_in_any_env() -> None:
    """Production path: KMS key ARNs work regardless of ATF_ENV (only local: refs are gated)."""
    import boto3
    from moto import mock_aws

    from trustkit_aws.kms import KmsEs256Signer

    with mock_aws():
        arn = boto3.client("kms", region_name="us-east-1").create_key(
            KeySpec="ECC_NIST_P256", KeyUsage="SIGN_VERIFY"
        )["KeyMetadata"]["Arn"]
        f = make_signer_factory({"ATF_ENV": "prod"})
        assert isinstance(f(arn), KmsEs256Signer)


def write_ca(tmp_path: pathlib.Path) -> str:
    from tests.inference.test_wiring import _ca_pem

    (tmp_path / "ca.pem").write_bytes(_ca_pem())
    return str(tmp_path / "ca.pem")


@pytest.mark.security
class TestBundleWiring:
    def base(self, tmp_path: pathlib.Path) -> dict[str, str]:
        p = tmp_path / "profiles.json"
        p.write_text(json.dumps({"version": 1, "profiles": [profile_doc(gateway_id="gw-alpha")]}))
        write_key(tmp_path / "keys", "chat")
        return {
            "ATF_ENV": "local",
            "ATF_PROFILES_PATH": str(p),
            "ATF_LOCAL_KEYS_DIR": str(tmp_path / "keys"),
            "ATF_CA_BUNDLE": write_ca(tmp_path),
        }

    def test_bundle_configured_handler_runs(self, tmp_path: pathlib.Path) -> None:
        from tests.policy.test_bundle import SIGNER

        (tmp_path / "k.jwk").write_text(json.dumps(SIGNER.public_jwk()))
        env = {
            **self.base(tmp_path),
            "ATF_BUNDLE_ISSUER": "atf-bundle-publisher",
            "ATF_BUNDLE_PUBLIC_JWK_PATH": str(tmp_path / "k.jwk"),
            "ATF_BUNDLE_PATH": str(tmp_path / "bundle.jws"),
        }
        assert status(build_handler(env)(event(), ctx())) == 401  # wired, real pipeline

    def test_broken_bundle_config_denies_everything(self, tmp_path: pathlib.Path) -> None:
        """Bundle configured but unusable (no source): cold-start failure -> deny-all handler."""
        env = {**self.base(tmp_path), "ATF_BUNDLE_ISSUER": "x"}
        assert status(build_handler(env)(event(), ctx())) == 503


@pytest.mark.security
class TestGatewayIdParameter:
    """ADR-0026 §22: the AWS-assigned gateway id comes from one SSM parameter at cold start and is
    still matched exactly against ``GATEWAY_ARN`` (ADR-0012 §2). Every failure is deny-all."""

    def env(self, tmp_path: pathlib.Path, *profiles: dict[str, Any]) -> dict[str, str]:
        write_key(tmp_path / "keys", "chat")
        return {
            "ATF_ENV": "local",
            "ATF_PROFILES_JSON": json.dumps({"version": 1, "profiles": list(profiles)}),
            "ATF_GATEWAY_ID_PARAMETER": "/atf-dev/interceptor/gateway-id",
            "ATF_LOCAL_KEYS_DIR": str(tmp_path / "keys"),
            "ATF_CA_BUNDLE": write_ca(tmp_path),
        }

    def test_bound_id_is_matched_exactly(self, tmp_path: pathlib.Path) -> None:
        asked: list[str] = []

        def fetch(name: str) -> str:
            asked.append(name)
            return "gw-alpha\n"

        env = self.env(tmp_path, profile_doc(gateway_id="bound-at-cold-start"))
        assert status(build_handler(env, fetch_parameter=fetch)(event(), ctx())) == 401
        assert asked == ["/atf-dev/interceptor/gateway-id"]

    def test_other_gateway_is_unknown(self, tmp_path: pathlib.Path) -> None:
        env = self.env(tmp_path, profile_doc(gateway_id="x"))
        assert (
            status(build_handler(env, fetch_parameter=lambda n: "gw-beta")(event(), ctx())) == 403
        )

    @pytest.mark.parametrize("value", ["", "../gw-alpha", "gw alpha", "-gw", "g" * 101])
    def test_malformed_id_denies_everything(self, tmp_path: pathlib.Path, value: str) -> None:
        env = self.env(tmp_path, profile_doc(gateway_id="x"))
        assert status(build_handler(env, fetch_parameter=lambda n: value)(event(), ctx())) == 503

    def test_unreadable_parameter_denies_everything(self, tmp_path: pathlib.Path) -> None:
        def fetch(name: str) -> str:
            raise RuntimeError("AccessDenied")

        env = self.env(tmp_path, profile_doc(gateway_id="x"))
        assert status(build_handler(env, fetch_parameter=fetch)(event(), ctx())) == 503

    def test_needs_exactly_one_profile(self, tmp_path: pathlib.Path) -> None:
        """Binding one id into several profiles would be ambiguous: refuse instead."""
        env = self.env(tmp_path, profile_doc(gateway_id="a"), profile_doc(gateway_id="b"))
        assert (
            status(build_handler(env, fetch_parameter=lambda n: "gw-alpha")(event(), ctx())) == 503
        )
        empty = self.env(tmp_path)
        assert (
            status(build_handler(empty, fetch_parameter=lambda n: "gw-alpha")(event(), ctx()))
            == 503
        )
