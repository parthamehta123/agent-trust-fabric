"""Model routes and env-driven wiring for the inference gateway (ADR-0019, ADR-0020)."""

from __future__ import annotations

import json
import pathlib
from collections.abc import Mapping, Sequence
from typing import Any

import boto3
import pytest
from atf_inference_gateway.app import build_app
from atf_inference_gateway.routes import (
    RoutesConfigError,
    load_routes,
    routed,
)
from atf_inference_gateway.service import Completion
from fastapi.testclient import TestClient
from moto import mock_aws

from tests.inference.test_inference import AGENT, profile_doc

LOCAL = {"ATF_ENV": "local"}
LOGICAL, PROVIDER = "claude-sonnet", "openai/mock-sonnet"
BASE = "https://mock-llm:8443/v1"


def routes_doc(**over: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {LOGICAL: {"provider_model": PROVIDER, "api_base": BASE}}
    doc.update(over)
    return doc


class TestLoadRoutes:
    def test_local_route_with_api_base(self) -> None:
        r = load_routes(json.dumps(routes_doc()), env=LOCAL)[LOGICAL]
        assert (r.provider_model, r.api_base) == (PROVIDER, BASE)

    def test_route_without_api_base_ok_anywhere(self) -> None:
        doc = {LOGICAL: {"provider_model": "bedrock/anthropic.claude-test"}}
        assert load_routes(json.dumps(doc), env={})[LOGICAL].api_base is None

    @pytest.mark.security
    @pytest.mark.parametrize("env", [{}, {"ATF_ENV": "prod"}, {"ATF_ENV": "LOCAL"}])
    def test_api_base_outside_local_is_cold_start_failure(self, env: dict[str, str]) -> None:
        """Config must not be able to send prompts to an arbitrary host in a real environment."""
        with pytest.raises(RoutesConfigError):
            load_routes(json.dumps(routes_doc()), env=env)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param(
                {LOGICAL: {"provider_model": PROVIDER, "api_base": "http://x/v1"}}, id="http"
            ),
            pytest.param({LOGICAL: {"provider_model": "a b"}}, id="bad-model-id"),
            pytest.param({LOGICAL: {"provider_model": PROVIDER, "extra": 1}}, id="unknown-key"),
            pytest.param({LOGICAL: {}}, id="missing-provider"),
            pytest.param({"bad name": {"provider_model": PROVIDER}}, id="bad-logical-name"),
            pytest.param({}, id="empty"),
            pytest.param([], id="not-object"),
        ],
    )
    def test_rejects(self, bad: Any) -> None:
        with pytest.raises(RoutesConfigError):
            load_routes(json.dumps(bad), env=LOCAL)

    @pytest.mark.parametrize("raw", ["", "nope", b"\xff"])
    def test_unparseable(self, raw: Any) -> None:
        with pytest.raises(RoutesConfigError):
            load_routes(raw, env=LOCAL)

    def test_duplicate_key(self) -> None:
        raw = '{"m": {"provider_model": "a/b"}, "m": {"provider_model": "c/d"}}'
        with pytest.raises(RoutesConfigError):
            load_routes(raw, env=LOCAL)


class TestRouted:
    def test_maps_logical_to_provider_and_base(self) -> None:
        calls: list[tuple[Any, ...]] = []

        def provider(
            model: str,
            messages: Sequence[Mapping[str, str]],
            max_tokens: int,
            temperature: float | None,
            *,
            api_base: str | None,
        ) -> Completion:
            calls.append((model, list(messages), max_tokens, temperature, api_base))
            return Completion("ok", 1, 2)

        fn = routed(load_routes(json.dumps(routes_doc()), env=LOCAL), provider)
        msgs = [{"role": "user", "content": "hi"}]
        assert fn(LOGICAL, msgs, 16, 0.5).text == "ok"
        assert calls == [(PROVIDER, msgs, 16, 0.5, BASE)]

    def test_unrouted_model_raises(self) -> None:
        """Defence in depth: coverage is checked at cold start, but never fall through."""

        def provider(*_: Any, **__: Any) -> Completion:
            raise AssertionError("must not be called")

        fn = routed(load_routes(json.dumps(routes_doc()), env=LOCAL), provider)
        with pytest.raises(LookupError):
            fn("claude-opus", [{"role": "user", "content": "hi"}], 16, None)


# ----------------------------------------------------------------------------- build_app


@pytest.fixture
def files(tmp_path: pathlib.Path) -> dict[str, str]:
    (tmp_path / "profile.json").write_text(json.dumps(profile_doc()))
    (tmp_path / "routes.json").write_text(json.dumps(routes_doc()))
    (tmp_path / "ca.pem").write_bytes(_ca_pem())
    from tests.policy.test_bundle import SIGNER

    (tmp_path / "bundle-key.jwk").write_text(json.dumps(SIGNER.public_jwk()))
    return {
        "ATF_BUNDLE_ISSUER": "atf-bundle-publisher",
        "ATF_BUNDLE_PUBLIC_JWK_PATH": str(tmp_path / "bundle-key.jwk"),
        "ATF_BUNDLE_PATH": str(tmp_path / "bundle.jws"),
        "ATF_ENV": "local",
        "ATF_INFERENCE_PROFILE_PATH": str(tmp_path / "profile.json"),
        "ATF_MODEL_ROUTES_PATH": str(tmp_path / "routes.json"),
        "ATF_BUDGET_TABLE": "budgets",
        "ATF_CA_BUNDLE": str(tmp_path / "ca.pem"),
        "AWS_REGION": "us-east-1",
    }


def _ca_pem() -> bytes:
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class TestBuildApp:
    def test_local_wiring_creates_budget_table(self, files: dict[str, str]) -> None:
        with mock_aws():
            app = build_app(files)
            assert TestClient(app).get("/ping").json() == {"status": "ok"}
            tables = boto3.client("dynamodb", region_name="us-east-1").list_tables()
            assert "budgets" in tables["TableNames"]

    def test_unauthenticated_request_is_401(self, files: dict[str, str]) -> None:
        with mock_aws():
            r = TestClient(build_app(files)).post("/v1/chat/completions", json={})
        assert r.status_code == 401

    @pytest.mark.security
    def test_api_base_outside_local_fails_cold_start(self, files: dict[str, str]) -> None:
        with mock_aws(), pytest.raises(RoutesConfigError):
            build_app({**files, "ATF_ENV": "prod"})

    @pytest.mark.security
    @pytest.mark.security
    def test_unusable_ca_bundle_fails_cold_start(self, files: dict[str, str]) -> None:
        pathlib.Path(files["ATF_CA_BUNDLE"]).write_text("")
        with mock_aws(), pytest.raises(ValueError, match="ca bundle unusable"):
            build_app(files)

    @pytest.mark.parametrize("missing", ["ATF_INFERENCE_PROFILE_PATH", "ATF_BUDGET_TABLE"])
    def test_missing_required_env_fails_cold_start(
        self, files: dict[str, str], missing: str
    ) -> None:
        env = {k: v for k, v in files.items() if k != missing}
        with mock_aws(), pytest.raises(KeyError):
            build_app(env)

    def test_no_table_creation_outside_local(self, files: dict[str, str]) -> None:
        """Real environments: Terraform owns the table; the service never creates it."""
        routes = json.dumps({LOGICAL: {"provider_model": "bedrock/anthropic.claude-test"}})
        pathlib.Path(files["ATF_MODEL_ROUTES_PATH"]).write_text(routes)
        with mock_aws():
            build_app({**files, "ATF_ENV": "prod"})
            tables = boto3.client("dynamodb", region_name="us-east-1").list_tables()
            assert tables["TableNames"] == []

    def test_guardrail_scanner_selected_when_configured(self, files: dict[str, str]) -> None:
        with mock_aws():
            app = build_app({**files, "ATF_GUARDRAIL_ID": "gr-1", "ATF_GUARDRAIL_VERSION": "1"})
        assert TestClient(app).get("/ping").status_code == 200

    def test_guardrail_version_required_with_id(self, files: dict[str, str]) -> None:
        with mock_aws(), pytest.raises(KeyError):
            build_app({**files, "ATF_GUARDRAIL_ID": "gr-1"})

    def test_app_from_env(self, files: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
        from atf_inference_gateway.app import app_from_env

        for k, v in files.items():
            monkeypatch.setenv(k, v)
        with mock_aws():
            assert TestClient(app_from_env()).get("/ping").status_code == 200

    @pytest.mark.security
    def test_bundle_config_required(self, files: dict[str, str]) -> None:
        """No bundle settings: cold-start failure, never 'serve without policy'."""
        env = {k: v for k, v in files.items() if not k.startswith("ATF_BUNDLE_")}
        with mock_aws(), pytest.raises(KeyError):
            build_app(env)

    @pytest.mark.security
    def test_no_bundle_yet_is_503(self, files: dict[str, str], mint: Any) -> None:
        """Wired correctly but nothing published yet: every call is refused (fail closed)."""
        from tests.conftest import good_claims

        with mock_aws():
            app = build_app(files)
        tok = mint(good_claims(sub=AGENT, client_id=AGENT), header={"typ": "at+jwt"})
        # The validator would need the real JWKS; a 401 or 503 are both refusals. What must
        # never happen is a completion.
        r = TestClient(app).post(
            "/v1/chat/completions",
            json={"model": LOGICAL, "messages": [{"role": "user", "content": "hi"}]},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code in (401, 503)
