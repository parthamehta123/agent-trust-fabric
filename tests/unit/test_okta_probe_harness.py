"""The Okta preflight harness, without Okta: config rules, the PKCE listener, the report's refusal
of token material, key generation, and the opt-in gate. These run in CI; the probes don't."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import pathlib
import stat
import threading
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import ValidationError

from tests.okta_probes.config import OktaPreflightConfig, example
from tests.okta_probes.conftest import probes_enabled
from tests.okta_probes.login import LoginError, authorize_url, pkce_pair, wait_for_code
from tests.okta_probes.report import Report, safe

ORG = "https://integrator-1234567.okta.com"


def config(**over: Any) -> OktaPreflightConfig:
    doc = example()
    doc.update(over)
    return OktaPreflightConfig.model_validate_json(json.dumps(doc))


class TestConfig:
    def test_example_is_valid(self) -> None:
        cfg = config()
        assert cfg.authorization_servers.agent.jwks_uri.startswith(f"{ORG}/oauth2/aus")
        assert cfg.redirect_uri == "http://127.0.0.1:8765/callback"

    @pytest.mark.security
    @pytest.mark.parametrize(
        "issuer",
        [
            "https://attacker.example/oauth2/aus1",  # another origin
            f"{ORG}/oauth2/../evil",  # escapes the AS path
            "http://integrator-1234567.okta.com/oauth2/aus1",  # not https
            ORG,  # the org AS isn't a custom authorization server
        ],
    )
    def test_issuers_must_be_custom_servers_of_the_org(self, issuer: str) -> None:
        doc = example()
        servers: Any = doc["authorization_servers"]
        servers["tool"]["issuer"] = issuer
        with pytest.raises(ValidationError):
            OktaPreflightConfig.model_validate_json(json.dumps(doc))

    def test_unknown_keys_refused(self) -> None:
        with pytest.raises(ValidationError):
            config(client_secret="x")  # secrets have no place in this file

    @pytest.mark.parametrize("port", [0, 80, 70000])
    def test_redirect_port_range(self, port: int) -> None:
        with pytest.raises(ValidationError):
            config(redirect_port=port)


class TestGate:
    def test_needs_flag_and_config_file(self, tmp_path: pathlib.Path) -> None:
        f = tmp_path / "c.json"
        f.write_text("{}")
        assert probes_enabled({"ATF_OKTA_PROBES": "1", "ATF_OKTA_CONFIG": str(f)})
        assert not probes_enabled({"ATF_OKTA_PROBES": "1"})
        assert not probes_enabled({"ATF_OKTA_CONFIG": str(f)})
        assert not probes_enabled({"ATF_OKTA_PROBES": "true", "ATF_OKTA_CONFIG": str(f)})
        assert not probes_enabled({"ATF_OKTA_PROBES": "1", "ATF_OKTA_CONFIG": str(tmp_path / "x")})


class TestPkce:
    def test_s256_challenge(self) -> None:
        verifier, challenge = pkce_pair()
        assert 43 <= len(verifier) <= 128
        digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        assert challenge == digest.rstrip(b"=").decode()
        assert pkce_pair()[0] != verifier

    def test_authorize_url(self) -> None:
        url = authorize_url(
            config(), state="s", nonce="n", challenge="c", redirect_uri=config().redirect_uri
        )
        parts = urlsplit(url)
        q = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert f"{parts.scheme}://{parts.netloc}" == ORG
        assert parts.path == "/oauth2/v1/authorize"
        assert q["code_challenge_method"] == "S256"
        assert q["redirect_uri"].startswith("http://127.0.0.1:")
        assert (q["state"], q["nonce"], q["response_type"]) == ("s", "n", "code")
        assert "client_secret" not in q


def hit(path: str) -> dict[str, Any]:
    """Run ``wait_for_code`` on an ephemeral port and send it one request."""
    result: dict[str, Any] = {}

    def listening(port: int) -> None:
        def send() -> None:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
                    result["status"] = r.status
            except urllib.error.HTTPError as e:
                result["status"] = e.code

        threading.Thread(target=send, daemon=True).start()

    try:
        result["code"] = wait_for_code(port=0, state="good", on_listening=listening, timeout_s=5)
    except LoginError as e:
        result["error"] = str(e)
    return result


@pytest.mark.security
class TestCallbackListener:
    def test_returns_the_code(self) -> None:
        r = hit("/callback?code=abc&state=good")
        assert r["code"] == "abc"

    @pytest.mark.parametrize(
        ("path", "error"),
        [
            ("/callback?code=abc&state=bad", "state_mismatch"),
            ("/callback?code=abc", "state_mismatch"),
            ("/callback?error=access_denied&state=good", "access_denied"),
            ("/callback?state=good", "no_code"),
            ("/other?code=abc&state=good", "unexpected_path"),
        ],
    )
    def test_refuses_anything_else(self, path: str, error: str) -> None:
        r = hit(path)
        assert "code" not in r
        assert r["error"] == error

    def test_times_out(self) -> None:
        with pytest.raises(LoginError, match="timed_out"):
            wait_for_code(port=0, state="s", on_listening=lambda _: None, timeout_s=0.6)

    def test_binds_loopback_only(self) -> None:
        seen: list[int] = []
        with pytest.raises(LoginError):
            wait_for_code(port=0, state="s", on_listening=seen.append, timeout_s=0.6)
        with pytest.raises(OSError):  # noqa: PT011 - any connection failure proves it's closed
            urllib.request.urlopen(f"http://127.0.0.1:{seen[0]}/callback", timeout=1)


@pytest.mark.security
class TestReport:
    @pytest.mark.parametrize(
        "value",
        [
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig",
            "prefix eyJhbGciOiJFUzI1NiJ9.eyJhIjoiYiJ9 suffix",
            "-----BEGIN PRIVATE KEY-----",
            "a" * 130,
            "x" * 201,
        ],
    )
    def test_refuses_token_material(self, value: str) -> None:
        with pytest.raises(ValueError, match="token- or key-shaped"):
            safe(value)

    def test_shapes_and_codes_are_fine(self) -> None:
        assert safe(["scp:list", "cid:str"]) == "scp:list, cid:str"
        assert safe(True) == "True"
        assert safe("use_dpop_nonce") == "use_dpop_nonce"

    def test_markdown(self, tmp_path: pathlib.Path) -> None:
        r = Report()
        r.add("A-16", "test_delegation_exchange_emits_act", "**fail**: invalid_request", {})
        r.add("A-15", "test_t2_names_the_user", "pass", {"has_uid": "True"})
        out = tmp_path / "r.md"
        r.write(out, today=dt.date(2026, 10, 19))
        text = out.read_text()
        assert text.startswith("# Okta preflight (2026-10-19)")
        assert text.index("A-15") < text.index("A-16")
        assert "| A-15 | `test_t2_names_the_user` | pass | has_uid: True |" in text


class TestKeyScript:
    def run(self, *args: str) -> tuple[int, str]:
        import contextlib
        import io

        from scripts.okta_probe_keys import main

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            code = main(list(args))
        return code, buf.getvalue()

    def test_writes_private_keys_0600_and_prints_public_jwks(self, tmp_path: pathlib.Path) -> None:
        keys = tmp_path / "keys"
        code, out = self.run("--dir", str(keys))
        assert code == 0
        assert stat.S_IMODE(keys.stat().st_mode) == 0o700
        for client in ("chat", "agent", "tool-gateway"):
            assert stat.S_IMODE((keys / f"{client}.pem").stat().st_mode) == 0o600
        assert "PRIVATE" not in out
        assert '"d"' not in out
        assert out.count('"kty": "EC"') == 3

    @pytest.mark.security
    def test_never_overwrites_without_rotate(self, tmp_path: pathlib.Path) -> None:
        keys = tmp_path / "keys"
        self.run("--dir", str(keys))
        before = (keys / "chat.pem").read_bytes()
        assert self.run("--dir", str(keys))[0] == 1
        assert (keys / "chat.pem").read_bytes() == before
        assert self.run("--dir", str(keys), "--rotate")[0] == 0
        assert (keys / "chat.pem").read_bytes() != before
