"""File-shaped config from a path or an inline value (ADR-0026 §13)."""

from __future__ import annotations

import pathlib

import pytest

from trustkit.config import ConfigSourceError, ca_bundle, load_document


class TestLoadDocument:
    def test_path(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "doc.json").write_bytes(b'{"a": 1}')
        assert load_document({"ATF_X_PATH": str(tmp_path / "doc.json")}, "ATF_X") == b'{"a": 1}'

    def test_inline(self) -> None:
        assert load_document({"ATF_X_JSON": '{"a": 1}'}, "ATF_X") == b'{"a": 1}'

    def test_inline_suffix(self) -> None:
        env = {"ATF_G_CEDAR": "forbid (principal, action, resource);"}
        assert load_document(env, "ATF_G", inline_suffix="_CEDAR").startswith(b"forbid")

    @pytest.mark.security
    def test_both_refused(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "doc.json").write_text("{}")
        env = {"ATF_X_PATH": str(tmp_path / "doc.json"), "ATF_X_JSON": "{}"}
        with pytest.raises(ConfigSourceError, match="not both"):
            load_document(env, "ATF_X")

    @pytest.mark.security
    @pytest.mark.parametrize("value", ["", "   ", "\n"])
    def test_empty_inline_refused(self, value: str) -> None:
        with pytest.raises(ConfigSourceError, match="empty"):
            load_document({"ATF_X_JSON": value}, "ATF_X")

    def test_neither_is_key_error(self) -> None:
        with pytest.raises(KeyError, match="ATF_X_JSON or ATF_X_PATH"):
            load_document({}, "ATF_X")

    def test_other_suffix_ignored(self) -> None:
        """Only the named suffix counts: ``_JSON`` does not satisfy a ``_CEDAR`` document."""
        with pytest.raises(KeyError):
            load_document({"ATF_G_JSON": "{}"}, "ATF_G", inline_suffix="_CEDAR")


class TestCaBundle:
    @pytest.mark.security
    def test_local_requires_pinned_ca(self) -> None:
        with pytest.raises(KeyError):
            ca_bundle({"ATF_ENV": "local"})

    def test_local_pinned(self) -> None:
        assert ca_bundle({"ATF_ENV": "local", "ATF_CA_BUNDLE": "/ca.pem"}) == "/ca.pem"

    @pytest.mark.parametrize("env", [{"ATF_ENV": "dev"}, {"ATF_ENV": "dev", "ATF_CA_BUNDLE": ""}])
    def test_aws_public_trust(self, env: dict[str, str]) -> None:
        assert ca_bundle(env) is None

    def test_aws_may_still_pin(self) -> None:
        assert ca_bundle({"ATF_ENV": "dev", "ATF_CA_BUNDLE": "/corp.pem"}) == "/corp.pem"
