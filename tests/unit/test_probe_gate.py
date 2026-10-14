"""The AWS probes never run by accident (ADR-0026 §28)."""

from __future__ import annotations

import pathlib

import pytest

from tests.aws_probes.conftest import probes_enabled


@pytest.mark.security
@pytest.mark.parametrize("drop", ["ATF_AWS_PROBES", "AWS_PROFILE", "ATF_AWS_OUTPUTS"])
def test_every_setting_is_required(tmp_path: pathlib.Path, drop: str) -> None:
    (tmp_path / "out.json").write_text("{}")
    env = {
        "ATF_AWS_PROBES": "1",
        "AWS_PROFILE": "sandbox",
        "ATF_AWS_OUTPUTS": str(tmp_path / "out.json"),
    }
    assert probes_enabled(env)
    assert not probes_enabled({k: v for k, v in env.items() if k != drop})


@pytest.mark.security
def test_flag_must_be_exactly_one(tmp_path: pathlib.Path) -> None:
    (tmp_path / "out.json").write_text("{}")
    env = {
        "ATF_AWS_PROBES": "true",
        "AWS_PROFILE": "x",
        "ATF_AWS_OUTPUTS": str(tmp_path / "out.json"),
    }
    assert not probes_enabled(env)


@pytest.mark.security
def test_missing_outputs_file_disables(tmp_path: pathlib.Path) -> None:
    env = {
        "ATF_AWS_PROBES": "1",
        "AWS_PROFILE": "x",
        "ATF_AWS_OUTPUTS": str(tmp_path / "nope.json"),
    }
    assert not probes_enabled(env)
