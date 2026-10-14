"""Opt-in probes against a sandbox apply (ADR-0026 §28). They verify A-1b..A-11 and the ED-x rows.

Nothing here runs unless **all** of these are set, so a laptop with credentials never touches AWS
by accident:

* ``ATF_AWS_PROBES=1``
* ``AWS_PROFILE``: an explicit named profile (default credentials are never used)
* ``ATF_AWS_OUTPUTS``: path to ``tofu output -json`` from ``infra/envs/dev``

Every probe is read-only, or attempts a write that must be *denied*.
"""

from __future__ import annotations

import json
import os
import pathlib
from collections.abc import Mapping
from typing import Any

import pytest


def probes_enabled(env: Mapping[str, str]) -> bool:
    """All three, or nothing runs: the flag, a named profile, and the outputs file."""
    return (
        env.get("ATF_AWS_PROBES") == "1"
        and bool(env.get("AWS_PROFILE"))
        and pathlib.Path(env.get("ATF_AWS_OUTPUTS", "/nonexistent")).is_file()
    )


ENABLED = probes_enabled(os.environ)
REASON = "AWS probes are opt-in: ATF_AWS_PROBES=1, AWS_PROFILE and ATF_AWS_OUTPUTS"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    here = pathlib.Path(__file__).parent
    for item in items:
        if here in pathlib.Path(str(item.fspath)).parents:
            item.add_marker(pytest.mark.aws)
            if not ENABLED:
                item.add_marker(pytest.mark.skip(reason=REASON))


@pytest.fixture(scope="session")
def outputs() -> dict[str, Any]:
    raw = json.loads(pathlib.Path(os.environ["ATF_AWS_OUTPUTS"]).read_text())
    return {k: v["value"] for k, v in raw.items()}


@pytest.fixture(scope="session")
def aws(outputs: dict[str, Any]) -> Any:
    import boto3

    return boto3.session.Session(profile_name=os.environ["AWS_PROFILE"])
