"""Architectural boundaries enforced as tests (architecture §1, design goal 5)."""

from __future__ import annotations

import ast
import pathlib

import pytest

TRUSTKIT_SRC = pathlib.Path(__file__).parents[2] / "packages" / "trustkit" / "src" / "trustkit"
FORBIDDEN_IN_CORE = ("boto3", "botocore", "aioboto3", "mypy_boto3", "okta", "requests", "httpx")


def _imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("module", sorted(TRUSTKIT_SRC.rglob("*.py")), ids=lambda p: p.name)
def test_trustkit_core_is_provider_neutral(module: pathlib.Path) -> None:
    """Cloud/IdP SDKs and HTTP clients belong in adapters; the core stays testable offline."""
    leaked = _imports(module) & set(FORBIDDEN_IN_CORE)
    assert not leaked, f"{module.name} imports {sorted(leaked)}"
