"""compose.yaml must parse as strictly as Docker Compose parses it.

PyYAML silently keeps the *last* of two identical mapping keys (including two ``<<`` merge keys);
Compose rejects the file. A duplicate once slipped through a PyYAML-based check while adding
DPoP settings (ADR-0028), so this loader refuses duplicates the way Compose does."""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


class StrictLoader(yaml.SafeLoader):
    pass


def _no_duplicates(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> Any:
    """Compare the *raw* scalar keys (``<<`` included) before PyYAML flattens merges."""
    seen: set[str] = set()
    for key_node, _ in node.value:
        if isinstance(key_node, yaml.ScalarNode):
            if key_node.value in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key_node.value!r}", key_node.start_mark
                )
            seen.add(key_node.value)
    return loader.construct_mapping(node, deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)


def test_compose_has_no_duplicate_keys() -> None:
    yaml.load((ROOT / "compose.yaml").read_text(), Loader=StrictLoader)  # noqa: S506 - SafeLoader subclass


def test_the_check_catches_a_duplicate_merge_key() -> None:
    doc = "a: &a {x: 1}\nb: &b {y: 2}\nsvc:\n  <<: *a\n  z: 3\n  <<: *b\n"
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        yaml.load(doc, Loader=StrictLoader)  # noqa: S506 - SafeLoader subclass


def test_dpop_settings_reach_exactly_the_data_plane_gateways() -> None:
    """ADR-0028 end state in compose: gateways required, beta's runtime bound, nobody else touched.
    (Alpha's compose runtime is the echo agent; the e2e harness acts as alpha, with DPoP.)"""
    d = yaml.load((ROOT / "compose.yaml").read_text(), Loader=StrictLoader)  # noqa: S506
    svc = d["services"]
    with_mode = sorted(n for n, s in svc.items() if "ATF_DPOP_MODE" in (s.get("environment") or {}))
    assert with_mode == ["a2a-gateway", "inference-gateway", "mcp-gateway"]
    for n in with_mode:
        env = svc[n]["environment"]
        assert env["ATF_DPOP_MODE"] == "required"
        assert env["ATF_PUBLIC_URL"] == f"https://{n}:8443"
        assert env["ATF_BUNDLE_ISSUER"] == "atf-bundle-publisher"  # existing merges intact
    assert svc["agent-beta"]["environment"]["ATF_WORKLOAD_DPOP"] == "1"
    assert "ATF_WORKLOAD_TOKEN_ENDPOINT" not in (svc["agent-runtime"].get("environment") or {})
