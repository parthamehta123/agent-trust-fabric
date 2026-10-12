"""Canonical tool snapshots for pinning (ADR-0017 §3, TM-TOOL-03)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

TOOL_NAME_PATTERN: Final = r"^[A-Za-z0-9_-]{1,64}$"
"""Tool names may not contain ``__`` (reserved as the namespace separator)."""


_NAME: Final = re.compile(TOOL_NAME_PATTERN)


class SnapshotError(ValueError):
    """Malformed tools/list result. Log-safe."""


@dataclass(frozen=True)
class ToolSnapshot:
    tools: tuple[Mapping[str, Any], ...]
    """Each: {"name", "description", "inputSchema"}, sorted by name."""
    digest: str
    """SHA-256 over the canonical JSON of ``tools``."""

    def names(self) -> frozenset[str]:
        return frozenset(str(t["name"]) for t in self.tools)


def take_snapshot(tools_list_result: Mapping[str, Any]) -> ToolSnapshot:
    """Validate and canonicalise an MCP ``tools/list`` result.

    Rejects: missing/non-list ``tools``; non-object entries; bad or duplicate names; names with
    ``__``; non-string descriptions; non-object ``inputSchema``. Unknown per-tool fields are
    dropped *before* hashing, so annotation noise can't be used to toggle the digest, while every
    field that changes what the model sees (name, description, schema) is covered.
    """
    tools = tools_list_result.get("tools") if isinstance(tools_list_result, Mapping) else None
    if not isinstance(tools, list):
        raise SnapshotError("tools/list result has no tools array")
    canonical: list[dict[str, Any]] = []
    seen: set[str] = set()
    for tool in tools:
        if not isinstance(tool, Mapping):
            raise SnapshotError("tool entry is not an object")
        name, description, schema = (
            tool.get("name"),
            tool.get("description", ""),
            tool.get("inputSchema"),
        )
        if not isinstance(name, str) or not _NAME.fullmatch(name) or "__" in name:
            raise SnapshotError("invalid tool name")
        if name in seen:
            raise SnapshotError("duplicate tool name")
        if not isinstance(description, str) or not isinstance(schema, Mapping):
            raise SnapshotError("invalid tool description or inputSchema")
        seen.add(name)
        canonical.append({"name": name, "description": description, "inputSchema": dict(schema)})
    canonical.sort(key=lambda t: t["name"])
    try:
        blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise SnapshotError("tool schema is not canonical JSON") from None
    return ToolSnapshot(tuple(canonical), hashlib.sha256(blob.encode()).hexdigest())
