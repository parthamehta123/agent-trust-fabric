"""File-shaped config from a path or an inline env value (ADR-0026 §13).

Locally, documents are mounted read-only and named by ``<BASE>_PATH``. In AWS the deployment
renders them inline (``<BASE>_JSON``, or another suffix for non-JSON text), so each change is a
new task-definition revision. Exactly one source must be set; anything else is a cold-start
failure, never a silent default.
"""

from __future__ import annotations

import pathlib
from collections.abc import Mapping

__all__ = ["ConfigSourceError", "ca_bundle", "load_document"]


class ConfigSourceError(ValueError):
    """Both sources set, or the inline value is empty."""


def load_document(env: Mapping[str, str], base: str, *, inline_suffix: str = "_JSON") -> bytes:
    """The raw document for ``base``, from ``<base><inline_suffix>`` or ``<base>_PATH``.

    Neither set raises ``KeyError`` (as a missing required variable always has). Callers parse
    and validate the bytes themselves."""
    inline_key, path_key = f"{base}{inline_suffix}", f"{base}_PATH"
    has_inline, has_path = inline_key in env, path_key in env
    if has_inline and has_path:
        raise ConfigSourceError(f"set {inline_key} or {path_key}, not both")
    if has_inline:
        value = env[inline_key]
        if not value.strip():
            raise ConfigSourceError(f"{inline_key} is empty")
        return value.encode()
    if has_path:
        return pathlib.Path(env[path_key]).read_bytes()
    raise KeyError(f"{inline_key} or {path_key}")


def ca_bundle(env: Mapping[str, str]) -> str | None:
    """Outbound TLS trust. The local stack must pin its ephemeral CA (``ATF_CA_BUNDLE``), so a
    missing value never silently widens trust to the system store there. Elsewhere it's optional:
    unset means the platform's public trust store."""
    if env.get("ATF_ENV") == "local":
        return env["ATF_CA_BUNDLE"]
    return env.get("ATF_CA_BUNDLE") or None
