"""Tool token authorities (ADR-0025 §4 amendment to ADR-0017/0018).

Gateway configuration maps each permitted delegated-token **audience** to the authorization
server that mints tokens for it. Enrolment refuses any other audience, and each server's exchange
uses its mapped AS, so every tool keeps its own audience (no cross-tool token replay) and admins
can't point delegation at an arbitrary AS.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from trustkit.profiles import HttpsUrl


class AuthorityConfigError(Exception):
    """Authorities file invalid. Log-safe; a cold-start failure."""


class ToolAuthority(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    issuer: HttpsUrl
    token_endpoint: HttpsUrl
    jwks_uri: HttpsUrl


_MAP: TypeAdapter[dict[str, ToolAuthority]] = TypeAdapter(dict[str, ToolAuthority])


def load_authorities(raw: str | bytes) -> Mapping[str, ToolAuthority]:
    def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({k for k, _ in pairs}) != len(pairs):
            raise ValueError("duplicate audience")
        return dict(pairs)

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        doc = json.loads(text, object_pairs_hook=no_dupes)
        out = _MAP.validate_json(json.dumps(doc), strict=True)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError, ValidationError):
        raise AuthorityConfigError("tool authorities invalid") from None
    if not out or any(not aud.strip() for aud in out):
        raise AuthorityConfigError("tool authorities invalid")
    return out
