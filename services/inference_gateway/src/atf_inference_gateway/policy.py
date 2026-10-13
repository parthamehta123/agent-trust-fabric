"""Inference profile: inbound workload-token policy and scanner settings (ADR-0019, ADR-0022)."""

from __future__ import annotations

import json
from typing import Annotated, Any, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from trustkit.profiles import HttpsUrl, ProfileConfigError, ScannerFailureMode

MAX_OUTPUT_TOKENS_CEILING: Final = 32_768

ModelId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:/-]{1,200}$")]
"""A logical model name or LiteLLM model id (``bedrock/anthropic.claude-...``); no wildcards."""


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Inbound(_Strict):
    issuer: HttpsUrl
    audiences: Annotated[
        frozenset[Annotated[str, StringConstraints(min_length=1)]], Field(min_length=1)
    ]
    jwks_uri: HttpsUrl


class InferenceProfile(_Strict):
    """Gateway-level settings only. Which agents may call which models, with which budgets,
    comes from the signed policy bundle (ADR-0022)."""

    inbound: Inbound
    scanner_failure_mode: ScannerFailureMode = ScannerFailureMode.CLOSED
    scanner_timeout_ms: Annotated[int, Field(gt=0, le=2_000)] = 800


def load_inference_profile(raw: str | bytes) -> InferenceProfile:
    """Strict JSON parse; any problem raises ``ProfileConfigError`` (fail closed, log-safe)."""

    def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({k for k, _ in pairs}) != len(pairs):
            raise ValueError("duplicate key")
        return dict(pairs)

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        doc = json.loads(text, object_pairs_hook=no_dupes)
        # Non-objects fail validation. JSON mode: arrays -> frozenset, no coercion.
        return InferenceProfile.model_validate_json(json.dumps(doc))
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError, ValidationError):
        raise ProfileConfigError("inference profile invalid") from None


__all__ = [
    "Inbound",
    "InferenceProfile",
    "ProfileConfigError",
    "load_inference_profile",
]
