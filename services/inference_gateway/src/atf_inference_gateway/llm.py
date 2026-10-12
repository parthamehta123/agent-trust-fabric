"""LiteLLM adapter with no hidden egress (ADR-0019 §2).

Import this module, not ``litellm`` directly: it sets ``LITELLM_LOCAL_MODEL_COST_MAP`` *before*
LiteLLM is imported and disables telemetry, so nothing phones home at import or call time.
"""

from __future__ import annotations

import os

# Must be set before LiteLLM is imported anywhere in the process (ADR-0019 §2).
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
os.environ.setdefault("LITELLM_TELEMETRY", "False")

from collections.abc import Mapping, Sequence
from typing import Any

import litellm

from atf_inference_gateway.service import Completion

litellm.telemetry = False
litellm.success_callback = []
litellm.failure_callback = []
litellm.callbacks = []


def litellm_complete(
    model: str,
    messages: Sequence[Mapping[str, str]],
    max_tokens: int,
    temperature: float | None,
    *,
    mock_response: str | None = None,
) -> Completion:
    """Provider call via LiteLLM. ``mock_response`` is for tests/local stack only."""
    kwargs: dict[str, Any] = {"model": model, "messages": list(messages), "max_tokens": max_tokens}
    if temperature is not None:
        kwargs["temperature"] = temperature
    if mock_response is not None:
        kwargs["mock_response"] = mock_response
    response = litellm.completion(**kwargs)
    text = response.choices[0].message.content or ""
    usage = getattr(response, "usage", None)
    return Completion(
        text=str(text),
        prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
        completion_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
    )
