"""Model routes: logical model name -> LiteLLM model id (+ local-only api_base).

Agents' allowlists name *logical* models; only this file names providers. ``api_base`` lets
config redirect prompts to another host, so it is honoured only with ``ATF_ENV=local`` and must
be https; anywhere else it is a cold-start failure (same pattern as ADR-0018 §1).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Annotated, Any

from pydantic import Field, TypeAdapter, ValidationError

from atf_inference_gateway.policy import InferenceProfile, ModelId, _Strict
from atf_inference_gateway.service import Completion, CompletionFn
from trustkit.profiles import HttpsUrl, ProfileConfigError


class RoutesConfigError(ProfileConfigError):
    """Routes file invalid, or not allowed in this environment. Message is log-safe."""


class ModelRoute(_Strict):
    provider_model: ModelId
    api_base: HttpsUrl | None = None


ProviderFn = Callable[..., Completion]
"""``(provider_model, messages, max_tokens, temperature, *, api_base) -> Completion``."""


_ROUTES: TypeAdapter[dict[str, ModelRoute]] = TypeAdapter(
    Annotated[dict[ModelId, ModelRoute], Field(min_length=1)]
)


def load_routes(raw: str | bytes, *, env: Mapping[str, str]) -> Mapping[str, ModelRoute]:
    def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({k for k, _ in pairs}) != len(pairs):
            raise ValueError("duplicate key")
        return dict(pairs)

    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        doc = json.loads(text, object_pairs_hook=no_dupes)
        routes = _ROUTES.validate_json(json.dumps(doc), strict=True)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError, ValidationError):
        raise RoutesConfigError("model routes invalid") from None
    if env.get("ATF_ENV") != "local" and any(r.api_base is not None for r in routes.values()):
        raise RoutesConfigError("api_base is honoured only with ATF_ENV=local")
    return routes


def check_coverage(profile: InferenceProfile, routes: Mapping[str, ModelRoute]) -> None:
    """Every model in any agent's allowlist must have a route (else ``RoutesConfigError``)."""
    allowlisted = {m for policy in profile.agents.values() for m in policy.models}
    if not allowlisted <= routes.keys():
        raise RoutesConfigError("an allowlisted model has no route")


def routed(routes: Mapping[str, ModelRoute], provider: ProviderFn) -> CompletionFn:
    """Adapt a provider call to the service's logical-model ``CompletionFn``."""

    def complete(
        model: str,
        messages: Sequence[Mapping[str, str]],
        max_tokens: int,
        temperature: float | None,
    ) -> Completion:
        route = routes.get(model)
        if route is None:
            raise LookupError("no route")  # never fall through to a provider with a raw name
        return provider(
            route.provider_model, messages, max_tokens, temperature, api_base=route.api_base
        )

    return complete
