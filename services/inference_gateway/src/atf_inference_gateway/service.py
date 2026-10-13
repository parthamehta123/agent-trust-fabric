"""Chat completions with policy, budget and scanning around the model call (ADR-0019)."""

from __future__ import annotations

import contextlib
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from atf_inference_gateway.budget import BudgetStore, BudgetUnavailableError, estimate_tokens
from atf_inference_gateway.policy import InferenceProfile
from trustkit.profiles import ScannerFailureMode
from trustkit.scanning import ContentScanner, Direction, Verdict, scan_with_policy
from trustkit_policy.bundle import LoadedBundle
from trustkit_policy.grants import ModelGrant
from trustkit_policy.pdp import DecisionRequest, Resource
from trustkit_policy.runtime import effective_fail_mode
from trustkit_policy.schema import Action, ResourceType

_ALLOWED_KEYS: Final = frozenset({"model", "messages", "max_tokens", "temperature", "stream"})
_ROLES: Final = frozenset({"system", "user", "assistant"})


@dataclass(frozen=True)
class Completion:
    text: str
    prompt_tokens: int
    completion_tokens: int


CompletionFn = Callable[[str, Sequence[Mapping[str, str]], int, float | None], Completion]
"""(model, messages, max_tokens, temperature) -> Completion. Raises on provider failure."""


class ChatError(Exception):
    """Log-safe. ``status`` is the HTTP status; ``code`` a stable machine-readable reason."""

    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code
        super().__init__(code)


class InferenceService:
    """``chat`` order: shape -> bundle grant + Cedar ``call_model`` -> clamp -> prompt scan ->
    reserve (agent, model) budget -> call -> (release on failure) -> settle -> completion scan
    -> respond."""

    def __init__(
        self,
        *,
        profile: InferenceProfile,
        budget: BudgetStore,
        scanner: ContentScanner,
        complete: CompletionFn,
        today: Callable[[], str],
        policy: Callable[[], LoadedBundle | None],
        routable: frozenset[str],
        now: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        self._profile, self._budget, self._scanner = profile, budget, scanner
        self._complete, self._today = complete, today
        self._policy, self._routable, self._now = policy, routable, now

    def _authorize(self, agent: str, model: str) -> tuple[ModelGrant, ScannerFailureMode]:
        """Bundle + Cedar ``call_model`` (ADR-0022). Raises ``ChatError``:
        503 ``policy_unavailable``, 403 ``agent_not_allowed`` / ``model_not_allowed``.
        Returns the model grant (budget, max tokens) and the effective scanner fail mode."""
        loaded = self._policy()
        if loaded is None:
            raise ChatError(503, "policy_unavailable")  # no fresh bundle: fail closed
        grant = loaded.grant(agent, self._now())
        if grant is None:
            raise ChatError(403, "agent_not_allowed")
        model_grant = grant.models.get(model)
        if model_grant is None or model not in self._routable:
            raise ChatError(403, "model_not_allowed")
        decision = loaded.pdp.decide(
            DecisionRequest(
                agent_id=agent,
                action=Action.CALL_MODEL,
                resource=Resource(ResourceType.MODEL, model),
            )
        )
        if not decision.allowed:
            raise ChatError(403, "model_not_allowed")
        return model_grant, effective_fail_mode(
            self._profile.scanner_failure_mode, grant.scanner_failure_mode
        )

    def chat(self, agent: str, request: Mapping[str, Any]) -> dict[str, Any]:
        """OpenAI-compatible response dict, or raises ``ChatError``."""
        model, messages, max_tokens, temperature = _parse(request)
        grant, fail_mode = self._authorize(agent, model)  # before any provider call (TM-INF-01)
        clamped = min(max_tokens or grant.max_output_tokens, grant.max_output_tokens)

        prompt = "\n".join(m["content"] for m in messages)
        if self._scan(prompt, Direction.REQUEST, fail_mode)[0] is not Verdict.ALLOW:
            raise ChatError(403, "prompt_blocked")  # before any spend (TM-INF-03)

        # Budgets are granted per model (ADR-0021 §3), so the counter is per agent and model.
        key, day, estimate = f"{agent}#{model}", self._today(), estimate_tokens(messages, clamped)
        try:
            reserved = self._budget.reserve(key, day, estimate, grant.daily_token_budget)
        except BudgetUnavailableError:
            raise ChatError(503, "budget_unavailable") from None  # fail closed
        if not reserved:
            raise ChatError(429, "budget_exhausted")

        try:
            completion = self._complete(model, messages, clamped, temperature)
        except Exception:  # noqa: BLE001 - provider failures never leak details
            with contextlib.suppress(BudgetUnavailableError):
                self._budget.adjust(key, day, -estimate)
            raise ChatError(502, "provider_error") from None
        actual = completion.prompt_tokens + completion.completion_tokens
        with contextlib.suppress(BudgetUnavailableError):
            self._budget.adjust(key, day, actual - estimate)

        verdict, redacted = self._scan(completion.text, Direction.RESPONSE, fail_mode)
        if verdict is Verdict.BLOCK:
            raise ChatError(502, "completion_blocked")
        text = redacted if verdict is Verdict.REDACT and redacted is not None else completion.text
        return {
            "id": f"chatcmpl-{uuid.uuid4().hex}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": completion.prompt_tokens,
                "completion_tokens": completion.completion_tokens,
                "total_tokens": actual,
            },
        }

    def _scan(
        self, text: str, direction: Direction, failure_mode: ScannerFailureMode
    ) -> tuple[Verdict, str | None]:
        outcome = scan_with_policy(
            self._scanner,
            text,
            direction=direction,
            failure_mode=failure_mode,
            timeout_s=self._profile.scanner_timeout_ms / 1000,
        )
        return outcome.result.verdict, outcome.result.redacted_text


def _parse(request: Any) -> tuple[str, list[dict[str, str]], int | None, float | None]:
    """Shape validation only. Unknown keys are refused (no provider pass-through parameters)."""
    if not isinstance(request, Mapping) or not set(request) <= _ALLOWED_KEYS:
        raise ChatError(400, "invalid_request")
    if request.get("stream") not in (None, False):
        raise ChatError(400, "invalid_request")
    model, messages = request.get("model"), request.get("messages")
    if not isinstance(model, str) or not isinstance(messages, list) or not messages:
        raise ChatError(400, "invalid_request")
    parsed: list[dict[str, str]] = []
    for m in messages:
        if (
            not isinstance(m, Mapping)
            or m.get("role") not in _ROLES
            or not isinstance(m.get("content"), str)
            or set(m) - {"role", "content"}
        ):
            raise ChatError(400, "invalid_request")
        parsed.append({"role": str(m["role"]), "content": str(m["content"])})
    max_tokens, temperature = request.get("max_tokens"), request.get("temperature")
    if max_tokens is not None and (
        not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0
    ):
        raise ChatError(400, "invalid_request")
    if temperature is not None and (
        not isinstance(temperature, (int, float))
        or isinstance(temperature, bool)
        or not 0 <= temperature <= 2
    ):
        raise ChatError(400, "invalid_request")
    return model, parsed, max_tokens, None if temperature is None else float(temperature)
