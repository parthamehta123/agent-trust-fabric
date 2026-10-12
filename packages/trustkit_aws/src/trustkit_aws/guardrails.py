"""Bedrock Guardrails as a ``ContentScanner`` (ADR-0019 §6).

``ApplyGuardrail`` with ``source`` INPUT (request) / OUTPUT (response):

* ``action == "NONE"``                                   -> ALLOW
* ``GUARDRAIL_INTERVENED`` and only anonymised PII       -> REDACT (``outputs[0].text``)
* ``GUARDRAIL_INTERVENED`` otherwise (blocked topic etc.) -> BLOCK (categories from assessments)
* any client error                                       -> ``ScannerUnavailableError``
  (``scan_with_policy`` then applies the profile's fail mode)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from botocore.exceptions import BotoCoreError, ClientError

from trustkit.scanning import Direction, ScannerUnavailableError, ScanResult, Verdict

_CATEGORY: Final = {
    "topicPolicy": "topic",
    "contentPolicy": "content",
    "wordPolicy": "word",
    "sensitiveInformationPolicy": "pii",
    "contextualGroundingPolicy": "grounding",
}
_NON_POLICY_KEYS: Final = frozenset({"invocationMetrics", "appliedGuardrailDetails"})

if TYPE_CHECKING:
    from mypy_boto3_bedrock_runtime import BedrockRuntimeClient


class BedrockGuardrailScanner:
    def __init__(self, client: BedrockRuntimeClient, *, guardrail_id: str, version: str) -> None:
        self._client, self._id, self._version = client, guardrail_id, version

    def scan(self, text: str, *, direction: Direction) -> ScanResult:
        try:
            resp = self._client.apply_guardrail(
                guardrailIdentifier=self._id,
                guardrailVersion=self._version,
                source="INPUT" if direction is Direction.REQUEST else "OUTPUT",
                content=[{"text": {"text": text}}],
            )
        except (ClientError, BotoCoreError):
            raise ScannerUnavailableError("guardrail unavailable") from None
        if resp.get("action") != "GUARDRAIL_INTERVENED":
            return ScanResult(Verdict.ALLOW)
        assessments: list[Any] = list(resp.get("assessments", []))
        categories = frozenset(
            _CATEGORY[k]
            for a in assessments
            for k, v in a.items()
            if k in _CATEGORY and any(f.get("action") != "NONE" for f in _findings(v))
        )
        if _only_anonymised_pii(assessments):
            redacted = "".join(o.get("text", "") for o in resp.get("outputs", []))
            return ScanResult(Verdict.REDACT, categories, redacted_text=redacted)
        return ScanResult(Verdict.BLOCK, categories or frozenset({"guardrail"}))


def _only_anonymised_pii(assessments: list[Any]) -> bool:
    """True iff every acted-on finding is an ANONYMIZED sensitive-information finding.

    Findings are judged by their own ``action``: ``NONE`` (detect-only) is not an intervention.
    Bookkeeping keys are ignored; any other unknown policy key counts as an intervention
    (fail closed, so a new policy type can't be mistaken for redaction)."""
    seen = False
    for a in assessments:
        for key, value in a.items():
            if key in _NON_POLICY_KEYS or not value:
                continue
            acted = [f for f in _findings(value) if f.get("action") != "NONE"]
            if key not in _CATEGORY and not acted:
                return False  # unknown shape: can't prove it's harmless
            for finding in acted:
                if key != "sensitiveInformationPolicy" or finding.get("action") != "ANONYMIZED":
                    return False
                seen = True
    return seen


def _findings(policy: Any) -> list[dict[str, Any]]:
    """Every finding dict in a policy assessment (topics, filters, piiEntities, regexes, ...)."""
    if not isinstance(policy, dict):
        return []
    return [f for v in policy.values() if isinstance(v, list) for f in v if isinstance(f, dict)]
