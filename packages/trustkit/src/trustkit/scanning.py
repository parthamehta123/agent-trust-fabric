"""Content scanning with fail-mode handling (ADR-0004, ADR-0012 §6).

``ContentScanner`` is the provider-neutral protocol: a local rules engine here, Bedrock Guardrails
or a third-party product as adapters. ``scan_with_policy`` is the **only** way the interceptor
calls a scanner. It applies the size limit, the timeout and the profile's failure mode, so no
caller can forget one of them.

Threat-model refs: TM-TOOL-04, TM-INF-03, RR-2.
"""

from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol

from trustkit.profiles import ScannerFailureMode

MAX_SCAN_BYTES: Final = 1_048_576
MAX_INFLIGHT_SCANS: Final = 8
_DEFAULT_LIMITER: Final = threading.BoundedSemaphore(MAX_INFLIGHT_SCANS)
REDACTION: Final = "[REDACTED]"

_INJECTION = re.compile(
    r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:your\s+)?(?:previous|prior)\s+instructions\b"
    r"|\breveal\s+(?:your\s+)?system\s+prompt\b",
    re.IGNORECASE,
)
_SECRETS = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


class Verdict(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"


class Direction(StrEnum):
    REQUEST = "request"
    RESPONSE = "response"


@dataclass(frozen=True)
class ScanResult:
    verdict: Verdict
    categories: frozenset[str] = frozenset()
    redacted_text: str | None = field(default=None, repr=False)
    """Required when ``verdict is REDACT``; never logged."""


class ScannerUnavailableError(Exception):
    """The scanner could not produce a verdict (error, overload, outage)."""


class ContentScanner(Protocol):
    def scan(self, text: str, *, direction: Direction) -> ScanResult: ...


@dataclass(frozen=True)
class ScanOutcome:
    result: ScanResult
    failed_open: bool
    """True when the scanner failed and the profile's ``open`` mode let the content through.
    The interceptor must emit a ``scanner.fail_open`` audit event (ADR-0004)."""
    failure: str | None = None
    """Set on failure: ``timeout``, ``unavailable``, ``too_large``, ``saturated`` or
    ``invalid_result``."""


class LocalRulesScanner:
    """Deterministic offline scanner. Not a production detector: it exists to exercise verdict
    and failure handling end to end.

    * Prompt-injection markers -> BLOCK, in either direction. On RESPONSE this is tool-output
      injection (TM-TOOL-04).
    * Secrets (AWS access key IDs, PEM private-key headers, JWT-shaped strings) -> BLOCK on
      RESPONSE, BLOCK on REQUEST.
    * PII (email addresses, US-SSN pattern, Luhn-valid card numbers) -> REDACT on RESPONSE,
      ALLOW on REQUEST (users may legitimately send their own PII to their agent).
    """

    def scan(self, text: str, *, direction: Direction) -> ScanResult:
        if _INJECTION.search(text):
            return ScanResult(Verdict.BLOCK, frozenset({"prompt_injection"}))
        if _SECRETS.search(text):
            return ScanResult(Verdict.BLOCK, frozenset({"secret"}))
        if direction is Direction.REQUEST:
            return ScanResult(Verdict.ALLOW)
        redacted = _EMAIL.sub(REDACTION, text)
        redacted = _SSN.sub(REDACTION, redacted)
        redacted = _CARD.sub(lambda m: REDACTION if _luhn(m.group()) else m.group(), redacted)
        if redacted != text:
            return ScanResult(Verdict.REDACT, frozenset({"pii"}), redacted_text=redacted)
        return ScanResult(Verdict.ALLOW)


def _luhn(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def failure_outcome(mode: ScannerFailureMode, failure: str) -> ScanOutcome:
    """The outcome the profile's fail mode prescribes for a scanner failure (ADR-0004)."""
    if mode is ScannerFailureMode.OPEN:
        return ScanOutcome(ScanResult(Verdict.ALLOW), failed_open=True, failure=failure)
    return ScanOutcome(
        ScanResult(Verdict.BLOCK, frozenset({"scanner_failure"})),
        failed_open=False,
        failure=failure,
    )


def scan_with_policy(
    scanner: ContentScanner,
    text: str,
    *,
    direction: Direction,
    failure_mode: ScannerFailureMode,
    timeout_s: float,
    limiter: threading.BoundedSemaphore | None = None,
) -> ScanOutcome:
    """Apply size limit, timeout and failure mode.

    Failure (timeout, ``ScannerUnavailableError``, any exception, oversize input, or a REDACT
    result without ``redacted_text``) gives:

    * ``closed`` -> BLOCK, ``failed_open=False``
    * ``open``   -> ALLOW, ``failed_open=True``

    At most ``MAX_INFLIGHT_SCANS`` scanner threads may exist at once, including ones that timed
    out but are still running. When full, the call fails fast as ``saturated`` instead of
    spawning another thread, so a hung scanner can't grow threads without bound.
    """
    if len(text.encode("utf-8", errors="replace")) > MAX_SCAN_BYTES:
        return failure_outcome(failure_mode, "too_large")
    slots = limiter if limiter is not None else _DEFAULT_LIMITER
    if not slots.acquire(blocking=False):
        return failure_outcome(failure_mode, "saturated")

    def run() -> ScanResult:
        try:
            return scanner.scan(text, direction=direction)
        finally:
            slots.release()  # released when the scan really ends, not when we stop waiting

    # Not a context manager: its __exit__ would wait for a hung scanner and defeat the timeout.
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="scanner")
    try:
        future = pool.submit(run)
        result = future.result(timeout=timeout_s)
    except FutureTimeoutError:
        return failure_outcome(failure_mode, "timeout")
    except Exception:  # noqa: BLE001 - any scanner failure is handled by the profile's fail mode
        return failure_outcome(failure_mode, "unavailable")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    if not isinstance(result, ScanResult) or (
        result.verdict is Verdict.REDACT and result.redacted_text is None
    ):
        return failure_outcome(failure_mode, "invalid_result")
    return ScanOutcome(result, failed_open=False)
