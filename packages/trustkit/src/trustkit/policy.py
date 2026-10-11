"""Static deployment policy checks shared by the emulator and (Phase 6) Terraform tests.

ADR-0014 §5, ADR-0012 §4, TM-RT-02, TM-ING-06.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

FORBIDDEN_PROPAGATED_HEADERS: Final = frozenset(
    {"authorization", "proxy-authorization", "x-subject-token", "cookie", "x-api-key"}
)
"""Credential-bearing headers that must never be on a target's allowedRequestHeaders."""

RESERVED_HEADERS: Final = frozenset({"x-atf-request-id", "x-atf-decision", "x-atf-scan-verdict"})
"""Must all be allowlisted on every interceptor-fronted target, so overwrites reach the target."""


class AllowlistViolationError(ValueError):
    """Message lists header *names* only."""


def check_target_allowlist(allowed_request_headers: Iterable[str]) -> None:
    """Raise unless the allowlist excludes credentials and includes every reserved header.

    Comparison is case-insensitive. Duplicates (case-insensitive) are themselves a violation.
    """
    lowered = [h.lower() for h in allowed_request_headers]
    if len(set(lowered)) != len(lowered):
        raise AllowlistViolationError("duplicate header names (case-insensitive)")
    credentials = sorted(set(lowered) & FORBIDDEN_PROPAGATED_HEADERS)
    if credentials:
        raise AllowlistViolationError(f"credential headers not allowed: {', '.join(credentials)}")
    missing = sorted(RESERVED_HEADERS - set(lowered))
    if missing:
        raise AllowlistViolationError(f"reserved headers missing: {', '.join(missing)}")
