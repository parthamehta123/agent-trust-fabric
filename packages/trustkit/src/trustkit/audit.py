"""Decision audit events (TM-ING-07, TM-AUD-02).

One event per interceptor decision. The schema is closed: there are no free-form ``extra`` fields,
so nothing unexpected (such as a token) can be attached. Every string field is checked at
construction, and anything shaped like a JWT/JWS is rejected. A bug that tries to log a token
fails loudly in tests instead of leaking quietly in production.

Token identity is recorded as ``sha256(jti)``, which lets an investigator correlate with IdP logs
without the log becoming a token store.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import IO, Any, Final, Protocol

_TOKEN_SHAPED: Final = re.compile(r"eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.")


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"


def jti_hash(jti: str | None) -> str | None:
    return None if jti is None else hashlib.sha256(jti.encode("utf-8")).hexdigest()


@dataclass(frozen=True, kw_only=True)
class AuditEvent:
    event_type: str
    """e.g. ``interceptor.request``, ``interceptor.response``, ``scanner.fail_open``,
    ``config.invalid``."""
    request_id: str
    decision: Decision
    reason: str
    gateway_id: str | None = None
    profile_id: str | None = None
    subject: str | None = None
    client_id: str | None = None
    target_audience: str | None = None
    at_jti_sha256: str | None = None
    idt_jti_sha256: str | None = None
    t2_jti_sha256: str | None = None
    t2_cached: bool | None = None
    scan_verdict: str | None = None
    scan_categories: tuple[str, ...] = ()
    scanner_failed_open: bool = False
    latency_ms: int | None = None

    def __post_init__(self) -> None:
        """Reject token-shaped values in any string field (TM-AUD-02)."""
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            values = value if isinstance(value, tuple) else (value,)
            if any(isinstance(v, str) and _TOKEN_SHAPED.search(v) for v in values):
                raise ValueError(f"audit field {f.name!r} looks like a token")

    def to_json(self) -> str:
        """One line of JSON with stable key order. ``None`` and empty fields are omitted."""
        out: dict[str, Any] = {}
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            if value is None or value == ():
                continue
            out[f.name] = list(value) if isinstance(value, tuple) else value
        return json.dumps(out, sort_keys=True, separators=(",", ":"))


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class JsonLinesSink:
    """Writes one JSON line per event (stdout -> CloudWatch Logs in Lambda)."""

    def __init__(self, stream: IO[str]) -> None:
        self._stream = stream

    def emit(self, event: AuditEvent) -> None:
        """Raises on write failure: the caller decides (the interceptor denies, TM-ING-07)."""
        self._stream.write(event.to_json() + "\n")
        self._stream.flush()
