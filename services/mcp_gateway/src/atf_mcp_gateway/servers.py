"""Enrolled MCP servers: record, lifecycle, store (ADR-0017 §2, §5, §8)."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from atf_mcp_gateway.snapshot import ToolSnapshot


class ServerStatus(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    PENDING_REVIEW = "pending_review"
    DISABLED = "disabled"


class Delegation(StrEnum):
    TOKEN = "token"  # noqa: S105 - enum label
    NONE = "none"


@dataclass(frozen=True)
class ServerRecord:
    server_id: str
    url: str
    delegation: Delegation
    audience: str | None
    """Tool audience for delegated tokens (``delegation = token``)."""
    scopes: frozenset[str]
    secret_arn: str | None
    """Secrets Manager ARN of the server's credential (``delegation = none``). Never the value."""
    status: ServerStatus
    enrolled_by: str
    approved_by: str | None = None
    approved_digest: str | None = None
    current: ToolSnapshot | None = None

    @property
    def callable(self) -> bool:
        """Approved, and the current snapshot is exactly what was approved."""
        return (
            self.status is ServerStatus.APPROVED
            and self.current is not None
            and self.approved_digest is not None
            and self.current.digest == self.approved_digest
        )


class SnapshotTooLargeError(Exception):
    """The serialised record exceeds the store's size budget (ADR-0018 §3)."""


class StoreConflictError(Exception):
    """Optimistic-concurrency check failed (the record changed underneath us)."""


class ServerStore(Protocol):
    def get(self, server_id: str) -> ServerRecord | None: ...

    def put(self, record: ServerRecord, *, expected_status: ServerStatus | None) -> None:
        """``expected_status=None`` means "must not exist yet"."""
        ...

    def list(self) -> list[ServerRecord]: ...


class InMemoryServerStore:
    def __init__(self) -> None:
        self._records: dict[str, ServerRecord] = {}
        self._lock = threading.Lock()

    def get(self, server_id: str) -> ServerRecord | None:
        return self._records.get(server_id)

    def put(self, record: ServerRecord, *, expected_status: ServerStatus | None) -> None:
        with self._lock:
            current = self._records.get(record.server_id)
            if expected_status is None and current is not None:
                raise StoreConflictError("record already exists")
            if expected_status is not None and (
                current is None or current.status is not expected_status
            ):
                raise StoreConflictError("record changed underneath us")
            self._records[record.server_id] = record

    def list(self) -> list[ServerRecord]:
        return list(self._records.values())
