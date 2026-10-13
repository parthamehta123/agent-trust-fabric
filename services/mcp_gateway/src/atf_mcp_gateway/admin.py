"""Server enrolment and approval (ADR-0017 §2-§4).

Every operation needs an ``AdminPrincipal`` obtained from ``authorize_admin``: a valid IdP token
carrying the ``mcp.admin`` scope. Approval enforces approver ≠ enroller (two-person rule) and a
clean description scan of a fresh snapshot.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from atf_mcp_gateway.servers import (
    Delegation,
    ServerRecord,
    ServerStatus,
    ServerStore,
    SnapshotTooLargeError,
    StoreConflictError,
)
from atf_mcp_gateway.snapshot import SnapshotError, take_snapshot
from trustkit.jwt import TokenValidationError, TokenValidator
from trustkit.profiles import ScannerFailureMode
from trustkit.scanning import ContentScanner, Direction, Verdict, scan_with_policy
from trustkit_http.ssrf import Network, Resolver, SsrfError, default_resolver, vet_url

ADMIN_SCOPE: Final = "mcp.admin"
_BEARER: Final = re.compile(r"^[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9._~+/=-]+)$")
_SERVER_ID: Final = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_SCOPE: Final = re.compile(r"^[A-Za-z0-9:._/-]{1,128}$")
_SECRET_ARN: Final = re.compile(
    r"^arn:aws:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+$"
)
_AUDIENCE: Final = re.compile(r"^\S{1,512}$")


class AdminFailure(StrEnum):
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    INVALID = "invalid"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    SAME_PERSON = "same_person"
    SNAPSHOT_REJECTED = "snapshot_rejected"


class AdminError(Exception):
    def __init__(self, failure: AdminFailure, detail: str = "") -> None:
        self.failure, self.detail = failure, detail
        super().__init__(f"{failure.value}: {detail}" if detail else failure.value)


@dataclass(frozen=True)
class AdminPrincipal:
    subject: str


def authorize_admin(authorization_header: str | None, validator: TokenValidator) -> AdminPrincipal:
    """Bearer token valid under ``validator`` and carrying ``mcp.admin`` in ``scope``."""
    m = _BEARER.fullmatch(authorization_header or "")
    if m is None:
        raise AdminError(AdminFailure.UNAUTHORIZED)
    try:
        token = validator.validate(m.group(1))
    except TokenValidationError:
        raise AdminError(AdminFailure.UNAUTHORIZED) from None
    scope = token.claims.get("scope")
    if not isinstance(scope, str) or ADMIN_SCOPE not in scope.split():
        raise AdminError(AdminFailure.FORBIDDEN)
    return AdminPrincipal(token.subject)


FetchTools = Callable[[ServerRecord], Mapping[str, Any]]
"""Call the server's ``tools/list`` (SSRF-pinned) and return the JSON-RPC ``result``."""


class AdminService:
    def __init__(
        self,
        *,
        store: ServerStore,
        fetch_tools: FetchTools,
        scanner: ContentScanner,
        audiences: frozenset[str],
        resolver: Resolver = default_resolver,
        allow: frozenset[Network] = frozenset(),
    ) -> None:
        """``audiences``: delegated-token audiences with a configured authority. Token-mode
        enrolment for any other audience is refused (no arbitrary AS, no cross-tool replay)."""
        self._allow, self._audiences = allow, audiences
        self._store, self._fetch, self._scanner, self._resolver = (
            store,
            fetch_tools,
            scanner,
            resolver,
        )

    def enroll(
        self,
        principal: AdminPrincipal,
        *,
        server_id: str,
        url: str,
        delegation: Delegation,
        audience: str | None = None,
        scopes: frozenset[str] = frozenset(),
        secret_arn: str | None = None,
    ) -> ServerRecord:
        """Validate fields, vet the URL (SSRF), store as DRAFT."""
        if not _SERVER_ID.fullmatch(server_id):
            raise AdminError(AdminFailure.INVALID, "server_id must be a slug")
        if not scopes or not all(_SCOPE.fullmatch(s) for s in scopes):
            raise AdminError(AdminFailure.INVALID, "scopes must be explicit, without wildcards")
        if delegation is Delegation.TOKEN:
            if (
                audience is None
                or not _AUDIENCE.fullmatch(audience)
                or audience not in self._audiences
                or secret_arn is not None
            ):
                raise AdminError(
                    AdminFailure.INVALID, "token delegation needs an audience, no secret"
                )
        elif audience is not None or secret_arn is None or not _SECRET_ARN.fullmatch(secret_arn):
            raise AdminError(AdminFailure.INVALID, "delegation none needs a Secrets Manager ARN")
        try:
            vet_url(url, resolver=self._resolver, allow=self._allow)
        except SsrfError:
            raise AdminError(AdminFailure.INVALID, "url rejected by egress policy") from None
        record = ServerRecord(
            server_id=server_id,
            url=url,
            delegation=delegation,
            audience=audience,
            scopes=scopes,
            secret_arn=secret_arn,
            status=ServerStatus.DRAFT,
            enrolled_by=principal.subject,
        )
        self._put(record, expected=None)
        return record

    def refresh(self, principal: AdminPrincipal, server_id: str) -> ServerRecord:
        """Fetch + snapshot. An APPROVED server whose digest drifted becomes PENDING_REVIEW."""
        record = self._get(server_id)
        if record.status is ServerStatus.DISABLED:
            raise AdminError(AdminFailure.CONFLICT, "server is disabled")
        try:
            snap = take_snapshot(self._fetch(record))
        except SnapshotError:
            raise AdminError(AdminFailure.INVALID, "tools/list result malformed") from None
        except Exception:  # noqa: BLE001 - discovery failure of any kind
            raise AdminError(AdminFailure.INVALID, "discovery failed") from None
        status = record.status
        if status is ServerStatus.APPROVED and snap.digest != record.approved_digest:
            status = ServerStatus.PENDING_REVIEW  # TM-TOOL-03: drift quarantines
        updated = dataclasses.replace(record, current=snap, status=status)
        self._put(updated, expected=record.status)
        return updated

    def approve(self, principal: AdminPrincipal, server_id: str) -> ServerRecord:
        """DRAFT/PENDING_REVIEW -> APPROVED, pinning the current digest. Requires a snapshot,
        a different subject than the enroller, and clean tool descriptions."""
        record = self._get(server_id)
        if record.status not in (ServerStatus.DRAFT, ServerStatus.PENDING_REVIEW):
            raise AdminError(AdminFailure.CONFLICT, "server is not awaiting approval")
        if record.current is None:
            raise AdminError(AdminFailure.INVALID, "refresh before approving")
        if principal.subject == record.enrolled_by:
            raise AdminError(AdminFailure.SAME_PERSON)
        for tool in record.current.tools:
            text = f"{tool['name']}\n{tool['description']}\n{json.dumps(tool['inputSchema'])}"
            outcome = scan_with_policy(
                self._scanner,
                text,
                direction=Direction.RESPONSE,
                failure_mode=ScannerFailureMode.CLOSED,
                timeout_s=2.0,
            )
            if outcome.result.verdict is not Verdict.ALLOW:
                raise AdminError(AdminFailure.SNAPSHOT_REJECTED)
        updated = dataclasses.replace(
            record,
            status=ServerStatus.APPROVED,
            approved_by=principal.subject,
            approved_digest=record.current.digest,
        )
        self._put(updated, expected=record.status)
        return updated

    def list_servers(self, principal: AdminPrincipal) -> list[ServerRecord]:
        return sorted(self._store.list(), key=lambda r: r.server_id)

    def disable(self, principal: AdminPrincipal, server_id: str) -> ServerRecord:
        record = self._get(server_id)
        updated = dataclasses.replace(record, status=ServerStatus.DISABLED)
        self._put(updated, expected=record.status)
        return updated

    def _get(self, server_id: str) -> ServerRecord:
        record = self._store.get(server_id)
        if record is None:
            raise AdminError(AdminFailure.NOT_FOUND)
        return record

    def _put(self, record: ServerRecord, *, expected: ServerStatus | None) -> None:
        try:
            self._store.put(record, expected_status=expected)
        except StoreConflictError:
            raise AdminError(AdminFailure.CONFLICT) from None
        except SnapshotTooLargeError:
            raise AdminError(AdminFailure.INVALID, "tool snapshot too large") from None
