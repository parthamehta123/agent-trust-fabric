"""Retrieval-time authorization (ADR-0025 §2-§3, §6)."""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from atf_knowledge_server.store import Chunk, VectorStore
from trustkit.audit import AuditEvent, AuditSink, Decision
from trustkit.profiles import ScannerFailureMode
from trustkit.scanning import ContentScanner, Direction, Verdict, scan_with_policy
from trustkit_policy.bundle import LoadedBundle
from trustkit_policy.runtime import document_decision, knowledge_filter, user_collections

MAX_TOP_K: Final = 10
MAX_QUERY_CHARS: Final = 2_000


@dataclass(frozen=True)
class RetrievalResult:
    chunks: tuple[Chunk, ...]
    withheld: int = 0
    """Chunks dropped by the response scan (count only; never which or why)."""


class RetrievalUnavailableError(Exception):
    """No fresh policy bundle, or the backend failed: nothing is returned."""


class Retriever:
    def __init__(
        self,
        *,
        store: VectorStore,
        policy: Callable[[], LoadedBundle | None],
        scanner: ContentScanner,
        audit: AuditSink,
        now: Callable[[], int],
    ) -> None:
        self._store, self._policy, self._scanner = store, policy, scanner
        self._audit, self._now = audit, now

    def retrieve(
        self,
        *,
        agent_id: str,
        chain: tuple[str, ...],
        user: str,
        user_scopes: frozenset[str],
        query: str,
        top_k: int,
    ) -> RetrievalResult:
        """Server-side filter -> store -> per-chunk Cedar re-check (anomalies dropped and
        audited) -> response scan (flagged chunks withheld)."""
        if not 1 <= top_k <= MAX_TOP_K or not query or len(query) > MAX_QUERY_CHARS:
            raise ValueError("invalid retrieval request")
        loaded = self._policy()
        if loaded is None:
            raise RetrievalUnavailableError("no fresh policy bundle")
        collections = user_collections(user_scopes)
        flt = knowledge_filter(
            loaded, agent_id=agent_id, chain=chain, user_collections=collections, now=self._now()
        )
        if flt is None:
            return RetrievalResult(chunks=())  # nothing retrievable: no query at all
        try:
            found = list(self._store.search(query, flt, top_k))
        except Exception:  # noqa: BLE001 - backend detail never surfaces
            raise RetrievalUnavailableError("knowledge backend failed") from None

        released: list[Chunk] = []
        withheld = 0
        for chunk in found:
            decision = document_decision(
                loaded,
                agent_id=agent_id,
                chain=chain,
                user=user,
                user_collections=collections,
                collection=chunk.collection,
                classification=chunk.classification,
            )
            if not decision.allowed:
                # Passed the filter but not Cedar: a filter bug or backend divergence (A-3).
                self._emit("knowledge.filter_anomaly", agent_id, user, chain, chunk.chunk_id)
                continue
            outcome = scan_with_policy(
                self._scanner,
                chunk.text,
                direction=Direction.RESPONSE,
                failure_mode=ScannerFailureMode.CLOSED,
                timeout_s=0.8,
            )
            verdict = outcome.result.verdict
            if verdict is Verdict.BLOCK:
                withheld += 1
                self._emit("knowledge.chunk_withheld", agent_id, user, chain, chunk.chunk_id)
                continue
            if verdict is Verdict.REDACT and outcome.result.redacted_text is not None:
                chunk = chunk.model_copy(update={"text": outcome.result.redacted_text})
            released.append(chunk)
        self._emit("knowledge.retrieve", agent_id, user, chain, f"{len(released)} released")
        return RetrievalResult(chunks=tuple(released), withheld=withheld)

    def _emit(self, event: str, agent: str, user: str, chain: tuple[str, ...], reason: str) -> None:
        with contextlib.suppress(Exception):
            self._audit.emit(
                AuditEvent(
                    event_type=event,
                    request_id=str(uuid.uuid4()),
                    decision=Decision.DENY if event != "knowledge.retrieve" else Decision.ALLOW,
                    reason=reason[:256],
                    subject=user,
                    client_id=agent,
                    actor_chain=chain,
                )
            )
