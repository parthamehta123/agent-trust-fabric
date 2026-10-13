"""Bedrock Knowledge Bases ``Retrieve`` adapter (ADR-0025 §7, ED-13).

Our ``RetrievalFilter`` is translated to the KB metadata filter (``andAll`` of ``in`` on
``collection`` and ``lessThanOrEquals`` on ``classification_rank``). Results are re-validated
into ``Chunk``s: anything missing labels is dropped, never trusted.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from atf_knowledge_server.store import Chunk, Provenance
from trustkit_policy.runtime import RetrievalFilter

if TYPE_CHECKING:
    from mypy_boto3_bedrock_agent_runtime import AgentsforBedrockRuntimeClient


class KnowledgeBackendError(Exception):
    """The KB could not be queried. Log-safe."""


def to_kb_filter(flt: RetrievalFilter) -> dict[str, Any]:
    return {
        "andAll": [
            {"in": {"key": "collection", "value": sorted(flt.collections)}},
            {"lessThanOrEquals": {"key": "classification_rank", "value": flt.max_rank}},
        ]
    }


class BedrockKbStore:
    def __init__(self, client: AgentsforBedrockRuntimeClient, *, knowledge_base_id: str) -> None:
        self._c, self._kb = client, knowledge_base_id

    def search(self, query: str, flt: RetrievalFilter, top_k: int) -> Sequence[Chunk]:
        if not flt.collections or top_k <= 0:
            return []  # never an unfiltered query
        try:
            r = self._c.retrieve(
                knowledgeBaseId=self._kb,
                retrievalQuery={"text": query},
                retrievalConfiguration={
                    "vectorSearchConfiguration": {
                        "numberOfResults": top_k,
                        "filter": to_kb_filter(flt),  # type: ignore[typeddict-item]
                    }
                },
            )
        except (ClientError, BotoCoreError):
            raise KnowledgeBackendError("knowledge base unavailable") from None
        out: list[Chunk] = []
        for item in r.get("retrievalResults", []):
            chunk = _to_chunk(item)
            if chunk is not None:
                out.append(chunk)
        return out


def _to_chunk(item: Any) -> Chunk | None:
    """A result becomes a Chunk only with complete, valid labels; otherwise it is dropped."""
    try:
        md = item["metadata"]
        return Chunk(
            chunk_id=str(md["chunk_id"]),
            doc_id=str(md["doc_id"]),
            title=str(md["title"]),
            text=str(item["content"]["text"]),
            collection=md["collection"],
            classification=md["classification"],
            provenance=Provenance(
                source=str(md["source"]),
                sha256=md["sha256"],
                ingested_by=str(md["ingested_by"]),
                ingested_at=int(md["ingested_at"]),
            ),
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        return None
