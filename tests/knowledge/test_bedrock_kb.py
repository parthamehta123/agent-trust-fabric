"""Bedrock KB Retrieve adapter, via botocore Stubber (ADR-0025 §7, ED-13)."""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from atf_knowledge_server.bedrock_kb import BedrockKbStore, KnowledgeBackendError, to_kb_filter
from botocore.stub import ANY, Stubber

from trustkit_policy.runtime import RetrievalFilter

FLT = RetrievalFilter(collections=frozenset({"hr", "eng"}), max_rank=2)


def client() -> Any:
    return boto3.client(
        "bedrock-agent-runtime",
        region_name="us-east-1",
        aws_access_key_id="x",
        aws_secret_access_key="x",
    )


def result(**meta: Any) -> dict[str, Any]:
    md = {
        "chunk_id": "c1",
        "doc_id": "d1",
        "title": "Runbook",
        "collection": "eng",
        "classification": "internal",
        "source": "s3://corpus/eng/d1.md",
        "sha256": "0" * 64,
        "ingested_by": "ingest-ci",
        "ingested_at": 1_800_000_000,
    }
    md.update(meta)
    return {
        "content": {"text": "deploy steps"},
        "metadata": {k: v for k, v in md.items() if v is not None},
    }


def test_filter_translation() -> None:
    assert to_kb_filter(FLT) == {
        "andAll": [
            {"in": {"key": "collection", "value": ["eng", "hr"]}},
            {"lessThanOrEquals": {"key": "classification_rank", "value": 2}},
        ]
    }


def test_search_sends_filter_and_maps_results() -> None:
    c = client()
    stub = Stubber(c)
    stub.add_response(
        "retrieve",
        {"retrievalResults": [result()]},
        {
            "knowledgeBaseId": "KBEXAMPLE1",
            "retrievalQuery": {"text": "deploy"},
            "retrievalConfiguration": {
                "vectorSearchConfiguration": {"numberOfResults": 3, "filter": to_kb_filter(FLT)}
            },
        },
    )
    with stub:
        chunks = BedrockKbStore(c, knowledge_base_id="KBEXAMPLE1").search("deploy", FLT, 3)
    assert [(ch.chunk_id, ch.collection, ch.text) for ch in chunks] == [
        ("c1", "eng", "deploy steps")
    ]


@pytest.mark.security
@pytest.mark.parametrize(
    "bad",
    [
        {"collection": None},
        {"classification": "secret"},
        {"classification": None},
        {"sha256": "nope"},
    ],
)
def test_results_without_valid_labels_dropped(bad: dict[str, Any]) -> None:
    c = client()
    stub = Stubber(c)
    stub.add_response(
        "retrieve",
        {"retrievalResults": [result(**bad)]},
        {"knowledgeBaseId": "KBEXAMPLE1", "retrievalQuery": ANY, "retrievalConfiguration": ANY},
    )
    with stub:
        assert BedrockKbStore(c, knowledge_base_id="KBEXAMPLE1").search("q", FLT, 3) == []


@pytest.mark.security
def test_empty_filter_never_queries() -> None:
    c = client()
    with Stubber(c):  # no responses queued: any call would fail
        assert (
            BedrockKbStore(c, knowledge_base_id="KBEXAMPLE1").search(
                "q", RetrievalFilter(frozenset(), 3), 3
            )
            == []
        )


@pytest.mark.security
def test_backend_error() -> None:
    c = client()
    stub = Stubber(c)
    stub.add_client_error(
        "retrieve", service_error_code="AccessDeniedException", http_status_code=403
    )
    with stub, pytest.raises(KnowledgeBackendError):
        BedrockKbStore(c, knowledge_base_id="KBEXAMPLE1").search("q", FLT, 3)
