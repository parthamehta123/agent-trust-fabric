"""Bedrock KB on S3 Vectors after ingest + sync (A-3, A-10, ED-13).

Needs the runbook's ingest step to have run with the sample corpus."""

from __future__ import annotations

import os
from typing import Any

import pytest
from atf_knowledge_server.bedrock_kb import BedrockKbStore

from trustkit_policy.runtime import RetrievalFilter

QUERY = os.environ.get("ATF_PROBE_KB_QUERY", "deploy runbook")


def store(aws: Any, outputs: dict[str, Any]) -> BedrockKbStore:
    return BedrockKbStore(
        aws.client("bedrock-agent-runtime"), knowledge_base_id=outputs["knowledge"]["kb_id"]
    )


def test_a10_our_chunks_come_back_with_their_labels(aws: Any, outputs: dict[str, Any]) -> None:
    hits = store(aws, outputs).search(
        QUERY, RetrievalFilter(frozenset({"public", "eng"}), 3), top_k=5
    )
    assert hits, "ingest + sync the sample corpus first (runbook step 7)"
    for c in hits:
        assert ":" in c.chunk_id
        assert c.provenance.sha256


@pytest.mark.security
def test_a3_the_metadata_filter_is_enforced_server_side(aws: Any, outputs: dict[str, Any]) -> None:
    """Only `public` at rank 0: nothing else may come back, even before our Cedar re-check."""
    hits = store(aws, outputs).search(QUERY, RetrievalFilter(frozenset({"public"}), 0), top_k=10)
    assert all(c.collection == "public" and c.classification == "public" for c in hits)
