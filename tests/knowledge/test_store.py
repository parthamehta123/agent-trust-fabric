"""Local vector store and embedding (ADR-0025 §7)."""

from __future__ import annotations

import math
import pathlib

import pytest
from atf_knowledge_server.store import (
    EMBED_DIMS,
    CorpusIndexError,
    LocalVectorStore,
    embed,
    write_index,
)

from tests.knowledge.test_ingest import manifest, run
from trustkit_policy.runtime import RetrievalFilter

ALL = RetrievalFilter(collections=frozenset({"eng", "hr", "public"}), max_rank=3)


def corpus() -> list:
    return list(
        run(
            (
                manifest(
                    doc_id="deploy", title="Deploy", collection="eng", classification="internal"
                ),
                "Deploys go through the release pipeline with canary analysis.",
            ),
            (
                manifest(
                    doc_id="salaries",
                    title="Salary bands",
                    collection="hr",
                    classification="restricted",
                ),
                "Salary bands for engineering levels and the compensation review.",
            ),
            (
                manifest(
                    doc_id="handbook",
                    title="Handbook",
                    collection="public",
                    classification="public",
                ),
                "Welcome to the company handbook and holiday calendar.",
            ),
        ).chunks
    )


@pytest.fixture
def store(tmp_path: pathlib.Path) -> LocalVectorStore:
    write_index(corpus(), tmp_path / "index.jsonl")
    return LocalVectorStore(tmp_path / "index.jsonl")


class TestEmbed:
    def test_deterministic_normalised(self) -> None:
        v = embed("Release pipeline canary")
        assert v == embed("release   PIPELINE canary")
        assert len(v) == EMBED_DIMS
        assert math.isclose(math.sqrt(sum(x * x for x in v)), 1.0, rel_tol=1e-9)

    def test_empty_is_zero_vector(self) -> None:
        assert set(embed("")) == {0.0}


class TestSearch:
    def test_relevance(self, store: LocalVectorStore) -> None:
        assert store.search("release pipeline canary", ALL, 1)[0].doc_id == "deploy"

    @pytest.mark.security
    def test_filter_is_strict(self, store: LocalVectorStore) -> None:
        eng_only = RetrievalFilter(collections=frozenset({"eng"}), max_rank=3)
        assert {
            c.collection for c in store.search("salary compensation handbook", eng_only, 10)
        } <= {"eng"}
        low = RetrievalFilter(collections=frozenset({"eng", "hr", "public"}), max_rank=1)
        assert "salaries" not in {c.doc_id for c in store.search("salary bands", low, 10)}

    @pytest.mark.security
    def test_empty_filter_returns_nothing(self, store: LocalVectorStore) -> None:
        assert store.search("anything", RetrievalFilter(frozenset(), 3), 10) == []

    def test_top_k(self, store: LocalVectorStore) -> None:
        assert len(store.search("the", ALL, 2)) <= 2


@pytest.mark.security
class TestIndexIntegrity:
    def test_missing(self, tmp_path: pathlib.Path) -> None:
        with pytest.raises(CorpusIndexError):
            LocalVectorStore(tmp_path / "nope.jsonl")

    @pytest.mark.parametrize("bad", ["{not json", '{"chunk_id": "x"}', "[]"])
    def test_any_malformed_line_fails_whole_index(self, tmp_path: pathlib.Path, bad: str) -> None:
        write_index(corpus(), tmp_path / "index.jsonl")
        p = tmp_path / "index.jsonl"
        p.write_text(p.read_text() + bad + "\n")
        with pytest.raises(CorpusIndexError):
            LocalVectorStore(p)

    def test_write_atomic_and_readable(self, tmp_path: pathlib.Path) -> None:
        write_index(corpus(), tmp_path / "index.jsonl")
        assert sorted(p.name for p in tmp_path.iterdir()) == ["index.jsonl"]
        assert (tmp_path / "index.jsonl").stat().st_mode & 0o777 == 0o644
