"""Corpus chunks, the deterministic local embedding, and vector stores (ADR-0025 §7)."""

from __future__ import annotations

import hashlib
import math
import os
import pathlib
import re
import tempfile
from collections.abc import Sequence
from typing import Annotated, Final, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from trustkit_policy.grants import Classification, CollectionSlug
from trustkit_policy.runtime import RetrievalFilter

EMBED_DIMS: Final = 256
_WORD: Final = re.compile(r"[a-z0-9]+")


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Provenance(_Strict):
    source: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    ingested_by: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    ingested_at: Annotated[int, Field(gt=0)]


class Chunk(_Strict):
    chunk_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:-]{1,200}$")]
    doc_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,128}$")]
    title: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    text: Annotated[str, StringConstraints(min_length=1, max_length=8_000)]
    collection: CollectionSlug
    classification: Classification
    provenance: Provenance
    vector: tuple[float, ...] = ()


def embed(text: str, dims: int = EMBED_DIMS) -> tuple[float, ...]:
    """Deterministic signed-hashing embedding (lower-cased word tokens), L2-normalised.
    Local/tests only: retrieval quality is not the point, authorization is."""
    v = [0.0] * dims
    for word in _WORD.findall(text.lower()):
        h = hashlib.sha256(word.encode()).digest()
        idx = int.from_bytes(h[:4], "big") % dims
        v[idx] += 1.0 if h[4] & 1 else -1.0
    norm = math.sqrt(sum(x * x for x in v))
    return tuple(x / norm for x in v) if norm else tuple(v)


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=False))


class VectorStore(Protocol):
    def search(self, query: str, flt: RetrievalFilter, top_k: int) -> Sequence[Chunk]:
        """Top-k chunks matching ``flt`` (collection in set, rank <= max). Never unfiltered."""


class LocalVectorStore:
    """In-process store over an index file written by ``ingest`` (JSON lines of ``Chunk``).
    Any malformed line makes the whole index unusable (fail closed, never partial)."""

    def __init__(self, index_path: pathlib.Path) -> None:
        try:
            lines = index_path.read_text().splitlines()
            self._chunks = tuple(Chunk.model_validate_json(line) for line in lines if line.strip())
        except (OSError, ValueError, ValidationError):
            raise CorpusIndexError("knowledge index unusable") from None

    def search(self, query: str, flt: RetrievalFilter, top_k: int) -> Sequence[Chunk]:
        if not flt.collections or top_k <= 0:
            return []
        from trustkit_policy.grants import classification_rank

        q = embed(query)
        allowed = [
            c
            for c in self._chunks
            if c.collection in flt.collections
            and classification_rank(c.classification) <= flt.max_rank
        ]
        allowed.sort(key=lambda c: _cosine(q, c.vector), reverse=True)
        return allowed[:top_k]


class CorpusIndexError(Exception):
    """The index file is missing or malformed."""


def write_index(chunks: Sequence[Chunk], path: pathlib.Path) -> None:
    """Atomic write (temp file + rename), mode 0644."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".index-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for c in chunks:
                f.write(c.model_dump_json() + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        pathlib.Path(tmp).unlink(missing_ok=True)
        raise
