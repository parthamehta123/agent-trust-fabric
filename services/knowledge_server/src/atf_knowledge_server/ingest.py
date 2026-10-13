"""Ingestion (ADR-0025 §5): bounded owner manifests, scan-before-index, provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from atf_knowledge_server.store import Chunk, Provenance, embed, write_index
from trustkit.profiles import ScannerFailureMode
from trustkit.scanning import (
    ContentScanner,
    Direction,
    LocalRulesScanner,
    Verdict,
    scan_with_policy,
)
from trustkit_policy.grants import Classification, CollectionSlug, classification_rank

MAX_CHUNK_CHARS: Final = 1_200
MAX_DOC_CHARS: Final = 200_000


class Manifest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    doc_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,128}$")]
    title: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    collection: CollectionSlug
    classification: Classification
    source: Annotated[str, StringConstraints(min_length=1, max_length=512)]


class CollectionsConfig(BaseModel):
    """Platform config: known collections and each one's classification ceiling."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    collections: dict[CollectionSlug, Classification]


class Rejection(StrEnum):
    MANIFEST_INVALID = "manifest_invalid"
    UNKNOWN_COLLECTION = "unknown_collection"
    ABOVE_CEILING = "above_ceiling"
    EMPTY_OR_TOO_LARGE = "empty_or_too_large"
    CONTENT_BLOCKED = "content_blocked"
    DUPLICATE_DOC_ID = "duplicate_doc_id"


@dataclass(frozen=True)
class IngestReport:
    chunks: tuple[Chunk, ...]
    rejected: Mapping[str, Rejection] = field(default_factory=dict)
    """doc_id (or ``#<index>`` when the manifest itself is invalid) -> reason. No content."""


def chunk_text(text: str, max_chars: int = MAX_CHUNK_CHARS) -> list[str]:
    """Paragraph-first chunking; no chunk exceeds ``max_chars``; whitespace-only dropped."""
    out: list[str] = []
    for para in text.split("\n\n"):
        para = para.strip()
        while len(para) > max_chars:
            cut = para.rfind(" ", 0, max_chars)
            cut = cut if cut > 0 else max_chars
            out.append(para[:cut].strip())
            para = para[cut:].strip()
        if para:
            out.append(para)
    return [c for c in out if c]


def ingest_documents(
    documents: Sequence[tuple[Mapping[str, object], str]],
    *,
    config: CollectionsConfig,
    scanner: ContentScanner,
    ingested_by: str,
    now: Callable[[], int],
) -> IngestReport:
    """Validate, scan, chunk, embed, label. A rejected document contributes nothing."""
    rejected: dict[str, Rejection] = {}
    parsed: list[tuple[int, Manifest, str]] = []
    for i, (raw, text) in enumerate(documents):
        try:
            parsed.append((i, Manifest.model_validate_json(json.dumps(raw)), text))
        except (ValidationError, TypeError, ValueError):
            rejected[f"#{i}"] = Rejection.MANIFEST_INVALID
    counts = Counter(m.doc_id for _, m, _ in parsed)

    chunks: list[Chunk] = []
    for _, m, text in parsed:
        reason = _check(m, text, config, scanner, duplicate=counts[m.doc_id] > 1)
        if reason is not None:
            rejected[m.doc_id] = reason
            continue
        digest = hashlib.sha256(text.encode()).hexdigest()
        prov = Provenance(
            source=m.source, sha256=digest, ingested_by=ingested_by, ingested_at=now()
        )
        for n, piece in enumerate(chunk_text(text)):
            chunks.append(
                Chunk(
                    chunk_id=f"{m.doc_id}:{n}",
                    doc_id=m.doc_id,
                    title=m.title,
                    text=piece,
                    collection=m.collection,
                    classification=m.classification,
                    provenance=prov,
                    vector=embed(f"{m.title} {piece}"),
                )
            )
    return IngestReport(chunks=tuple(chunks), rejected=rejected)


def _check(
    m: Manifest, text: str, config: CollectionsConfig, scanner: ContentScanner, *, duplicate: bool
) -> Rejection | None:
    if duplicate:
        return Rejection.DUPLICATE_DOC_ID
    ceiling = config.collections.get(m.collection)
    if ceiling is None:
        return Rejection.UNKNOWN_COLLECTION
    if classification_rank(m.classification) > classification_rank(ceiling):
        return Rejection.ABOVE_CEILING
    if not text.strip() or len(text) > MAX_DOC_CHARS:
        return Rejection.EMPTY_OR_TOO_LARGE
    outcome = scan_with_policy(
        scanner,
        text,
        direction=Direction.RESPONSE,  # the corpus is content agents will later receive
        failure_mode=ScannerFailureMode.CLOSED,
        timeout_s=2.0,
    )
    # ADR-0025 §5: injection- or secret-shaped content (BLOCK) never enters the index; a scanner
    # failure is a BLOCK too (fail closed). PII (REDACT) may be stored: it is masked at retrieval.
    if outcome.result.verdict is Verdict.BLOCK:
        return Rejection.CONTENT_BLOCKED
    return None


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m atf_knowledge_server.ingest --corpus DIR --config collections.json
    --out index.jsonl --ingested-by NAME``. Each document is ``<name>.txt`` with a
    ``<name>.json`` manifest. Exits non-zero if anything was rejected (and writes nothing)."""
    ap = argparse.ArgumentParser(description="Ingest a labelled corpus into a knowledge index.")
    ap.add_argument("--corpus", type=pathlib.Path, required=True)
    ap.add_argument("--config", type=pathlib.Path, required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--ingested-by", required=True)
    args = ap.parse_args(argv)
    config = CollectionsConfig.model_validate_json(args.config.read_text())
    docs: list[tuple[Mapping[str, object], str]] = []
    for txt in sorted(args.corpus.glob("*.txt")):
        mpath = txt.with_suffix(".json")
        manifest: object = json.loads(mpath.read_text()) if mpath.exists() else None
        docs.append((manifest if isinstance(manifest, dict) else {}, txt.read_text()))
    report = ingest_documents(
        docs,
        config=config,
        scanner=LocalRulesScanner(),
        ingested_by=args.ingested_by,
        now=lambda: int(time.time()),
    )
    if report.rejected:
        for doc, reason in sorted(report.rejected.items()):
            print(f"rejected {doc}: {reason.value}", file=sys.stderr)
        return 1
    write_index(report.chunks, args.out)
    print(f"indexed {len(report.chunks)} chunks from {len(docs)} documents")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
